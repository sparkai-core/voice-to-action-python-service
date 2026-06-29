"""
Voice-to-Action — Slack Interactive Handler
Handles all Slack button interactions (approve/edit/reject/in-progress/done)
and routes back to n8n via webhooks.
"""

import os
import json
import hmac
import hashlib
import time
import re
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import httpx
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Voice-to-Action Slack Handler")

SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
N8N_WEBHOOK_BASE = os.getenv("N8N_WEBHOOK_BASE")  # e.g. https://your-n8n.com/webhook

PRIORITY_OPTIONS = ["Urgent", "Normal", "Low"]
PRIORITY_MAP = {
    "High": "Urgent", "Urgent": "Urgent",
    "Medium": "Normal", "Normal": "Normal",
    "Low": "Low",
}


def extract_from_message_blocks(payload: dict) -> dict:
    """Parse brief/title from Slack message blocks when button value omits them."""
    result = {"brief": "", "title": ""}
    for block in payload.get("message", {}).get("blocks", []):
        if block.get("type") != "section":
            continue
        text = block.get("text", {}).get("text", "")
        if not result["title"]:
            title_match = re.match(r"\*([^*]+)\*", text)
            if title_match:
                candidate = title_match.group(1).strip()
                if candidate != "📝 Task:":
                    result["title"] = candidate
            task_match = re.search(r"\*📝 Task:\*\s*(.+?)(?:\n\n|$)", text)
            if task_match:
                result["title"] = task_match.group(1).strip()
        brief_match = re.search(
            r"(?:📄 )?\*Brief:\*\s*(.+?)(?:\n\n|\n👤|\n🔴|\n🟡|\n🟢|\n📅|\n🆔|$)",
            text,
            re.DOTALL,
        )
        if brief_match:
            result["brief"] = brief_match.group(1).strip()
    return result


def normalize_task(task: dict) -> dict:
    """Map button payload fields to what the modal and n8n webhooks expect."""
    raw_priority = task.get("priority") or "Normal"
    priority = PRIORITY_MAP.get(raw_priority, "Normal")
    if priority not in PRIORITY_OPTIONS:
        priority = "Normal"
    brief = (task.get("brief") or "").strip()
    return {
        "brief": brief,
        "title": task.get("title") or task.get("task") or "",
        "assignee": task.get("assignee") or "Unassigned",
        "priority": priority,
        "deadline": task.get("deadline") or "",
    }


def resolve_task(action_value: dict, payload: dict) -> dict:
    """Resolve brief/title from button value, with fallback to the Slack message text."""
    task = normalize_task(action_value)
    if not task["brief"] or not task["title"]:
        from_msg = extract_from_message_blocks(payload)
        if not task["brief"]:
            task["brief"] = from_msg["brief"]
        if not task["title"]:
            task["title"] = from_msg["title"]
    if not task["brief"] and task["title"]:
        task["brief"] = task["title"]
    return task


# ── Slack signature verification ─────────────────────────────────────────────

def verify_slack_signature(request_body: bytes, timestamp: str, signature: str) -> bool:
    """Verify that the request genuinely came from Slack."""
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False  # Replay attack protection
    sig_basestring = f"v0:{timestamp}:{request_body.decode('utf-8')}"
    computed = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(),
        sig_basestring.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, signature)


# ── Slack API helper ──────────────────────────────────────────────────────────

async def slack_api(method: str, payload: dict):
    """Call any Slack API method."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://slack.com/api/{method}",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            json=payload
        )
        data = resp.json()
        if not data.get("ok"):
            print(f"Slack API error [{method}]: {data.get('error', data)}")
        return data


async def update_slack_message(channel_id: str, message_ts: str, text: str):
    """Replace the original interactive message with a status line."""
    if not channel_id or not message_ts:
        print("Slack message update skipped: missing channel_id or message_ts")
        return
    await slack_api("chat.update", {
        "channel": channel_id,
        "ts": message_ts,
        "text": text,
        "blocks": [],
    })


async def resolve_slack_user_id(assignee: str) -> str | None:
    """Map assignee name or Slack ID to a user ID for users_select initial value."""
    value = (assignee or "").strip()
    if not value or value.lower() == "unassigned":
        return None
    if re.match(r"^U[A-Z0-9]+$", value, re.I):
        return value
    data = await slack_api("users.list", {"limit": 200})
    if not data.get("ok"):
        return None
    target = value.lower()
    for member in data.get("members", []):
        if member.get("deleted") or member.get("is_bot"):
            continue
        profile = member.get("profile", {})
        candidates = [
            member.get("real_name", ""),
            member.get("name", ""),
            profile.get("display_name", ""),
            profile.get("real_name", ""),
        ]
        if any(c and c.lower() == target for c in candidates):
            return member["id"]
    return None


async def slack_user_display_name(user_id: str) -> str:
    """Get a human-readable name for Airtable / Slack messages."""
    if not user_id:
        return "Unassigned"
    data = await slack_api("users.info", {"user": user_id})
    if not data.get("ok"):
        return user_id
    user = data["user"]
    profile = user.get("profile", {})
    return (
        profile.get("display_name")
        or profile.get("real_name")
        or user.get("real_name")
        or user.get("name")
        or user_id
    )


async def build_assignee_select(task: dict) -> dict:
    """Slack users_select — searchable list of workspace members."""
    element = {
        "type": "users_select",
        "action_id": "assignee",
        "placeholder": {"type": "plain_text", "text": "Select a team member"},
    }
    initial_user = await resolve_slack_user_id(task.get("assignee", ""))
    if initial_user:
        element["initial_user"] = initial_user
    return {
        "type": "input",
        "block_id": "assignee_block",
        "optional": True,
        "label": {"type": "plain_text", "text": "Assigned To"},
        "element": element,
    }


async def open_edit_modal(
    trigger_id: str,
    task: dict,
    channel_id: str,
    message_ts: str,
):
    """Open a Slack modal so the Founder can edit task fields inline."""
    task = normalize_task(task)
    priority = task["priority"]
    assignee_block = await build_assignee_select(task)

    blocks = [
        {
            "type": "input",
            "block_id": "title_block",
            "label": {"type": "plain_text", "text": "Task Title"},
            "element": {
                "type": "plain_text_input",
                "action_id": "title",
                "initial_value": task["title"]
            }
        },
        {
            "type": "input",
            "block_id": "brief_block",
            "label": {"type": "plain_text", "text": "Brief (primary key)"},
            "element": {
                "type": "plain_text_input",
                "action_id": "brief",
                "multiline": True,
                "initial_value": task["brief"]
            }
        },
        assignee_block,
        {
            "type": "input",
            "block_id": "priority_block",
            "label": {"type": "plain_text", "text": "Priority"},
            "element": {
                "type": "static_select",
                "action_id": "priority",
                "initial_option": {
                    "text": {"type": "plain_text", "text": priority},
                    "value": priority
                },
                "options": [
                    {"text": {"type": "plain_text", "text": "Urgent"}, "value": "Urgent"},
                    {"text": {"type": "plain_text", "text": "Normal"}, "value": "Normal"},
                    {"text": {"type": "plain_text", "text": "Low"},    "value": "Low"}
                ]
            }
        },
        {
            "type": "input",
            "block_id": "deadline_block",
            "label": {"type": "plain_text", "text": "Deadline (optional)"},
            "optional": True,
            "element": {
                "type": "plain_text_input",
                "action_id": "deadline",
                "placeholder": {"type": "plain_text", "text": "e.g. Friday, 27 June"},
                "initial_value": task["deadline"]
            }
        }
    ]

    result = await slack_api("views.open", {
        "trigger_id": trigger_id,
        "view": {
            "type": "modal",
            "callback_id": "edit_task_modal",
            "private_metadata": json.dumps({
                "brief": task["brief"],
                "channel_id": channel_id,
                "message_ts": message_ts,
            }),
            "title": {"type": "plain_text", "text": "Edit Task"},
            "submit": {"type": "plain_text", "text": "Approve"},
            "close": {"type": "plain_text", "text": "Cancel"},
            "blocks": blocks
        }
    })
    return result


# ── Main interactive endpoint ─────────────────────────────────────────────────

@app.post("/slack/interactive")
async def slack_interactive(request: Request):
    """
    Receives ALL Slack button clicks and modal submissions.
    Routes each action to the correct n8n webhook.
    """
    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")
    if not SLACK_SIGNING_SECRET or not verify_slack_signature(body, timestamp, signature):
        raise HTTPException(status_code=403, detail="Invalid Slack signature")

    form = await request.form()
    payload = json.loads(form["payload"])
    payload_type = payload.get("type")
    print(f"Slack interactive: type={payload_type}")

    # ── Modal submission (Edit → Approve) ────────────────────────────────────
    if payload_type == "view_submission":
        if payload["view"]["callback_id"] == "edit_task_modal":
            meta = json.loads(payload["view"]["private_metadata"])
            values = payload["view"]["state"]["values"]
            assignee_slack_id = values["assignee_block"]["assignee"].get("selected_user", "")
            assignee_name = await slack_user_display_name(assignee_slack_id)
            edited_task = {
                "title":    values["title_block"]["title"]["value"],
                "brief":    values["brief_block"]["brief"]["value"],
                "assignee": assignee_name,
                "assignee_slack_id": assignee_slack_id,
                "priority": values["priority_block"]["priority"]["selected_option"]["value"],
                "deadline": (values.get("deadline_block", {}).get("deadline", {}).get("value") or ""),
                "action":   "approve"
            }
            async with httpx.AsyncClient() as client:
                await client.post(f"{N8N_WEBHOOK_BASE}/task-approved", json=edited_task)
            await update_slack_message(
                meta.get("channel_id", ""),
                meta.get("message_ts", ""),
                f"✅ Task approved and sent to assignee.\n*{edited_task['title']}*",
            )
            return JSONResponse(content={})

    # ── Button actions ────────────────────────────────────────────────────────
    if payload_type == "block_actions":
        action = payload["actions"][0]
        action_id = action["action_id"]
        action_value = json.loads(action.get("value", "{}"))
        task = resolve_task(action_value, payload)
        brief = task["brief"]
        user_id = payload["user"]["id"]

        print(f"Slack action: {action_id} brief={brief!r}")

        if action_id == "approve_task":
            async with httpx.AsyncClient() as client:
                await client.post(f"{N8N_WEBHOOK_BASE}/task-approved", json={
                    **task, "action": "approve"
                })
            await update_slack_message(
                payload["channel"]["id"],
                payload["message"]["ts"],
                "✅ Task approved and sent to assignee.",
            )

        elif action_id == "edit_task":
            await open_edit_modal(
                trigger_id=payload["trigger_id"],
                task=task,
                channel_id=payload["channel"]["id"],
                message_ts=payload["message"]["ts"],
            )

        elif action_id == "reject_task":
            async with httpx.AsyncClient() as client:
                await client.post(f"{N8N_WEBHOOK_BASE}/task-rejected", json={
                    "brief": brief
                })
            await update_slack_message(
                payload["channel"]["id"],
                payload["message"]["ts"],
                "🔄 Task sent back for regeneration.",
            )

        elif action_id == "mark_in_progress":
            async with httpx.AsyncClient() as client:
                await client.post(f"{N8N_WEBHOOK_BASE}/task-status", json={
                    "brief": brief,
                    "title": task["title"],
                    "status": "In Progress",
                    "user_id": user_id
                })
            await update_slack_message(
                payload["channel"]["id"],
                payload["message"]["ts"],
                "🔵 Marked as *In Progress*. Good luck!",
            )

        elif action_id == "mark_done":
            async with httpx.AsyncClient() as client:
                await client.post(f"{N8N_WEBHOOK_BASE}/task-status", json={
                    "brief": brief,
                    "title": task["title"],
                    "status": "Done",
                    "user_id": user_id
                })
            await update_slack_message(
                payload["channel"]["id"],
                payload["message"]["ts"],
                "✅ Marked as *Done*. Great work!",
            )

        return JSONResponse(content={})

    return JSONResponse(content={})


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}
