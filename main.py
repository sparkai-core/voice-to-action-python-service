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


def normalize_task(task: dict) -> dict:
    """Map button payload fields to what the modal and n8n webhooks expect."""
    raw_priority = task.get("priority") or "Normal"
    priority = PRIORITY_MAP.get(raw_priority, "Normal")
    if priority not in PRIORITY_OPTIONS:
        priority = "Normal"
    return {
        "task_id": task.get("task_id", ""),
        "title": task.get("title") or task.get("task") or "",
        "brief": task.get("brief") or "",
        "assignee": task.get("assignee") or "Unassigned",
        "priority": priority,
        "deadline": task.get("deadline") or "",
    }


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


async def open_edit_modal(trigger_id: str, task: dict, task_id: str):
    """Open a Slack modal so the Founder can edit task fields inline."""
    task = normalize_task({**task, "task_id": task_id or task.get("task_id", "")})
    priority = task["priority"]

    result = await slack_api("views.open", {
        "trigger_id": trigger_id,
        "view": {
            "type": "modal",
            "callback_id": "edit_task_modal",
            "private_metadata": json.dumps({"task_id": task_id}),
            "title": {"type": "plain_text", "text": "Edit Task"},
            "submit": {"type": "plain_text", "text": "Approve"},
            "close": {"type": "plain_text", "text": "Cancel"},
            "blocks": [
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
                    "label": {"type": "plain_text", "text": "Brief"},
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "brief",
                        "multiline": True,
                        "initial_value": task["brief"]
                    }
                },
                {
                    "type": "input",
                    "block_id": "assignee_block",
                    "label": {"type": "plain_text", "text": "Assigned To"},
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "assignee",
                        "initial_value": task["assignee"]
                    }
                },
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
    # Verify Slack signature
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
            edited_task = {
                "task_id":  meta["task_id"],
                "title":    values["title_block"]["title"]["value"],
                "brief":    values["brief_block"]["brief"]["value"],
                "assignee": values["assignee_block"]["assignee"]["value"],
                "priority": values["priority_block"]["priority"]["selected_option"]["value"],
                "deadline": (values["deadline_block"]["deadline"]["value"] or ""),
                "action":   "approve"
            }
            async with httpx.AsyncClient() as client:
                await client.post(f"{N8N_WEBHOOK_BASE}/task-approved", json=edited_task)
            return JSONResponse(content={})  # Empty = close modal

    # ── Button actions ────────────────────────────────────────────────────────
    if payload_type == "block_actions":
        action = payload["actions"][0]
        action_id = action["action_id"]
        action_value = json.loads(action.get("value", "{}"))
        task = normalize_task(action_value)
        task_id = task["task_id"]
        user_id = payload["user"]["id"]

        print(f"Slack action: {action_id} task_id={task_id}")

        # — Founder approval buttons —
        if action_id == "approve_task":
            async with httpx.AsyncClient() as client:
                await client.post(f"{N8N_WEBHOOK_BASE}/task-approved", json={
                    **task, "action": "approve"
                })
            await slack_api("chat.update", {
                "channel": payload["channel"]["id"],
                "ts": payload["message"]["ts"],
                "text": "✅ Task approved and sent to assignee.",
                "blocks": []
            })

        elif action_id == "edit_task":
            await open_edit_modal(
                trigger_id=payload["trigger_id"],
                task=task,
                task_id=task_id
            )

        elif action_id == "reject_task":
            async with httpx.AsyncClient() as client:
                await client.post(f"{N8N_WEBHOOK_BASE}/task-rejected", json={
                    "task_id": task_id
                })
            await slack_api("chat.update", {
                "channel": payload["channel"]["id"],
                "ts": payload["message"]["ts"],
                "text": "🔄 Task sent back for regeneration.",
                "blocks": []
            })

        # — Team member status buttons —
        elif action_id == "mark_in_progress":
            async with httpx.AsyncClient() as client:
                await client.post(f"{N8N_WEBHOOK_BASE}/task-status", json={
                    "task_id": task_id,
                    "status": "In Progress",
                    "user_id": user_id
                })
            await slack_api("chat.update", {
                "channel": payload["channel"]["id"],
                "ts": payload["message"]["ts"],
                "text": f"🔵 Marked as *In Progress*. Good luck!",
                "blocks": []
            })

        elif action_id == "mark_done":
            async with httpx.AsyncClient() as client:
                await client.post(f"{N8N_WEBHOOK_BASE}/task-status", json={
                    "task_id": task_id,
                    "status": "Done",
                    "user_id": user_id
                })
            await slack_api("chat.update", {
                "channel": payload["channel"]["id"],
                "ts": payload["message"]["ts"],
                "text": "✅ Marked as *Done*. Great work!",
                "blocks": []
            })

        return JSONResponse(content={})

    return JSONResponse(content={})


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}
