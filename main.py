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
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
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


def extract_task_from_clicked_button(blocks: list, clicked_value: str) -> dict:
    """Parse brief/title from the section linked to the button that was clicked."""
    result = {"brief": "", "title": ""}
    target = (clicked_value or "").strip()
    if not blocks or not target:
        return result

    for i, block in enumerate(blocks):
        if block.get("type") != "actions":
            continue
        if not any(el.get("value") == target for el in block.get("elements", [])):
            continue
        section_idx = i - 1
        if section_idx >= 0 and blocks[section_idx].get("type") == "divider":
            section_idx -= 1
        if section_idx < 0 or blocks[section_idx].get("type") != "section":
            return result
        text = blocks[section_idx].get("text", {}).get("text", "")
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

    return result


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
    task_index = task.get("task_index")
    return {
        "brief": brief,
        "title": task.get("title") or task.get("task") or "",
        "assignee": task.get("assignee") or "Unassigned",
        "priority": priority,
        "deadline": task.get("deadline") or "",
        "task_index": task_index if task_index is not None else None,
    }


def resolve_task(action_value: dict, payload: dict) -> dict:
    """Resolve brief/title from button value, with fallback to the clicked task section."""
    task = normalize_task(action_value)
    if not task["brief"] or not task["title"]:
        clicked = payload.get("actions", [{}])[0].get("value", "")
        from_msg = extract_task_from_clicked_button(
            payload.get("message", {}).get("blocks", []),
            clicked,
        )
        if not from_msg["brief"] and not from_msg["title"]:
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


async def fetch_message_blocks(channel_id: str, message_ts: str) -> list:
    """Load the current blocks for a channel message."""
    data = await slack_api("conversations.history", {
        "channel": channel_id,
        "latest": message_ts,
        "oldest": message_ts,
        "inclusive": True,
        "limit": 1,
    })
    if not data.get("ok"):
        return []
    messages = data.get("messages", [])
    if not messages:
        return []
    return messages[0].get("blocks", [])


def task_brief_from_button_value(value: str) -> str:
    try:
        data = json.loads(value or "{}")
        return (data.get("brief") or data.get("title") or "").strip()
    except json.JSONDecodeError:
        return ""


def is_status_action_block(actions_block: dict) -> bool:
    """True if this actions block has Mark In Progress / Mark Done buttons."""
    action_ids = {el.get("action_id") for el in actions_block.get("elements", [])}
    return "mark_in_progress" in action_ids or "mark_done" in action_ids


def is_founder_approval_block(actions_block: dict) -> bool:
    """True if this actions block has Approve / Edit / Reject buttons."""
    action_ids = {el.get("action_id") for el in actions_block.get("elements", [])}
    return "approve_task" in action_ids or "edit_task" in action_ids


def task_from_button_value(value: str) -> dict:
    try:
        data = json.loads(value or "{}")
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def format_task_section(task: dict) -> str:
    """Render a task section block matching Workflow 1 layout."""
    priority = task.get("priority") or "Normal"
    emoji = {"Urgent": "🔴", "Normal": "🟡", "Low": "🟢"}.get(priority, "🟡")
    assignee = task.get("assignee") or "Unassigned"
    if assignee == "Unassigned" and task.get("assignee_slack_id"):
        assignee = f"<@{task['assignee_slack_id']}>"
    deadline = task.get("deadline") or "Not specified"
    title = task.get("title") or task.get("brief") or "Untitled task"
    brief = task.get("brief") or title
    return (
        f"*📝 Task:* {title}\n\n"
        f"📄 *Brief:* {brief}\n\n"
        f"👤 *Assignee:* {assignee}\n\n"
        f"{emoji} *Priority:* {priority}\n\n"
        f"📅 *Deadline:* {deadline}"
    )


def actions_block_matches_task(
    actions_block: dict,
    target_brief: str,
    target_title: str = "",
    task_index: int | None = None,
) -> bool:
    """Strict match — one task per actions block (no fuzzy substring matching)."""
    target_brief = target_brief.strip()
    target_title = (target_title or "").strip()
    for el in actions_block.get("elements", []):
        data = task_from_button_value(el.get("value", ""))
        if task_index is not None and data.get("task_index") == task_index:
            return True
        btn_brief = (data.get("brief") or "").strip()
        btn_title = (data.get("title") or "").strip()
        if target_brief and btn_brief == target_brief:
            if not target_title or btn_title == target_title:
                return True
    return False


def find_founder_approval_actions_index(blocks: list, action_value: str) -> int | None:
    """Find the actions block index for the exact button value that was clicked."""
    target = (action_value or "").strip()
    if not target:
        return None
    for i, block in enumerate(blocks):
        if block.get("type") != "actions":
            continue
        if any(el.get("value") == target for el in block.get("elements", [])):
            return i
    return None


def mark_task_in_blocks(
    blocks: list,
    target_brief: str,
    status_line: str,
    task_details: dict | None = None,
    target_title: str = "",
    task_index: int | None = None,
    actions_block_index: int | None = None,
) -> list | None:
    """
    Update one founder-voice task (section + actions). Other tasks unchanged.
    """
    if not blocks:
        return None

    if actions_block_index is not None:
        i = actions_block_index
        if i < 0 or i >= len(blocks) or blocks[i].get("type") != "actions":
            return None
        section_idx = i - 1
        if section_idx >= 0 and blocks[section_idx].get("type") == "divider":
            section_idx -= 1
        if section_idx < 0 or blocks[section_idx].get("type") != "section":
            return None
        section_text = blocks[section_idx].get("text", {}).get("text", "")
        body = format_task_section(task_details) if task_details else section_text
        updated = list(blocks[:section_idx])
        updated.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"{body}\n\n{status_line}"},
        })
        divider_idx = section_idx + 1
        if divider_idx < i and blocks[divider_idx].get("type") == "divider":
            updated.append(blocks[divider_idx])
        updated.extend(blocks[i + 1:])
        return updated

    target = target_brief.strip()
    if not target and task_index is None:
        return None

    updated: list = []
    matched = False
    i = 0
    while i < len(blocks):
        block = blocks[i]
        if (
            block.get("type") == "section"
            and i + 1 < len(blocks)
            and blocks[i + 1].get("type") == "actions"
            and is_founder_approval_block(blocks[i + 1])
        ):
            actions_block = blocks[i + 1]
            if actions_block_matches_task(
                actions_block, target, target_title, task_index
            ):
                matched = True
                body = format_task_section(task_details) if task_details else block.get("text", {}).get("text", "")
                updated.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"{body}\n\n{status_line}"},
                })
                i += 2
                if i < len(blocks) and blocks[i].get("type") == "divider":
                    updated.append(blocks[i])
                    i += 1
                continue

        updated.append(block)
        i += 1

    return updated if matched else None


def message_has_pending_actions(blocks: list) -> bool:
    return any(block.get("type") == "actions" for block in blocks)


async def update_slack_message(channel_id: str, message_ts: str, text: str, blocks: list | None = None):
    """Replace or patch the original interactive message."""
    if not channel_id or not message_ts:
        print("Slack message update skipped: missing channel_id or message_ts")
        return False

    payload = {
        "channel": channel_id,
        "ts": message_ts,
        "text": text,
    }
    if blocks is not None:
        payload["blocks"] = blocks
    else:
        payload["blocks"] = [{
            "type": "section",
            "text": {"type": "mrkdwn", "text": text},
        }]

    data = await slack_api("chat.update", payload)
    if not data.get("ok"):
        print(f"chat.update failed: channel={channel_id} ts={message_ts} error={data.get('error')}")
        return False
    return True


async def update_message_after_task_action(
    channel_id: str,
    message_ts: str,
    match_brief: str,
    title: str,
    action: str,
    task_details: dict | None = None,
    match_title: str = "",
    task_index: int | None = None,
    current_blocks: list | None = None,
    clicked_button_value: str = "",
):
    """Update founder-voice message after approve/reject — one task at a time."""
    status_lines = {
        "approved": "✅ *Approved* — sent to assignee.",
        "rejected": "❌ *Rejected* — sent back for regeneration.",
    }
    status_line = status_lines.get(action, "✅ *Updated*")
    display_title = (task_details or {}).get("title") or title or match_brief
    fallback_text = f"{status_line}\n*{display_title}*"

    blocks = current_blocks if current_blocks else await fetch_message_blocks(channel_id, message_ts)
    actions_idx = find_founder_approval_actions_index(blocks, clicked_button_value)
    new_blocks = mark_task_in_blocks(
        blocks,
        match_brief,
        status_line,
        task_details,
        target_title=match_title,
        task_index=task_index,
        actions_block_index=actions_idx,
    )

    if new_blocks is not None:
        if not message_has_pending_actions(new_blocks):
            for idx, block in enumerate(new_blocks):
                if block.get("type") == "section":
                    header_text = block.get("text", {}).get("text", "")
                    if "task(s) extracted" in header_text.lower():
                        new_blocks[idx] = {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": "✅ *All tasks reviewed.*",
                            },
                        }
                        break
        ok = await update_slack_message(channel_id, message_ts, fallback_text, new_blocks)
    else:
        print(f"Could not match task block for brief={match_brief!r}; replacing whole message")
        ok = await update_slack_message(channel_id, message_ts, fallback_text)

    if not ok:
        print(f"Failed to update founder message for brief={match_brief!r}")


def mark_status_in_blocks_by_action(
    blocks: list,
    clicked_action_id: str,
    status_line: str,
    remove_buttons: bool,
) -> list | None:
    """Update the task section tied to the button the user clicked."""
    if not blocks:
        return None

    for i, block in enumerate(blocks):
        if block.get("type") != "actions":
            continue
        element_ids = {el.get("action_id") for el in block.get("elements", [])}
        if clicked_action_id not in element_ids:
            continue

        section_idx = i - 1
        if section_idx >= 0 and blocks[section_idx].get("type") == "divider":
            section_idx -= 1
        if section_idx < 0 or blocks[section_idx].get("type") != "section":
            continue

        section_text = blocks[section_idx].get("text", {}).get("text", "")
        updated = list(blocks[:section_idx])
        updated.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{section_text}\n\n{status_line}",
            },
        })
        if section_idx + 1 < i and blocks[section_idx + 1].get("type") == "divider":
            updated.append(blocks[section_idx + 1])
        if not remove_buttons:
            updated.append(block)
        updated.extend(blocks[i + 1:])
        return updated

    return None


def mark_assignee_task_in_blocks(
    blocks: list,
    target_brief: str,
    status_line: str,
    remove_buttons: bool,
) -> list | None:
    """
    Update assignee DM / #task-log task messages (section → divider? → actions).
    remove_buttons=False keeps buttons (In Progress); True removes them (Done).
    """
    target = target_brief.strip()
    if not blocks or not target:
        return None

    updated: list = []
    matched = False
    i = 0
    while i < len(blocks):
        block = blocks[i]
        if block.get("type") == "section":
            section_text = block.get("text", {}).get("text", "")
            actions_idx = i + 1
            if actions_idx < len(blocks) and blocks[actions_idx].get("type") == "divider":
                actions_idx += 1
            if (
                actions_idx < len(blocks)
                and blocks[actions_idx].get("type") == "actions"
                and is_status_action_block(blocks[actions_idx])
            ):
                actions_block = blocks[actions_idx]
                if actions_block_matches_task(actions_block, target):
                    matched = True
                    updated.append({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"{section_text}\n\n{status_line}",
                        },
                    })
                    if actions_idx > i + 1:
                        updated.append(blocks[i + 1])  # divider
                    if not remove_buttons:
                        updated.append(actions_block)
                    i = actions_idx + 1
                    continue

        updated.append(block)
        i += 1

    return updated if matched else None


async def update_message_after_status_action(
    channel_id: str,
    message_ts: str,
    brief: str,
    title: str,
    status: str,
    current_blocks: list | None = None,
    clicked_action_id: str = "",
):
    """Update assignee DM / #task-log after In Progress or Done."""
    status_lines = {
        "In Progress": "🔵 *Status: In Progress*",
        "Done": "✅ *Status: Done* — great work!",
    }
    status_line = status_lines.get(status, f"*Status: {status}*")
    remove_buttons = status == "Done"
    fallback_text = f"{status_line}\n*{title or brief}*"

    blocks = current_blocks
    if not blocks:
        blocks = await fetch_message_blocks(channel_id, message_ts)

    new_blocks = None
    if clicked_action_id:
        new_blocks = mark_status_in_blocks_by_action(
            blocks, clicked_action_id, status_line, remove_buttons
        )
    if new_blocks is None:
        new_blocks = mark_assignee_task_in_blocks(
            blocks, brief, status_line, remove_buttons
        )

    if new_blocks is not None:
        ok = await update_slack_message(channel_id, message_ts, fallback_text, new_blocks)
    else:
        print(f"Could not match assignee task block for brief={brief!r}; keeping buttons in fallback")
        ok = await update_slack_message(channel_id, message_ts, fallback_text, _status_fallback_blocks(
            blocks, status_line, remove_buttons, clicked_action_id
        ))

    if not ok:
        print(f"Failed to update status message for brief={brief!r}")


def _status_fallback_blocks(
    blocks: list,
    status_line: str,
    remove_buttons: bool,
    clicked_action_id: str,
) -> list:
    """Last resort: append status line and preserve action buttons when possible."""
    if not blocks:
        return [{"type": "section", "text": {"type": "mrkdwn", "text": status_line}}]

    if clicked_action_id:
        rebuilt = mark_status_in_blocks_by_action(
            blocks, clicked_action_id, status_line, remove_buttons
        )
        if rebuilt:
            return rebuilt

    actions = next((b for b in blocks if b.get("type") == "actions"), None)
    section = next((b for b in blocks if b.get("type") == "section"), None)
    header = next((b for b in blocks if b.get("type") == "header"), None)
    divider = next((b for b in blocks if b.get("type") == "divider"), None)

    result = []
    if header:
        result.append(header)
    if section:
        text = section.get("text", {}).get("text", "")
        result.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"{text}\n\n{status_line}"},
        })
    else:
        result.append({"type": "section", "text": {"type": "mrkdwn", "text": status_line}})
    if divider:
        result.append(divider)
    if actions and not remove_buttons:
        result.append(actions)
    return result


async def send_task_status_to_n8n(brief: str, title: str, status: str, user_id: str) -> bool:
    """Notify n8n to update Airtable status and post to #task-log."""
    payload = {
        "brief": brief,
        "title": title,
        "status": status,
        "user_id": user_id,
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{N8N_WEBHOOK_BASE}/task-status", json=payload)
            print(f"n8n task-status ({status}): status={resp.status_code} brief={brief!r}")
            return resp.status_code < 400
    except Exception as exc:
        print(f"n8n task-status webhook failed ({status}): {exc}")
        return False


def parse_assignee_field(assignee: str) -> tuple[str, str | None]:
    """Parse assignee text into (name_hint, slack_user_id)."""
    value = (assignee or "").strip()
    if not value or value.lower() == "unassigned":
        return "", None
    mention = re.match(r"^<@(U[A-Z0-9]+)>$", value, re.I)
    if mention:
        return "", mention.group(1)
    if re.match(r"^U[A-Z0-9]+$", value, re.I):
        return "", value
    return value, None


def extract_selected_user_from_modal(values: dict) -> str:
    """Read Slack user ID from users_select modal state."""
    assignee_state = values.get("assignee_block", {}).get("assignee", {})
    for key in ("selected_user", "selected_conversation"):
        val = (assignee_state.get(key) or "").strip()
        if val and re.match(r"^U[A-Z0-9]+$", val, re.I):
            return val
    return ""


def normalize_person_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


async def resolve_slack_user_id(assignee: str) -> str | None:
    """Map assignee name or Slack ID to a user ID via users.list (requires users:read)."""
    value = (assignee or "").strip()
    if not value or value.lower() == "unassigned":
        return None
    if re.match(r"^U[A-Z0-9]+$", value, re.I):
        return value

    target = value.lower()
    target_norm = normalize_person_name(value)
    members = await fetch_slack_members()
    if not members:
        print("resolve_slack_user_id: users.list returned no members (check users:read scope)")

    for member in members:
        if member.get("deleted") or member.get("is_bot"):
            continue
        profile = member.get("profile", {})
        candidates = [
            member.get("real_name", ""),
            member.get("name", ""),
            profile.get("display_name", ""),
            profile.get("real_name", ""),
        ]
        for candidate in candidates:
            if not candidate:
                continue
            c = candidate.strip()
            if c.lower() == target or normalize_person_name(c) == target_norm:
                return member["id"]
        first = (member.get("real_name") or profile.get("real_name") or "").strip().split()
        if first and first[0].lower() == target:
            return member["id"]

    return None


async def prepare_approved_task_payload(task: dict) -> dict:
    """Resolve Slack user ID + display name — no manual ASSIGNEE_MAP needed."""
    payload = {k: v for k, v in dict(task).items() if v is not None}
    existing_id = (payload.get("assignee_slack_id") or "").strip()
    if re.match(r"^U[A-Z0-9]+$", existing_id, re.I):
        payload["assignee_slack_id"] = existing_id
        payload["assignee"] = await slack_user_display_name(existing_id)
        payload["deadline"] = normalize_deadline_to_iso(payload.get("deadline", ""))
        return payload

    name_hint, id_from_name = parse_assignee_field(payload.get("assignee", ""))
    slack_id = (id_from_name or "").strip()

    if not slack_id:
        lookup = name_hint or (payload.get("assignee") or "").strip()
        if lookup and lookup.lower() != "unassigned":
            resolved = await resolve_slack_user_id(lookup)
            slack_id = resolved or ""

    if slack_id:
        payload["assignee_slack_id"] = slack_id
        payload["assignee"] = await slack_user_display_name(slack_id)
    else:
        payload["assignee_slack_id"] = ""
        assignee = name_hint or (payload.get("assignee") or "").strip()
        payload["assignee"] = assignee if assignee else "Unassigned"
        print(
            f"prepare_approved_task_payload: no Slack ID for assignee={payload['assignee']!r}"
        )

    payload["deadline"] = normalize_deadline_to_iso(payload.get("deadline", ""))
    return payload


async def send_task_approved_to_n8n(task: dict):
    """Notify n8n that a task was approved."""
    payload = await prepare_approved_task_payload(task)
    payload["action"] = "approve"
    payload["assignee_slack_id"] = (payload.get("assignee_slack_id") or "").strip()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{N8N_WEBHOOK_BASE}/task-approved",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            print(
                f"n8n task-approved: status={resp.status_code} "
                f"assignee={payload.get('assignee')!r} "
                f"assignee_slack_id={payload.get('assignee_slack_id')!r}"
            )
            if resp.status_code >= 400:
                print(f"n8n task-approved response: {resp.text[:500]}")
    except Exception as exc:
        print(f"n8n task-approved webhook failed: {exc}")


def member_display_name(member: dict) -> str:
    """Best display name from a Slack member/users.info object."""
    profile = member.get("profile", {})
    for key in ("real_name", "display_name"):
        val = (profile.get(key) or member.get(key) or "").strip()
        if val:
            return val
    username = (member.get("name") or "").strip()
    return username


async def fetch_slack_members() -> list[dict]:
    """Paginated workspace member list (requires users:read)."""
    members: list[dict] = []
    cursor: str | None = None
    while True:
        payload: dict = {"limit": 200}
        if cursor:
            payload["cursor"] = cursor
        data = await slack_api("users.list", payload)
        if not data.get("ok"):
            break
        members.extend(data.get("members", []))
        cursor = data.get("response_metadata", {}).get("next_cursor") or None
        if not cursor:
            break
    return members


async def slack_user_display_name(user_id: str) -> str:
    """Get a human-readable name for Airtable / Slack messages."""
    if not user_id:
        return "Unassigned"
    user_id = user_id.strip()

    data = await slack_api("users.info", {"user": user_id})
    if data.get("ok"):
        name = member_display_name(data["user"])
        if name:
            return name

    for member in await fetch_slack_members():
        if member.get("id") == user_id:
            name = member_display_name(member)
            if name:
                return name
            break

    print(f"Could not resolve display name for Slack user {user_id}")
    return "Unknown"


def deadline_for_modal(deadline: str) -> str:
    """Return a real deadline for the modal, or empty so the placeholder shows."""
    value = (deadline or "").strip()
    if not value or value.lower() in ("not specified", "none", "n/a", "-"):
        return ""
    return value


def normalize_deadline_to_iso(deadline: str) -> str:
    """Normalize deadline to YYYY-MM-DD for Airtable/n8n (expects DD/MM/YYYY input)."""
    value = (deadline or "").strip()
    if not value or value.lower() in ("not specified", "none", "n/a", "-"):
        return ""

    if re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        try:
            datetime.strptime(value, "%Y-%m-%d")
            return value
        except ValueError:
            pass

    for fmt in (
        "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y",
        "%d/%m/%y", "%d-%m-%y", "%d.%m.%y",
    ):
        try:
            return datetime.strptime(value, fmt).date().isoformat()
        except ValueError:
            continue

    return value


def normalize_deadline_input(deadline: str) -> str:
    """Clean and ISO-normalize deadline from modal submit."""
    return normalize_deadline_to_iso(deadline)


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
        "label": {"type": "plain_text", "text": "Assigned To"},
        "element": element,
    }


async def open_edit_modal(
    trigger_id: str,
    task: dict,
    channel_id: str,
    message_ts: str,
    edit_button_value: str = "",
):
    """Open a Slack modal so the Founder can edit task fields inline."""
    task = normalize_task(task)
    priority = task["priority"]
    assignee_block = await build_assignee_select(task)
    deadline_value = deadline_for_modal(task["deadline"])
    deadline_element = {
        "type": "plain_text_input",
        "action_id": "deadline",
        "placeholder": {"type": "plain_text", "text": "DD/MM/YYYY"},
    }
    if deadline_value:
        deadline_element["initial_value"] = deadline_value

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
            "label": {"type": "plain_text", "text": "Deadline"},
            "optional": True,
            "element": deadline_element,
        }
    ]

    result = await slack_api("views.open", {
        "trigger_id": trigger_id,
        "view": {
            "type": "modal",
            "callback_id": "edit_task_modal",
            "private_metadata": json.dumps({
                "original_brief": task["brief"],
                "original_title": task["title"],
                "task_index": task.get("task_index"),
                "edit_button_value": edit_button_value,
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
async def slack_interactive(request: Request, background_tasks: BackgroundTasks):
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
            assignee_slack_id = extract_selected_user_from_modal(values)
            print(f"edit modal submit: assignee_slack_id={assignee_slack_id!r}")
            edited_task = {
                "title":    values["title_block"]["title"]["value"],
                "brief":    values["brief_block"]["brief"]["value"],
                "assignee": "",
                "assignee_slack_id": assignee_slack_id,
                "priority": values["priority_block"]["priority"]["selected_option"]["value"],
                "deadline": normalize_deadline_input(
                    values.get("deadline_block", {}).get("deadline", {}).get("value") or ""
                ),
                "task_index": meta.get("task_index"),
            }
            original_brief = meta.get("original_brief") or meta.get("brief") or edited_task["brief"]
            original_title = meta.get("original_title", "")
            task_index = meta.get("task_index")
            channel_id = meta.get("channel_id", "")
            message_ts = meta.get("message_ts", "")

            await update_message_after_task_action(
                channel_id,
                message_ts,
                original_brief,
                edited_task["title"],
                "approved",
                task_details=edited_task,
                match_title=original_title,
                task_index=task_index,
                clicked_button_value=meta.get("edit_button_value", ""),
            )
            await send_task_approved_to_n8n(edited_task)
            return JSONResponse(content={})

    # ── Button actions ────────────────────────────────────────────────────────
    if payload_type == "block_actions":
        action = payload["actions"][0]
        action_id = action["action_id"]
        raw_button_value = action.get("value", "{}")
        action_value = json.loads(raw_button_value)
        task = resolve_task(action_value, payload)
        brief = task["brief"]
        user_id = payload["user"]["id"]
        message_blocks = payload.get("message", {}).get("blocks", [])

        print(f"Slack action: {action_id} brief={brief!r} task_index={task.get('task_index')!r}")

        if action_id == "approve_task":
            await update_message_after_task_action(
                payload["channel"]["id"],
                payload["message"]["ts"],
                brief,
                task["title"],
                "approved",
                task_details=task,
                match_title=task["title"],
                task_index=task.get("task_index"),
                current_blocks=message_blocks,
                clicked_button_value=raw_button_value,
            )
            await send_task_approved_to_n8n(dict(task))

        elif action_id == "edit_task":
            await open_edit_modal(
                trigger_id=payload["trigger_id"],
                task=task,
                channel_id=payload["channel"]["id"],
                message_ts=payload["message"]["ts"],
                edit_button_value=raw_button_value,
            )

        elif action_id == "reject_task":
            async with httpx.AsyncClient() as client:
                await client.post(f"{N8N_WEBHOOK_BASE}/task-rejected", json={
                    "brief": brief
                })
            await update_message_after_task_action(
                payload["channel"]["id"],
                payload["message"]["ts"],
                brief,
                task["title"],
                "rejected",
                match_title=task["title"],
                task_index=task.get("task_index"),
                current_blocks=message_blocks,
                clicked_button_value=raw_button_value,
            )

        elif action_id == "mark_in_progress":
            if not brief:
                from_msg = extract_from_message_blocks(payload)
                brief = from_msg["brief"] or task["title"]
            await send_task_status_to_n8n(brief, task["title"], "In Progress", user_id)
            await update_message_after_status_action(
                payload["channel"]["id"],
                payload["message"]["ts"],
                brief,
                task["title"],
                "In Progress",
                current_blocks=payload.get("message", {}).get("blocks", []),
                clicked_action_id=action_id,
            )

        elif action_id == "mark_done":
            if not brief:
                from_msg = extract_from_message_blocks(payload)
                brief = from_msg["brief"] or task["title"]
            await send_task_status_to_n8n(brief, task["title"], "Done", user_id)
            await update_message_after_status_action(
                payload["channel"]["id"],
                payload["message"]["ts"],
                brief,
                task["title"],
                "Done",
                current_blocks=payload.get("message", {}).get("blocks", []),
                clicked_action_id=action_id,
            )

        return JSONResponse(content={})

    return JSONResponse(content={})


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}
