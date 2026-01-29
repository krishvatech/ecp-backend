"""
WebSocket consumers for live Chat and Q&A with real-time upvote broadcasting.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from asgiref.sync import async_to_sync
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.contrib.auth.models import AnonymousUser

from events.models import Event
from interactions.models import ChatMessage, Question

log = logging.getLogger("channels")


def _display_name(user):
    """Best-effort printable name for a user."""
    try:
        full = getattr(user, "get_full_name", lambda: "")()
        if full:
            return full
        for f in ("first_name", "username"):
            v = getattr(user, f, "") or ""
            if v:
                return v
        email = getattr(user, "email", "") or ""
        if email:
            return email.split("@")[0]
    except Exception:
        pass
    uid = getattr(user, "id", None)
    return f"User {uid}" if uid else "User"


# -----------------------------
# Shared ORM helpers
# -----------------------------

@database_sync_to_async
def _get_event_and_check_membership(event_id: int, user_id: int):
    """
    Resolve the Event. Add membership checks here if required by your app.
    Return None to reject.
    """
    try:
        return Event.objects.get(pk=event_id)
    except Event.DoesNotExist:
        return None


@database_sync_to_async
def _create_chat_message(event_id: int, user_id: int, content: str) -> ChatMessage:
    return ChatMessage.objects.create(
        event_id=event_id,
        user_id=user_id,
        content=content.strip(),
    )


@database_sync_to_async
def _create_question(event_id: int, user_id: int, content: str) -> Question:
    return Question.objects.create(
        event_id=event_id,
        user_id=user_id,
        content=content.strip(),
    )


@database_sync_to_async
def _toggle_upvote(question_id: int, user_id: int):
    """
    Toggle upvote for a question.
    Returns tuple: (question or None, upvoted: bool, upvote_count: int)
    """
    try:
        q = Question.objects.get(pk=question_id)
    except Question.DoesNotExist:
        return None, False, 0

    # ManyToMany "upvoters" (through=QuestionUpvote) expected
    if q.upvoters.filter(id=user_id).exists():
        q.upvoters.remove(user_id)
        upvoted = False
    else:
        q.upvoters.add(user_id)
        upvoted = True

    count = q.upvoters.count()
    return q, upvoted, count


# -----------------------------
# Base consumer
# -----------------------------

class BaseEventConsumer(AsyncJsonWebsocketConsumer):
    """
    Base consumer providing:
      - auth check (reject Anonymous)
      - event resolve/membership check on connect
      - per-event group add/discard
      - robust JSON receive handler
    """

    group_name_prefix: str = "event"

    async def connect(self) -> None:
        log.debug("WS path=%s", self.scope.get("path"))
        self.user = self.scope.get("user", None)
        if not self.user or isinstance(self.user, AnonymousUser):
            await self.close(code=4401)  # Unauthorized
            return

        try:
            self.event_id = int(self.scope["url_route"]["kwargs"]["event_id"])
        except Exception:
            await self.close(code=4400)  # Bad Request
            return

        event = await _get_event_and_check_membership(self.event_id, self.user.id)
        if not event:
            await self.close(code=4403)  # Forbidden
            return

        self.event = event
        # Stable name used by both WS and REST broadcaster
        self.group_name = f"{self.group_name_prefix}_{self.event_id}_{self.__class__.__name__.lower()}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, code: int) -> None:
        try:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
        except Exception:
            pass

    async def send_error(self, detail: str, code: str = "bad_request") -> None:
        await self.send_json({"type": "error", "error": code, "detail": detail})

    # Robust frame parser (avoid JSONDecodeError on empty/binary frames)
    async def receive(self, text_data=None, bytes_data=None):
        if not text_data and not bytes_data:
            log.debug("Received empty WebSocket frame, ignoring")
            return
        if bytes_data and not text_data:
            try:
                text_data = bytes_data.decode("utf-8")
            except Exception as e:
                log.error("Failed to decode bytes_data: %s", e)
                await self.send_error("Invalid binary data", code="invalid_data")
                return
        try:
            content = json.loads(text_data)
        except json.JSONDecodeError as e:
            log.error("JSON decode error: %s", e)
            await self.send_error("Invalid JSON format", code="invalid_json")
            return
        except Exception as e:
            log.error("Unexpected error parsing message: %s", e)
            await self.send_error("Invalid message format", code="invalid_format")
            return

        await self.receive_json(content)


# -----------------------------
# Chat
# -----------------------------

class ChatConsumer(BaseEventConsumer):
    """
    Chat: send message then broadcast to event group.
    Client -> Server: {"message": "Hello world"}
    Server -> Clients: {"type":"chat.message", ...}
    """

    group_name_prefix = "event_chat"

    async def receive_json(self, content: Dict[str, Any], **kwargs: Any) -> None:
        msg = content.get("message")
        if not msg or not isinstance(msg, str):
            await self.send_error("Field 'message' (string) is required.", code="invalid_payload")
            return

        cm = await _create_chat_message(self.event_id, self.user.id, msg)

        payload = {
            "type": "chat.message",
            "event_id": self.event_id,
            "user_id": self.user.id,
            "uid": self.user.id,               # for client-side "You" tag
            "user": _display_name(self.user),
            "message": cm.content,
            "created_at": cm.created_at.isoformat(),
        }
        await self.channel_layer.group_send(self.group_name, {"type": "chat.message", "payload": payload})

    async def chat_message(self, event: Dict[str, Any]) -> None:
        await self.send_json(event.get("payload", {}))


# -----------------------------
# Q&A (ask & upvote)
# -----------------------------

class QnAConsumer(BaseEventConsumer):
    """
    Q&A: ask question or upvote existing question.
    - Ask:     {"content": "What time is keynote?"}
    - Upvote:  {"action": "upvote", "question_id": 123}
    """

    group_name_prefix = "event_qna"

    async def receive_json(self, content: Dict[str, Any], **kwargs: Any) -> None:
        action = content.get("action")
        question_id = content.get("question_id")
        text = content.get("content") or content.get("message")

        # ---------- UPVOTE ----------
        if action == "upvote":
            if not isinstance(question_id, int):
                await self.send_error("Invalid or missing 'question_id'.", code="invalid_payload")
                return

            q, upvoted, count = await _toggle_upvote(question_id, self.user.id)
            if not q:
                await self.send_error("Question not found.", code="not_found")
                return

            payload = {
                "type": "qna.upvote",
                "event_id": self.event_id,
                "question_id": q.id,
                "upvote_count": count,
                "upvoted": upvoted,
                "user_id": self.user.id,
            }
            await self.channel_layer.group_send(
                self.group_name,
                {"type": "qna.upvote", "payload": payload},
            )
            return

        # ---------- ASK QUESTION ----------
        if not text or not isinstance(text, str):
            await self.send_error("Provide 'content' to ask a question.", code="invalid_payload")
            return

        q = await _create_question(self.event_id, self.user.id, text)

        payload = {
            "type": "qna.question",
            "event_id": self.event_id,
            "question_id": q.id,
            "user_id": self.user.id,
            "uid": self.user.id,
            "user": _display_name(self.user),
            "content": q.content,
            "upvote_count": 0,
            "created_at": q.created_at.isoformat(),
        }
        await self.channel_layer.group_send(
            self.group_name,
            {"type": "qna.question", "payload": payload},
        )

    async def qna_question(self, event: Dict[str, Any]) -> None:
        """
        Called when group_send(type='qna.question', payload=...) is triggered.
        Forward payload to all connected clients.
        """
        await self.send_json(event.get("payload", {}))

    async def qna_upvote(self, event: Dict[str, Any]) -> None:
        """
        Called when group_send(type='qna.upvote', payload=...) is triggered.
        Forward payload to all connected clients.
        """
        await self.send_json(event.get("payload", {}))

    async def qna_visibility_change(self, event: Dict[str, Any]) -> None:
        """
        Called when group_send(type='qna.visibility_change', payload=...) is triggered.
        Forward visibility change payload to all connected clients.
        Triggered when a host/admin toggles question visibility.
        """
        await self.send_json(event.get("payload", {}))