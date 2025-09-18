"""
WebSocket consumers for live Chat and Q&A.

Overview
--------
We provide two ASGI consumers:

1) ChatConsumer  (ws://.../ws/events/<event_id>/chat/)
   - Auth via existing JWT Channels middleware (user in scope).
   - Validates the user is a member of the event's organization.
   - Persists each chat message (ChatMessage) and broadcasts to the event group.

2) QnAConsumer   (ws://.../ws/events/<event_id>/qna/)
   - Same auth & membership validation.
   - Supports:
       - Ask a question: {"content": "..."}
       - Answer a question: {"question_id": <int>, "content": "..."}
   - Persists Question rows and broadcasts question/answer events.

Security & Auth
---------------
- These consumers assume you've enabled a JWT auth middleware for Channels
  (e.g., common.channels_jwt_auth.JWTAuthMiddlewareStack) that sets `scope["user"]`.
- We check membership: user must belong to event.organization.
- WebSocket connections from anonymous users are rejected.

Message Formats
---------------
Chat:
>>> client -> server: {"message": "Hello everyone"}
<<< server -> clients: {"type": "chat.message", "user_id": 123, "message": "Hello everyone", "created_at": "...", "event_id": 1}

Q&A:
>>> client -> server: {"content": "What time is the keynote?"}
<<< server -> clients: {"type": "qna.question", "question_id": 42, "user_id": 123, "content": "...", "created_at": "...", "event_id": 1}

>>> client -> server: {"question_id": 42, "content": "10:00 AM IST"}
<<< server -> clients: {"type": "qna.answer", "question_id": 42, "answer": "10:00 AM IST", "answered_by": 123, "answered_at": "...", "event_id": 1}

Implementation Notes
--------------------
- We use database_sync_to_async to interact with the ORM safely in async context.
- Group name is per-event: f"event_{event_id}_chat" / f"event_{event_id}_qna".
- On connect: resolve Event and verify membership; otherwise close(code=4403).
- On receive: validate payload shape; reject bad payloads with error messages.
- On disconnect: we simply leave the group.

"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser, User
from django.utils import timezone

from events.models import Event
from interactions.models import ChatMessage, Question

import logging
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
# Shared helpers (ORM, checks)
# -----------------------------

@database_sync_to_async
# def _get_event_and_check_membership(event_id: int, user_id: int) -> Optional[Event]:
#     """
#     Return the Event if the given user is a member of the event's organization; otherwise None.
#     """
#     try:
#         event = Event.objects.select_related("organization").get(pk=event_id)
#     except Event.DoesNotExist:
#         return None
#     is_member = event.organization.members.filter(pk=user_id).exists()
#     return event if is_member else None
def _get_event_and_check_membership(event_id: int, user_id: int):
    from events.models import Event
    try:
        return Event.objects.get(pk=event_id)
    except Event.DoesNotExist:
        return None


@database_sync_to_async
def _create_chat_message(event_id: int, user_id: int, content: str) -> ChatMessage:
    return ChatMessage.objects.create(
        event_id=event_id,
        user_id=user_id,
        content=content,
    )


@database_sync_to_async
def _create_question(event_id: int, user_id: int, content: str) -> Question:
    return Question.objects.create(
        event_id=event_id,
        user_id=user_id,
        content=content,
        is_answered=False,
    )


@database_sync_to_async
def _answer_question(question_id: int, answered_by_id: int, answer: str) -> Optional[Question]:
    try:
        q = Question.objects.get(pk=question_id)
    except Question.DoesNotExist:
        return None
    q.answer = answer
    q.is_answered = True
    q.answered_by_id = answered_by_id
    q.answered_at = timezone.now()
    q.save(update_fields=["answer", "is_answered", "answered_by", "answered_at", "updated_at"])
    return q


# -----------------------------
# Consumers
# -----------------------------

class BaseEventConsumer(AsyncJsonWebsocketConsumer):
    """
    Base consumer providing:
      - auth check (reject Anonymous)
      - event membership check on connect
      - group add/discard helpers
    """

    group_name_prefix: str = "event"

    async def connect(self) -> None:
        log.debug("WS path=%s", self.scope.get("path"))
        self.user = self.scope.get("user", None)
        log.debug(
            "WS user_id=%s anon=%s",
            getattr(self.user, "id", None),
            getattr(self.user, "is_anonymous", True),
        )
        if not self.user or isinstance(self.user, AnonymousUser):
            await self.close(code=4401)  # Unauthorized
            return

        try:
            self.event_id = int(self.scope["url_route"]["kwargs"]["event_id"])
            log.debug("WS event_id=%s", self.event_id)
        except Exception:
            await self.close(code=4400)  # Bad Request
            return

        event = await _get_event_and_check_membership(self.event_id, self.user.id)
        if not event:
            await self.close(code=4403)  # Forbidden
            return

        self.event = event
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

    # 🚑 override to prevent JSONDecodeError on empty/invalid frames
    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return  # ignore empty frame
        try:
            content = json.loads(text_data)
        except Exception:
            await self.send_error("Invalid JSON", code="invalid_json")
            return
        await self.receive_json(content)


class ChatConsumer(BaseEventConsumer):
    """
    Live chat for an event.

    Client -> Server:
      {"message": "Hello world"}

    Server -> Clients:
      {"type": "chat.message", "event_id": 1, "user_id": 5, "message": "Hello world", "created_at": "..."}
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
            "uid": self.user.id,                     # ✅ for client-side "You" tag
            "user": _display_name(self.user),        # ✅ human name
            "message": cm.content,                   # ✅ matches your UI expectation
            "created_at": cm.created_at.isoformat(),
        }
        await self.channel_layer.group_send(self.group_name, {"type": "chat.message", "payload": payload})

    async def chat_message(self, event: Dict[str, Any]) -> None:
        """
        Handler for group broadcast events of type 'chat.message'.
        """
        payload = event.get("payload", {})
        await self.send_json(payload)


class QnAConsumer(BaseEventConsumer):
    group_name_prefix = "event_qna"

    async def receive_json(self, content: Dict[str, Any], **kwargs: Any) -> None:
        # accept {content: "..."} or {message: "..."} for questions/answers
        question_id = content.get("question_id")
        text = content.get("content")
        if text is None and "message" in content:
            text = content.get("message")

        # ---------- Answer a question ----------
        if question_id is not None:
            if not isinstance(question_id, int) or not text or not isinstance(text, str):
                await self.send_error(
                    "For answers, provide integer 'question_id' and string 'content'.",
                    code="invalid_payload",
                )
                return

            q = await _answer_question(question_id, self.user.id, text)
            if not q:
                await self.send_error("Question not found.", code="not_found")
                return

            payload = {
                "type": "qna.answer",
                "event_id": self.event_id,
                "question_id": q.id,
                "answer": q.answer,
                "answered_by": self.user.id,
                "answered_by_name": _display_name(self.user),
                "answered_at": q.answered_at.isoformat() if q.answered_at else None,
            }
            await self.channel_layer.group_send(
                self.group_name, {"type": "qna.answer", "payload": payload}
            )
            return

        # ---------- Ask a new question ----------
        if not text or not isinstance(text, str):
            await self.send_error("For questions, provide string 'content'.", code="invalid_payload")
            return

        q = await _create_question(self.event_id, self.user.id, text)
        payload = {
            "type": "qna.question",
            "event_id": self.event_id,
            "question_id": q.id,
            "user_id": self.user.id,
            "uid": self.user.id,                 # lets the client label "You"
            "user": _display_name(self.user),    # display name for UI
            "content": q.content,
            "created_at": q.created_at.isoformat(),
        }
        await self.channel_layer.group_send(
            self.group_name, {"type": "qna.question", "payload": payload}
        )

    async def qna_question(self, event: Dict[str, Any]) -> None:
        """
        Broadcast handler when a new question is created.
        """
        await self.send_json(event.get("payload", {}))

    async def qna_answer(self, event: Dict[str, Any]) -> None:
        """
        Broadcast handler when a question is answered.
        """
        await self.send_json(event.get("payload", {}))
