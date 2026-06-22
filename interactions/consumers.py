"""
WebSocket consumers for live Chat and Q&A with real-time upvote broadcasting.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4

from asgiref.sync import async_to_sync
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.contrib.auth.models import AnonymousUser
try:
    from autobahn.exception import Disconnected
except Exception:  # pragma: no cover - import guard for local/runtime variation
    Disconnected = None

from events.models import Event, EventParticipant, EventRegistration
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
def _get_event_and_check_membership(event_id: int, user):
    """
    Resolve the Event and verify user is authorized (registered, guest, or organizer).
    Return None to reject.
    """
    try:
        event = Event.objects.select_related("community").get(pk=event_id)
    except Event.DoesNotExist:
        return None

    user_id = getattr(user, "id", None)

    # Organizer always has access
    if event.community and event.community.owner_id == user_id:
        return event

    # Registered participant has access
    if EventRegistration.objects.filter(event_id=event_id, user_id=user_id).exists():
        return event

    # Guest users and recently converted guests should retain access to their event Q&A.
    from events.models import GuestAttendee

    guest_record = getattr(user, "guest", None)
    if guest_record and getattr(guest_record, "event_id", None) == event_id:
        return event

    converted_guest = GuestAttendee.objects.filter(event_id=event_id, converted_user_id=user_id).first()
    if converted_guest:
        return event

    return None  # Not a member — reject


@database_sync_to_async
def _can_receive_shared_qna_group(event_id: int, user) -> bool:
    """
    Only hosts/moderators/admins need the event-wide shared Q&A group.

    Normal attendees inside breakout rooms should listen only to their room group.
    Otherwise every shared group/grouping broadcast fans out to all breakout users
    even when their room-local Q&A does not need it.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False

    if getattr(user, "is_staff", False) or getattr(user, "is_superuser", False):
        return True

    user_id = getattr(user, "id", None)
    if not user_id:
        return False

    try:
        event = Event.objects.select_related("community").get(pk=event_id)
    except Event.DoesNotExist:
        return False

    if event.created_by_id == user_id:
        return True
    if getattr(event.community, "owner_id", None) == user_id:
        return True

    return EventParticipant.objects.filter(
        event_id=event_id,
        user_id=user_id,
        participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
        role__in=[EventParticipant.ROLE_HOST, EventParticipant.ROLE_MODERATOR],
    ).exists()


@database_sync_to_async
def _create_chat_message(event_id: int, user_id: int, content: str) -> ChatMessage:
    return ChatMessage.objects.create(
        event_id=event_id,
        user_id=user_id,
        content=content.strip(),
    )


@database_sync_to_async
def _create_question(event_id: int, user, content: str, lounge_table_id: int = None) -> Question:
    if getattr(user, "is_guest", False) and getattr(user, "guest", None):
        return Question.objects.create(
            event_id=event_id,
            user_id=None,
            guest_asker_id=user.guest.id,
            content=content.strip(),
            lounge_table_id=lounge_table_id,
        )
    return Question.objects.create(
        event_id=event_id,
        user_id=user.id,
        content=content.strip(),
        lounge_table_id=lounge_table_id,
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

    def _is_closed_socket_error(self, exc: Exception) -> bool:
        if Disconnected is not None and isinstance(exc, Disconnected):
            return True
        message = str(exc).lower()
        return (
            "closed protocol" in message
            or "connection already closed" in message
            or "socket is already closed" in message
        )

    async def send_json(self, content, close=False):
        if getattr(self, "_ws_closed", False):
            return
        try:
            await super().send_json(content, close=close)
        except Exception as exc:
            if self._is_closed_socket_error(exc):
                self._ws_closed = True
                log.debug(
                    "WS[%s] dropped send on closed socket event_id=%s user_id=%s payload_type=%s",
                    self.__class__.__name__,
                    getattr(self, "event_id", None),
                    getattr(getattr(self, "user", None), "id", None),
                    content.get("type") if isinstance(content, dict) else type(content).__name__,
                )
                return
            raise

    async def connect(self) -> None:
        log.debug("WS path=%s", self.scope.get("path"))
        self._ws_closed = False
        self.user = self.scope.get("user", None)
        if not self.user or isinstance(self.user, AnonymousUser):
            log.warning("WS[Chat] rejected: anonymous user path=%s", self.scope.get("path"))
            await self.close(code=4401)  # Unauthorized
            return

        try:
            self.event_id = int(self.scope["url_route"]["kwargs"]["event_id"])
        except Exception:
            log.warning("WS[Chat] rejected: invalid event_id in path")
            await self.close(code=4400)  # Bad Request
            return

        event = await _get_event_and_check_membership(self.event_id, self.user)
        if not event:
            log.warning("WS[Chat] rejected: event not found or user not member event_id=%s user_id=%s", self.event_id, self.user.id)
            await self.close(code=4403)  # Forbidden
            return

        self.event = event
        # Stable name used by both WS and REST broadcaster
        self.group_name = f"{self.group_name_prefix}_{self.event_id}_{self.__class__.__name__.lower()}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, code: int) -> None:
        self._ws_closed = True
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
        if bool(getattr(self.user, "is_guest", False)):
            await self.send_error("Guest chat over this channel is not supported.", code="guest_not_supported")
            return
        msg = content.get("message")
        if not msg or not isinstance(msg, str):
            await self.send_error("Field 'message' (string) is required.", code="invalid_payload")
            return

        ## Generate UUID for tracking
        message_uuid = uuid4()
        created_at = datetime.now(timezone.utc)

        # Create message dict for Redis/Celery
        message_dict = {
            'user_id': self.user.id,
            'content': msg.strip(),
            'created_at': created_at.isoformat(),
            'uuid': str(message_uuid),
        }

        # Save to Redis immediately
        from events.redis_messages import save_message_to_redis
        await database_sync_to_async(save_message_to_redis)(self.event_id, message_dict)

        # Broadcast to WebSocket clients immediately (Redis-first, no DB wait)
        payload = {
            "type": "chat.message",
            "event_id": self.event_id,
            "user_id": self.user.id,
            "uid": self.user.id,
            "user": _display_name(self.user),
            "message": msg.strip(),
            "created_at": created_at.isoformat(),
            "uuid": str(message_uuid),
            "status": "pending",  # Mark as pending until DB save completes
        }
        await self.channel_layer.group_send(self.group_name, {"type": "chat.message", "payload": payload})

        ##Queue Celery task to persist to DB (no await - fire and forget)
        from interactions.tasks import persist_chat_message_to_db
        persist_chat_message_to_db.delay(self.event_id, str(message_uuid), message_dict)

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
    
    ISOLATION: 
    - Supports lounge_table_id via query param.
    - Subscribes to table-specific channel if present.
    """

    group_name_prefix = "event_qna"
    lounge_table_id = None

    async def connect(self) -> None:
        # disconnect() can be called even when connect() rejects before accept().
        # Initialise every attribute used by disconnect() before any early return.
        self._ws_closed = False
        self.group_name = None
        self.shared_group_name = None
        self.lounge_table_id = None

        log.debug("WS path=%s", self.scope.get("path"))
        self.user = self.scope.get("user", None)
        if not self.user or isinstance(self.user, AnonymousUser):
            log.warning("WS[QnA] rejected: anonymous user path=%s", self.scope.get("path"))
            await self.close(code=4401)
            return

        try:
            self.event_id = int(self.scope["url_route"]["kwargs"]["event_id"])
        except Exception:
            log.warning("WS[QnA] rejected: invalid event_id in path")
            await self.close(code=4400)
            return

        event = await _get_event_and_check_membership(self.event_id, self.user)
        if not event:
            log.warning("WS[QnA] rejected: event not found or user not member event_id=%s user_id=%s", self.event_id, self.user.id)
            await self.close(code=4403)
            return

        self.event = event

        # Parse lounge_table_id from query params
        # (e.g. ws://...?lounge_table_id=123)
        try:
            from urllib.parse import parse_qs
            query_string = self.scope.get("query_string", b"").decode("utf-8")
            params = parse_qs(query_string)
            if "lounge_table_id" in params:
                 # Take the last value to be safe, assuming int
                 val = params["lounge_table_id"][-1]
                 if val and val.lower() != "null" and val.lower() != "undefined":
                     self.lounge_table_id = int(val)
        except Exception as e:
            log.warning(f"Error parsing lounge_table_id: {e}")
            self.lounge_table_id = None

        # Determine Group Name
        if self.lounge_table_id:
            # Table-Specific Room
            self.group_name = f"{self.group_name_prefix}_{self.event_id}_table_{self.lounge_table_id}"
        else:
            # Main Room
            self.group_name = f"{self.group_name_prefix}_{self.event_id}_main"

        await self.channel_layer.group_add(self.group_name, self.channel_name)

        # Only hosts/moderators/admins need event-wide group-management messages.
        # Breakout attendees receive room-local Q&A messages from self.group_name.
        if await _can_receive_shared_qna_group(self.event_id, self.user):
            self.shared_group_name = f"{self.group_name_prefix}_{self.event_id}_shared"
            await self.channel_layer.group_add(self.shared_group_name, self.channel_name)

        await self.accept()

    async def receive_json(self, content: Dict[str, Any], **kwargs: Any) -> None:
        action = content.get("action")
        question_id = content.get("question_id")
        text = content.get("content") or content.get("message")

        # ---------- TYPING INDICATOR ----------
        if content.get("type") == "qna.typing":
            # Derive user identity from the authenticated socket — never trust client-sent user_id
            is_guest = bool(getattr(self.user, "is_guest", False))
            if is_guest and getattr(self.user, "guest", None):
                user_id = f"guest_{self.user.guest.id}"
            else:
                user_id = str(self.user.id)

            is_typing = bool(content.get("is_typing", False))

            payload = {
                "type": "qna.typing",
                "event_id": self.event_id,
                "lounge_table_id": self.lounge_table_id,
                "user_id": user_id,
                "user_name": _display_name(self.user),
                "is_typing": is_typing,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            await self.channel_layer.group_send(
                self.group_name,
                {"type": "qna.typing", "payload": payload},
            )
            return

        # ---------- UPVOTE ----------
        if action == "upvote":
            if bool(getattr(self.user, "is_guest", False)):
                await self.send_error("Guest upvote is not supported.", code="guest_not_supported")
                return
            if not isinstance(question_id, int):
                await self.send_error("Invalid or missing 'question_id'.", code="invalid_payload")
                return

            q, upvoted, count = await _toggle_upvote(question_id, self.user.id)
            if not q:
                await self.send_error("Question not found.", code="not_found")
                return

            # Broadcast to the CURRENT room (group)
            # Note: Theoretically global upvotes could be reflected everywhere if we used a global group AND local group,
            # but to ensure isolation we only broadcast to the room where the upvoter is.
            # However, if the question is VISIBLE in this room, it should be fine.
            # Ideally questions physically belong to a room, so we are in the right room.
            
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

        # Generate UUID for tracking
        question_uuid = uuid4()
        created_at = datetime.now(timezone.utc)

        # Create question dict for Redis/Celery
        question_dict = {
            'user_id': self.user.id if not getattr(self.user, "is_guest", False) else None,
            'guest_asker_id': self.user.guest.id if (getattr(self.user, "is_guest", False) and getattr(self.user, "guest", None)) else None,
            'content': text.strip(),
            'lounge_table_id': self.lounge_table_id,
            'created_at': created_at.isoformat(),
            'uuid': str(question_uuid),
            'moderation_status': 'pending',
        }

        # Save to Redis immediately
        from events.redis_messages import save_question_to_redis
        await database_sync_to_async(save_question_to_redis)(self.event_id, question_dict)

        # Determine asker ID for payload
        asker_id = self.user.id
        if bool(getattr(self.user, "is_guest", False)) and getattr(self.user, "guest", None):
            asker_id = f"guest_{self.user.guest.id}"

        # Broadcast to WebSocket clients immediately (Redis-first, no DB wait)
        payload = {
            "type": "qna.question",
            "event_id": self.event_id,
            "lounge_table_id": self.lounge_table_id,
            "question_id": None,  # Will be set after DB save
            "uuid": str(question_uuid),  # Track by UUID until DB ID available
            "user_id": asker_id,
            "uid": asker_id,
            "user": _display_name(self.user),
            "content": text.strip(),
            "upvote_count": 0,
            "created_at": created_at.isoformat(),
            "status": "pending",  # Mark as pending until DB save completes
        }
        await self.channel_layer.group_send(
            self.group_name,
            {"type": "qna.question", "payload": payload},
        )

        # Queue Celery task to persist to DB (no await - fire and forget)
        from interactions.tasks import persist_qna_question_to_db
        persist_qna_question_to_db.delay(self.event_id, str(question_uuid), question_dict)

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

    async def qna_approved(self, event: Dict[str, Any]) -> None:
        """
        Called when group_send(type='qna.approved', payload=...) is triggered.
        Forward approved question payload to all connected clients.
        Triggered when a host approves a pending question.
        """
        await self.send_json(event.get("payload", {}))

    async def qna_rejected(self, event: Dict[str, Any]) -> None:
        """
        Called when group_send(type='qna.rejected', payload=...) is triggered.
        Forward rejected question payload to all connected clients.
        Triggered when a host rejects a pending question.
        """
        await self.send_json(event.get("payload", {}))

    async def qna_answered(self, event: Dict[str, Any]) -> None:
        """
        Called when group_send(type='qna.answered', payload=...) is triggered.
        Forward answered question payload to all connected clients.
        Triggered when a host marks a question as answered.
        """
        payload = event.get("payload", {})
        payload["type"] = "qna.answered"
        await self.send_json(payload)

    async def qna_pinned(self, event: Dict[str, Any]) -> None:
        """
        Called when group_send(type='qna.pinned', payload=...) is triggered.
        Forward pinned question payload to all connected clients.
        Triggered when a host pins or unpins a question.
        """
        await self.send_json(event.get("payload", {}))

    async def qna_anonymized(self, event: Dict[str, Any]) -> None:
        """
        Called when group_send(type='qna.anonymized', payload=...) is triggered.
        Forward anonymized question payload to all connected clients.
        Triggered when a host toggles the anonymous status of a question.
        """
        await self.send_json(event.get("payload", {}))

    async def qna_engagement_prompt(self, event: Dict[str, Any]) -> None:
        """
        Called when group_send(type='qna.engagement_prompt', payload=...) is triggered.
        Forward engagement prompt payload to all connected attendee clients.
        Triggered when a host sends a Q&A engagement prompt.

        Payload shape:
            { type, prompt_id, event_id, created_at }

        Attendee client should call the ack endpoint after receiving this;
        the backend then decides whether to show the banner (cap enforcement).
        """
        await self.send_json(event.get("payload", {}))

    # ------------------------------------------------------------------
    # Threaded reply handlers
    # ------------------------------------------------------------------

    async def qna_reply(self, event: Dict[str, Any]) -> None:
        """
        New reply created under a question.
        Payload: { type, event_id, question_id, reply_id, author_id, author_name,
                   author_avatar_url, content, upvote_count, created_at,
                   moderation_status, is_anonymous }
        """
        await self.send_json(event.get("payload", {}))

    async def qna_reply_update(self, event: Dict[str, Any]) -> None:
        """Reply content edited. Payload: { type, event_id, question_id, reply_id, content }"""
        await self.send_json(event.get("payload", {}))

    async def qna_reply_delete(self, event: Dict[str, Any]) -> None:
        """Reply deleted. Payload: { type, event_id, question_id, reply_id }"""
        await self.send_json(event.get("payload", {}))

    async def qna_reply_upvote(self, event: Dict[str, Any]) -> None:
        """Reply upvote toggled. Payload: { type, event_id, question_id, reply_id, upvote_count, upvoted, user_id }"""
        await self.send_json(event.get("payload", {}))

    async def qna_reply_approved(self, event: Dict[str, Any]) -> None:
        """Host approved a pending reply. Payload: { type, event_id, question_id, reply_id, content }"""
        await self.send_json(event.get("payload", {}))

    async def qna_reply_rejected(self, event: Dict[str, Any]) -> None:
        """Host rejected a reply. Payload: { type, event_id, question_id, reply_id, reason }"""
        await self.send_json(event.get("payload", {}))

    async def qna_reply_anonymized(self, event: Dict[str, Any]) -> None:
        """Host toggled anonymous on a reply. Payload: { type, event_id, question_id, reply_id, is_anonymous }"""
        await self.send_json(event.get("payload", {}))

    # Q&A Group handlers
    # ------------------------------------------------------------------

    async def qna_group_created(self, event: Dict[str, Any]) -> None:
        """New question group created (AI or manual). Payload includes group object with aggregated_vote_count."""
        await self.send_json(event.get("payload", {}))

    async def qna_group_updated(self, event: Dict[str, Any]) -> None:
        """Existing group updated (title/summary). Payload includes updated group object."""
        await self.send_json(event.get("payload", {}))

    async def qna_group_deleted(self, event: Dict[str, Any]) -> None:
        """Group deleted. Payload: { type, group_id, event_id }"""
        await self.send_json(event.get("payload", {}))

    async def qna_group_membership_updated(self, event: Dict[str, Any]) -> None:
        """Questions added/removed from a group. Payload: { type, group_id, event_id, added, removed }"""
        await self.send_json(event.get("payload", {}))

    async def qna_group_suggestion_reviewed(self, event: Dict[str, Any]) -> None:
        """AI suggestion approved/rejected. Payload: { type, suggestion_id, status, event_id }"""
        await self.send_json(event.get("payload", {}))

    async def qna_group_suggestions_ready(self, event: Dict[str, Any]) -> None:
        """New AI group suggestions pending host review. Payload: { type, count, event_id }"""
        await self.send_json(event.get("payload", {}))

    async def qna_group_upvote(self, event: Dict[str, Any]) -> None:
        """Group upvote count updated. Payload: { type, event_id, group_id, aggregated_vote_count }"""
        await self.send_json(event.get("payload", {}))

    async def qna_ai_public_suggestions_refresh(self, event: Dict[str, Any]) -> None:
        """Public AI suggestions refreshed. Payload: { event_id }"""
        await self.send_json(event.get("payload", {}))

    async def qna_typing(self, event: Dict[str, Any]) -> None:
        """
        Called when group_send(type='qna.typing', payload=...) is triggered.
        Forward the typing indicator payload to all connected clients in this room.
        Payload: { type, event_id, lounge_table_id, user_id, user_name, is_typing, timestamp }
        """
        await self.send_json(event.get("payload", {}))

    async def disconnect(self, code: int) -> None:
        self._ws_closed = True

        shared_group_name = getattr(self, "shared_group_name", None)
        if shared_group_name:
            try:
                await self.channel_layer.group_discard(shared_group_name, self.channel_name)
            except Exception:
                pass

        await super().disconnect(code)

