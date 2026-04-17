"""
Tests for Q&A Feature #13: Live Typing Indicator.

Covers:
  - Authenticated user typing event is broadcast with server-derived identity
  - is_typing=false is broadcast correctly
  - Spoofed user_id in client payload is ignored
  - Guest typing event is broadcast with guest_N user_id
  - Table-room isolation: main-room typing doesn't bleed into table room

Run with:
  pytest interactions/test_qna_typing.py -v
"""

import json
import pytest

from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model

from community.models import Community
from events.models import Event

User = get_user_model()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_qna_communicator(event_id, user, lounge_table_id=None):
    """Return a configured WebsocketCommunicator for the QnA endpoint."""
    from ecp_backend.asgi import application

    qs = f"?lounge_table_id={lounge_table_id}" if lounge_table_id else ""
    comm = WebsocketCommunicator(application, f"/ws/events/{event_id}/qna/{qs}")
    comm.scope["user"] = user
    return comm


class MockGuestUser:
    """Minimal guest user compatible with QnAConsumer identity checks."""
    is_anonymous = False
    is_authenticated = True
    is_guest = True
    is_staff = False

    class _Guest:
        def __init__(self, gid):
            self.id = gid

    def __init__(self, uid, guest_id, name="Guest User"):
        self.id = uid
        self.guest = self._Guest(guest_id)
        self._name = name

    def get_full_name(self):
        return self._name


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def org(db):
    host = User.objects.create_user(username="typing_host", password="pw")
    return Community.objects.create(name="TypingOrg", owner_id=host.id, description="")


@pytest.fixture
def event(org):
    host = User.objects.get(username="typing_host")
    return Event.objects.create(title="TypingEvent", community=org, created_by=host)


@pytest.fixture
def user_a(db, org):
    u = User.objects.create_user(username="typing_user_a", password="pw", first_name="Alice")
    org.members.add(u)
    return u


@pytest.fixture
def user_b(db, org):
    u = User.objects.create_user(username="typing_user_b", password="pw", first_name="Bob")
    org.members.add(u)
    return u


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_typing_broadcast(event, user_a, user_b):
    """
    When user_a sends qna.typing true, user_b in the same main room
    receives a payload with user_a's server-derived identity.
    """
    comm_a = _make_qna_communicator(event.id, user_a)
    comm_b = _make_qna_communicator(event.id, user_b)

    connected_a, _ = await comm_a.connect()
    connected_b, _ = await comm_b.connect()
    assert connected_a and connected_b

    await comm_a.send_json_to({"type": "qna.typing", "is_typing": True})

    # user_a also receives the broadcast (sent to the whole group, including self)
    msg_a = await comm_a.receive_json_from()
    msg_b = await comm_b.receive_json_from()

    for msg in (msg_a, msg_b):
        assert msg["type"] == "qna.typing"
        assert msg["user_id"] == str(user_a.id)
        assert msg["user_name"] == "Alice"
        assert msg["is_typing"] is True
        assert msg["event_id"] == event.id
        assert msg["lounge_table_id"] is None
        assert "timestamp" in msg

    await comm_a.disconnect()
    await comm_b.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_typing_stop(event, user_a, user_b):
    """is_typing=false is broadcast to the group with correct flag."""
    comm_a = _make_qna_communicator(event.id, user_a)
    comm_b = _make_qna_communicator(event.id, user_b)

    await comm_a.connect()
    await comm_b.connect()

    await comm_a.send_json_to({"type": "qna.typing", "is_typing": False})

    msg_b = await comm_b.receive_json_from()
    assert msg_b["type"] == "qna.typing"
    assert msg_b["is_typing"] is False
    assert msg_b["user_id"] == str(user_a.id)

    await comm_a.disconnect()
    await comm_b.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_typing_ignores_spoofed_user_id(event, user_a, user_b):
    """
    Even if the client sends a fake user_id in the payload, the broadcast
    must carry the real authenticated socket user's identity.
    """
    comm_a = _make_qna_communicator(event.id, user_a)
    comm_b = _make_qna_communicator(event.id, user_b)

    await comm_a.connect()
    await comm_b.connect()

    # Attempt to spoof user_b's id
    await comm_a.send_json_to({
        "type": "qna.typing",
        "is_typing": True,
        "user_id": user_b.id,   # spoofed!
    })

    msg_b = await comm_b.receive_json_from()
    assert msg_b["type"] == "qna.typing"
    # Must be user_a's real id, not the spoofed user_b id
    assert msg_b["user_id"] == str(user_a.id)
    assert msg_b["user_id"] != str(user_b.id)

    await comm_a.disconnect()
    await comm_b.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_guest_typing(event, user_b):
    """Guest typing event broadcasts user_id as 'guest_N'."""
    guest_user = MockGuestUser(uid="guest_99", guest_id=99, name="Guest Alice")
    comm_guest = _make_qna_communicator(event.id, guest_user)
    comm_b = _make_qna_communicator(event.id, user_b)

    connected_guest, _ = await comm_guest.connect()
    connected_b, _ = await comm_b.connect()
    assert connected_guest and connected_b

    await comm_guest.send_json_to({"type": "qna.typing", "is_typing": True})

    msg_b = await comm_b.receive_json_from()
    assert msg_b["type"] == "qna.typing"
    assert msg_b["user_id"] == "guest_99"
    assert msg_b["user_name"] == "Guest Alice"
    assert msg_b["is_typing"] is True

    await comm_guest.disconnect()
    await comm_b.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_typing_table_isolation(event, user_a, user_b):
    """
    user_a typing in the main room does NOT appear to user_b in table room.
    They are subscribed to different groups so the event must NOT cross rooms.
    """
    comm_a_main = _make_qna_communicator(event.id, user_a)          # main room
    comm_b_table = _make_qna_communicator(event.id, user_b, lounge_table_id=5)  # table 5

    await comm_a_main.connect()
    await comm_b_table.connect()

    await comm_a_main.send_json_to({"type": "qna.typing", "is_typing": True})

    # user_a (same group) should receive the echo
    msg_a = await comm_a_main.receive_json_from()
    assert msg_a["type"] == "qna.typing"

    # user_b (different group) should NOT receive anything within a short timeout
    got_unexpected = False
    try:
        msg = await comm_b_table.receive_json_from(timeout=0.5)
        # If we received something, fail the test
        got_unexpected = True
    except Exception:
        pass  # Expected — no message means isolation works

    assert not got_unexpected, "Table room received typing from main room — isolation broken!"

    await comm_a_main.disconnect()
    await comm_b_table.disconnect()
