"""
Tests for Q&A Threaded Replies.

Covers:
  - Create reply (authenticated user)
  - Create reply (guest)
  - Create reply anonymous (event anonymous mode)
  - Moderation: reply starts pending when qna_moderation_enabled
  - Host approves a pending reply
  - Host rejects a reply
  - Reply upvote toggle (user and guest)
  - Edit reply (owner can, other user cannot)
  - Delete reply (owner can, host can, other cannot)
  - Attendee visibility: pending replies hidden, approved visible
  - Host visibility: sees all replies including pending
  - Reply appears in question list response
  - One-level only: reply model has no child-reply field

Run with:
  pytest interactions/test_qna_replies.py -v
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from community.models import Community
from events.models import Event, GuestAttendee
from interactions.models import (
    Question,
    QnAReply,
    QnAReplyUpvote,
    QnAReplyGuestUpvote,
)

User = get_user_model()


# ──────────────────────────────────────────────────────────────────────────────
# URL helpers
# ──────────────────────────────────────────────────────────────────────────────

def replies_url(question_id):
    return f"/api/interactions/questions/{question_id}/replies/"


def reply_url(reply_id):
    return f"/api/interactions/replies/{reply_id}/"


def reply_action_url(reply_id, action):
    return f"/api/interactions/replies/{reply_id}/{action}/"


def questions_url(event_id):
    return f"/api/interactions/questions/?event_id={event_id}"


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def community(db):
    host = User.objects.create_user(username="host_fixture", password="pw")
    org = Community.objects.create(name="TestOrg", owner_id=host.id, description="")
    return org


@pytest.fixture
def host_user(community):
    return User.objects.get(username="host_fixture")


@pytest.fixture
def event(community, host_user):
    return Event.objects.create(
        title="TestEvent",
        community=community,
        created_by=host_user,
        status="live",
    )


@pytest.fixture
def attendee(community):
    u = User.objects.create_user(username="attendee_fixture", password="pw")
    community.members.add(u)
    return u


@pytest.fixture
def other_user(community):
    u = User.objects.create_user(username="other_fixture", password="pw")
    community.members.add(u)
    return u


@pytest.fixture
def question(event, attendee):
    return Question.objects.create(
        event=event,
        user=attendee,
        content="What is the main topic?",
        moderation_status="approved",
    )


@pytest.fixture
def guest(event):
    return GuestAttendee.objects.create(
        event=event,
        first_name="Guest",
        last_name="User",
        email="guest@example.com",
    )


def _client(user):
    c = APIClient()
    c.force_authenticate(user=user)
    return c


def _guest_client(guest_obj):
    """
    Build a DRF client that looks like an authenticated guest.
    We monkey-patch a minimal guest-like user.
    """
    from unittest.mock import MagicMock
    fake_user = MagicMock()
    fake_user.is_authenticated = True
    fake_user.is_guest = True
    fake_user.is_staff = False          # prevent MagicMock auto-truthy on is_staff
    fake_user.is_superuser = False
    fake_user.guest = guest_obj
    fake_user.id = None
    c = APIClient()
    c.force_authenticate(user=fake_user)
    return c


# ──────────────────────────────────────────────────────────────────────────────
# 1. Create reply (authenticated user)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_create_reply_authenticated(event, attendee, question):
    client = _client(attendee)
    resp = client.post(replies_url(question.id), {"content": "Great question!"}, format="json")
    assert resp.status_code == 201
    assert QnAReply.objects.filter(question=question, user=attendee).count() == 1
    reply = QnAReply.objects.get(question=question, user=attendee)
    assert reply.content == "Great question!"
    assert reply.event == event
    assert reply.lounge_table is None  # inherits from question (main room)


# ──────────────────────────────────────────────────────────────────────────────
# 2. Create reply (guest)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_create_reply_guest(event, question, guest):
    client = _guest_client(guest)
    resp = client.post(replies_url(question.id), {"content": "Thanks for asking!"}, format="json")
    assert resp.status_code == 201
    assert QnAReply.objects.filter(question=question, guest_asker=guest).count() == 1


# ──────────────────────────────────────────────────────────────────────────────
# 3. Anonymous reply via event anonymous mode
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_anonymous_reply_event_mode(event, attendee, question):
    event.qna_anonymous_mode = True
    event.save(update_fields=["qna_anonymous_mode"])

    client = _client(attendee)
    resp = client.post(replies_url(question.id), {"content": "Anonymous reply"}, format="json")
    assert resp.status_code == 201

    reply = QnAReply.objects.get(question=question, user=attendee)
    assert reply.is_anonymous is True


# ──────────────────────────────────────────────────────────────────────────────
# 4. Moderation: reply starts pending
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_reply_pending_when_moderation_enabled(event, attendee, question):
    event.qna_moderation_enabled = True
    event.save(update_fields=["qna_moderation_enabled"])

    client = _client(attendee)
    resp = client.post(replies_url(question.id), {"content": "Pending reply"}, format="json")
    assert resp.status_code == 201

    reply = QnAReply.objects.get(question=question)
    assert reply.moderation_status == "pending"


# ──────────────────────────────────────────────────────────────────────────────
# 5. Host approves a pending reply
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_host_approves_reply(event, host_user, attendee, question):
    reply = QnAReply.objects.create(
        question=question,
        event=event,
        user=attendee,
        content="Pending reply",
        moderation_status="pending",
    )

    client = _client(host_user)
    resp = client.post(reply_action_url(reply.id, "approve"), format="json")
    assert resp.status_code == 200

    reply.refresh_from_db()
    assert reply.moderation_status == "approved"


# ──────────────────────────────────────────────────────────────────────────────
# 6. Host rejects a reply
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_host_rejects_reply(event, host_user, attendee, question):
    reply = QnAReply.objects.create(
        question=question,
        event=event,
        user=attendee,
        content="Spam reply",
        moderation_status="pending",
    )

    client = _client(host_user)
    resp = client.post(reply_action_url(reply.id, "reject"), {"reason": "Spam"}, format="json")
    assert resp.status_code == 200

    reply.refresh_from_db()
    assert reply.moderation_status == "rejected"
    assert reply.rejection_reason == "Spam"


# ──────────────────────────────────────────────────────────────────────────────
# 7a. Reply upvote toggle (user)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_reply_upvote_toggle_user(event, attendee, other_user, question):
    reply = QnAReply.objects.create(
        question=question, event=event, user=attendee, content="Reply A"
    )
    client = _client(other_user)

    # First upvote
    resp = client.post(reply_action_url(reply.id, "upvote"), format="json")
    assert resp.status_code == 200
    assert resp.data["upvoted"] is True
    assert resp.data["upvote_count"] == 1
    assert QnAReplyUpvote.objects.filter(reply=reply, user=other_user).exists()

    # Toggle off
    resp = client.post(reply_action_url(reply.id, "upvote"), format="json")
    assert resp.status_code == 200
    assert resp.data["upvoted"] is False
    assert resp.data["upvote_count"] == 0
    assert not QnAReplyUpvote.objects.filter(reply=reply, user=other_user).exists()


# ──────────────────────────────────────────────────────────────────────────────
# 7b. Reply upvote toggle (guest)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_reply_upvote_toggle_guest(event, attendee, question, guest):
    reply = QnAReply.objects.create(
        question=question, event=event, user=attendee, content="Reply B"
    )
    client = _guest_client(guest)

    resp = client.post(reply_action_url(reply.id, "upvote"), format="json")
    assert resp.status_code == 200
    assert resp.data["upvoted"] is True
    assert QnAReplyGuestUpvote.objects.filter(reply=reply, guest=guest).exists()

    resp = client.post(reply_action_url(reply.id, "upvote"), format="json")
    assert resp.status_code == 200
    assert resp.data["upvoted"] is False
    assert not QnAReplyGuestUpvote.objects.filter(reply=reply, guest=guest).exists()


# ──────────────────────────────────────────────────────────────────────────────
# 8. Edit reply permissions
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_owner_can_edit_reply(event, attendee, question):
    reply = QnAReply.objects.create(
        question=question, event=event, user=attendee, content="Original"
    )
    client = _client(attendee)
    resp = client.patch(reply_url(reply.id), {"content": "Updated"}, format="json")
    assert resp.status_code == 200
    reply.refresh_from_db()
    assert reply.content == "Updated"


@pytest.mark.django_db
def test_other_user_cannot_edit_reply(event, attendee, other_user, question):
    reply = QnAReply.objects.create(
        question=question, event=event, user=attendee, content="Original"
    )
    client = _client(other_user)
    resp = client.patch(reply_url(reply.id), {"content": "Hijacked"}, format="json")
    assert resp.status_code == 403


@pytest.mark.django_db
def test_host_can_edit_reply(event, host_user, attendee, question):
    reply = QnAReply.objects.create(
        question=question, event=event, user=attendee, content="Original"
    )
    client = _client(host_user)
    resp = client.patch(reply_url(reply.id), {"content": "Host edit"}, format="json")
    assert resp.status_code == 200


# ──────────────────────────────────────────────────────────────────────────────
# 9. Delete reply permissions
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_owner_can_delete_reply(event, attendee, question):
    reply = QnAReply.objects.create(
        question=question, event=event, user=attendee, content="Delete me"
    )
    client = _client(attendee)
    resp = client.delete(reply_url(reply.id))
    assert resp.status_code == 204
    assert not QnAReply.objects.filter(pk=reply.id).exists()


@pytest.mark.django_db
def test_other_user_cannot_delete_reply(event, attendee, other_user, question):
    reply = QnAReply.objects.create(
        question=question, event=event, user=attendee, content="Protected"
    )
    client = _client(other_user)
    resp = client.delete(reply_url(reply.id))
    assert resp.status_code == 403


@pytest.mark.django_db
def test_host_can_delete_reply(event, host_user, attendee, question):
    reply = QnAReply.objects.create(
        question=question, event=event, user=attendee, content="Host can remove"
    )
    client = _client(host_user)
    resp = client.delete(reply_url(reply.id))
    assert resp.status_code == 204


# ──────────────────────────────────────────────────────────────────────────────
# 10a. Attendee visibility: pending replies hidden
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_attendee_cannot_see_pending_reply(event, attendee, other_user, question):
    event.qna_moderation_enabled = True
    event.save(update_fields=["qna_moderation_enabled"])

    QnAReply.objects.create(
        question=question, event=event, user=attendee,
        content="Pending", moderation_status="pending"
    )
    QnAReply.objects.create(
        question=question, event=event, user=attendee,
        content="Approved", moderation_status="approved"
    )

    client = _client(other_user)
    resp = client.get(replies_url(question.id))
    assert resp.status_code == 200
    contents = [r["content"] for r in resp.data]
    assert "Approved" in contents
    assert "Pending" not in contents


# ──────────────────────────────────────────────────────────────────────────────
# 10b. Host visibility: sees all replies
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_host_sees_all_replies(event, host_user, attendee, question):
    event.qna_moderation_enabled = True
    event.save(update_fields=["qna_moderation_enabled"])

    QnAReply.objects.create(
        question=question, event=event, user=attendee,
        content="Pending", moderation_status="pending"
    )
    QnAReply.objects.create(
        question=question, event=event, user=attendee,
        content="Approved", moderation_status="approved"
    )

    client = _client(host_user)
    resp = client.get(replies_url(question.id))
    assert resp.status_code == 200
    contents = [r["content"] for r in resp.data]
    assert "Pending" in contents
    assert "Approved" in contents


# ──────────────────────────────────────────────────────────────────────────────
# 11. Replies embedded in question list response
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_replies_embedded_in_question_list(event, attendee, question):
    QnAReply.objects.create(
        question=question, event=event, user=attendee, content="Embedded reply"
    )

    client = _client(attendee)
    resp = client.get(questions_url(event.id))
    assert resp.status_code == 200

    # Find the question in the list
    q_data = next((q for q in resp.data if q["id"] == question.id), None)
    assert q_data is not None
    assert "replies" in q_data
    assert "reply_count" in q_data
    assert q_data["reply_count"] == 1
    assert q_data["replies"][0]["content"] == "Embedded reply"


# ──────────────────────────────────────────────────────────────────────────────
# 12. One-level only: QnAReply has no question FK pointing to another reply
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_one_level_only_model_has_question_fk_not_reply_fk():
    """
    QnAReply must only have a FK to Question, never to another QnAReply.
    This ensures one-level threading at the schema level.
    """
    field_names = [f.name for f in QnAReply._meta.get_fields()]
    assert "question" in field_names
    # No self-referential FK
    for field in QnAReply._meta.get_fields():
        if hasattr(field, "related_model") and field.related_model is QnAReply:
            pytest.fail("QnAReply has a self-referential FK — replies should be one-level only")


# ──────────────────────────────────────────────────────────────────────────────
# 13. Unauthenticated user cannot post a reply
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_unauthenticated_cannot_post_reply(question):
    client = APIClient()
    resp = client.post(replies_url(question.id), {"content": "Sneaky reply"}, format="json")
    assert resp.status_code in (401, 403)


# ──────────────────────────────────────────────────────────────────────────────
# 14. Anonymize reply toggle (host only)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_host_anonymize_reply(event, host_user, attendee, question):
    reply = QnAReply.objects.create(
        question=question, event=event, user=attendee, content="Real name reply"
    )
    assert reply.is_anonymous is False

    client = _client(host_user)
    resp = client.post(reply_action_url(reply.id, "anonymize"), format="json")
    assert resp.status_code == 200
    assert resp.data["is_anonymous"] is True

    reply.refresh_from_db()
    assert reply.is_anonymous is True
    assert reply.anonymized_by == host_user

    # Toggle back
    resp = client.post(reply_action_url(reply.id, "anonymize"), format="json")
    assert resp.status_code == 200
    assert resp.data["is_anonymous"] is False


@pytest.mark.django_db
def test_attendee_cannot_anonymize_reply(event, attendee, other_user, question):
    reply = QnAReply.objects.create(
        question=question, event=event, user=attendee, content="Real name reply"
    )
    client = _client(other_user)
    resp = client.post(reply_action_url(reply.id, "anonymize"), format="json")
    assert resp.status_code == 403
