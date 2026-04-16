"""
Tests for the Q&A Engagement Prompt feature.

Covers:
  - Host can trigger a prompt (201)
  - Non-host cannot trigger (403)
  - Attendee ack returns show=True under cap
  - Attendee ack returns show=False once cap is reached
  - Guest ack creates a receipt and returns show=True
  - Dismiss marks dismissed_at on the receipt

Uses pytest + Django's APIClient (rest_framework.test).
Run with:
  pytest interactions/test_engagement_prompt.py -v
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from community.models import Community
from events.models import Event, GuestAttendee
from interactions.models import (
    QnAEngagementPrompt,
    QnAEngagementPromptReceipt,
    QNA_PROMPT_MAX_PER_USER,
)

User = get_user_model()

TRIGGER_URL = "/api/interactions/questions/engagement-prompt/trigger/"


def ack_url(prompt_id):
    return f"/api/interactions/questions/engagement-prompt/{prompt_id}/ack/"


def dismiss_url(prompt_id):
    return f"/api/interactions/questions/engagement-prompt/{prompt_id}/dismiss/"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

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
    )


@pytest.fixture
def attendee(db, community):
    user = User.objects.create_user(username="attendee1", password="pw")
    community.members.add(user)
    return user


@pytest.fixture
def host_client(host_user):
    client = APIClient()
    client.force_authenticate(user=host_user)
    return client


@pytest.fixture
def attendee_client(attendee):
    client = APIClient()
    client.force_authenticate(user=attendee)
    return client


# ---------------------------------------------------------------------------
# Tests: Trigger
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_host_can_trigger(host_client, event):
    """Host can trigger a Q&A engagement prompt → HTTP 201, DB record created."""
    resp = host_client.post(TRIGGER_URL, {"event_id": event.id}, format="json")
    assert resp.status_code == 201, resp.data
    data = resp.data
    assert "prompt_id" in data
    assert data["event_id"] == event.id
    assert QnAEngagementPrompt.objects.filter(event=event).count() == 1


@pytest.mark.django_db
def test_nonhost_cannot_trigger(attendee_client, event):
    """Non-host gets a 403 when trying to trigger a prompt."""
    resp = attendee_client.post(TRIGGER_URL, {"event_id": event.id}, format="json")
    assert resp.status_code == 403, resp.data


@pytest.mark.django_db
def test_trigger_custom_message(host_client, event):
    """Host can provide a custom message and auto_hide_seconds."""
    resp = host_client.post(
        TRIGGER_URL,
        {"event_id": event.id, "message": "Got questions? Ask now!", "auto_hide_seconds": 20},
        format="json",
    )
    assert resp.status_code == 201, resp.data
    prompt = QnAEngagementPrompt.objects.get(pk=resp.data["prompt_id"])
    assert prompt.message == "Got questions? Ask now!"
    assert prompt.auto_hide_seconds == 20


# ---------------------------------------------------------------------------
# Tests: Ack
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_ack_returns_show_true_under_cap(host_client, attendee_client, event):
    """Attendee ack returns show=True when under the prompt cap."""
    # Host creates a prompt
    trigger_resp = host_client.post(TRIGGER_URL, {"event_id": event.id}, format="json")
    assert trigger_resp.status_code == 201
    prompt_id = trigger_resp.data["prompt_id"]

    resp = attendee_client.post(ack_url(prompt_id), format="json")
    assert resp.status_code == 200, resp.data
    assert resp.data["show"] is True
    assert resp.data["max_reached"] is False
    assert resp.data["prompt_id"] == prompt_id
    assert QnAEngagementPromptReceipt.objects.filter(prompt_id=prompt_id).count() == 1


@pytest.mark.django_db
def test_ack_returns_show_false_when_cap_reached(host_client, attendee_client, event):
    """Attendee ack returns show=False once QNA_PROMPT_MAX_PER_USER receipts exist."""
    # Fill up the cap with existing receipts
    attendee_obj = User.objects.get(username="attendee1")
    for _ in range(QNA_PROMPT_MAX_PER_USER):
        prompt = QnAEngagementPrompt.objects.create(
            event=event,
            triggered_by=event.created_by,
        )
        QnAEngagementPromptReceipt.objects.create(
            prompt=prompt,
            event=event,
            user=attendee_obj,
        )

    # Trigger one more prompt, then ack it
    trigger_resp = host_client.post(TRIGGER_URL, {"event_id": event.id}, format="json")
    assert trigger_resp.status_code == 201
    new_prompt_id = trigger_resp.data["prompt_id"]

    resp = attendee_client.post(ack_url(new_prompt_id), format="json")
    assert resp.status_code == 200, resp.data
    assert resp.data["show"] is False
    assert resp.data["max_reached"] is True


@pytest.mark.django_db
def test_ack_prompt_not_found(attendee_client):
    """Ack on a non-existent prompt returns 404."""
    resp = attendee_client.post(ack_url(99999), format="json")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tests: Guest Ack
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_guest_ack_creates_receipt(host_client, event):
    """Guest attendee ack creates a receipt and returns show=True."""
    # Create a guest attendee
    guest = GuestAttendee.objects.create(
        event=event,
        email="guest@example.com",
        first_name="Guest",
        last_name="User",
    )

    # Simulate a guest user (mirrors how guest auth works in the system)
    from django.contrib.auth.models import AnonymousUser

    class MockGuestUser:
        is_authenticated = True
        is_guest = True
        is_staff = False
        id = f"guest_{guest.id}"

        def __init__(self, g):
            self.guest = g

    guest_user = MockGuestUser(guest)

    # Create a prompt
    trigger_resp = host_client.post(TRIGGER_URL, {"event_id": event.id}, format="json")
    assert trigger_resp.status_code == 201
    prompt_id = trigger_resp.data["prompt_id"]

    # Ack as guest using force_authenticate
    guest_client = APIClient()
    guest_client.force_authenticate(user=guest_user)
    resp = guest_client.post(ack_url(prompt_id), format="json")

    assert resp.status_code == 200, resp.data
    assert resp.data["show"] is True
    assert QnAEngagementPromptReceipt.objects.filter(
        prompt_id=prompt_id, guest=guest
    ).count() == 1


# ---------------------------------------------------------------------------
# Tests: Dismiss
# ---------------------------------------------------------------------------

@pytest.mark.django_db
def test_dismiss_sets_dismissed_at(host_client, attendee_client, event):
    """Attendee dismissing a banner sets dismissed_at on the receipt."""
    trigger_resp = host_client.post(TRIGGER_URL, {"event_id": event.id}, format="json")
    assert trigger_resp.status_code == 201
    prompt_id = trigger_resp.data["prompt_id"]

    # Ack first (creates receipt)
    ack_resp = attendee_client.post(ack_url(prompt_id), format="json")
    assert ack_resp.data["show"] is True

    # Dismiss
    dismiss_resp = attendee_client.post(dismiss_url(prompt_id), format="json")
    assert dismiss_resp.status_code == 200, dismiss_resp.data
    assert dismiss_resp.data["dismissed"] is True

    # Verify DB
    attendee_obj = User.objects.get(username="attendee1")
    receipt = QnAEngagementPromptReceipt.objects.get(
        prompt_id=prompt_id, user=attendee_obj
    )
    assert receipt.dismissed_at is not None


@pytest.mark.django_db
def test_dismiss_no_receipt_is_safe(attendee_client, event, host_client):
    """Dismissing when no receipt exists returns OK (idempotent)."""
    trigger_resp = host_client.post(TRIGGER_URL, {"event_id": event.id}, format="json")
    prompt_id = trigger_resp.data["prompt_id"]

    # Dismiss without acking first (no receipt)
    resp = attendee_client.post(dismiss_url(prompt_id), format="json")
    assert resp.status_code == 200, resp.data
    assert resp.data["dismissed"] is True
