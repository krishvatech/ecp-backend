"""
Tests for POST /api/interactions/questions/polish-draft/

Covers:
  - Valid request returns original + improved text
  - Empty content rejected (400)
  - Content below 5 chars rejected (400)
  - Content above 1000 chars rejected (400)
  - Missing event_id rejected (400)
  - Unauthenticated request rejected (401)
  - AI timeout handled safely (503, draft unchanged)
  - AI API error handled safely (503)
  - No Question object is created by the polish endpoint
  - Guest with valid event session can polish
  - Guest session for a different event is rejected (403)

Run with:
  pytest interactions/test_qna_polish.py -v
"""

import pytest
from unittest.mock import patch, MagicMock
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from community.models import Community
from events.models import Event, GuestAttendee
from interactions.models import Question

User = get_user_model()

POLISH_URL = "/api/interactions/questions/polish-draft/"


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def community(db):
    owner = User.objects.create_user(username="polish_host", password="pw")
    org = Community.objects.create(name="PolishOrg", owner_id=owner.id, description="")
    return org


@pytest.fixture
def host(community):
    return User.objects.get(username="polish_host")


@pytest.fixture
def event(community, host):
    return Event.objects.create(
        title="PolishEvent",
        community=community,
        created_by=host,
        status="live",
    )


@pytest.fixture
def attendee(community):
    u = User.objects.create_user(username="polish_attendee", password="pw")
    community.members.add(u)
    return u


@pytest.fixture
def guest(event):
    return GuestAttendee.objects.create(
        event=event,
        first_name="GuestPol",
        last_name="User",
        email="guestpol@example.com",
    )


@pytest.fixture
def other_event(community, host):
    """A second event — guest sessions for this should not access the first event."""
    return Event.objects.create(
        title="OtherPolishEvent",
        community=community,
        created_by=host,
        status="live",
    )


def _client(user):
    c = APIClient()
    c.force_authenticate(user=user)
    return c


def _guest_client(guest_obj):
    """Build a DRF client that looks like an authenticated guest."""
    mock_user = MagicMock()
    mock_user.is_authenticated = True
    mock_user.is_guest = True
    mock_user.guest = guest_obj
    mock_user.is_staff = False
    mock_user.pk = f"guest_{guest_obj.id}"

    c = APIClient()
    c.force_authenticate(user=mock_user)
    return c


# ──────────────────────────────────────────────────────────────────────────────
# Success cases
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_polish_returns_original_and_improved(event, attendee):
    """Valid request returns original, improved, and changed fields."""
    improved_text = "If I cannot attend the live session, will I be able to watch it later?"
    with patch(
        "interactions.views.polish_question",
        return_value=improved_text,
    ):
        res = _client(attendee).post(
            POLISH_URL,
            {"event_id": event.id, "content": "what happen if i miss the live"},
            format="json",
        )

    assert res.status_code == 200
    data = res.json()
    assert data["original"] == "what happen if i miss the live"
    assert data["improved"] == improved_text
    assert data["changed"] is True


@pytest.mark.django_db
def test_polish_changed_false_when_identical(event, attendee):
    """If AI returns the same text, changed=False."""
    content = "Will there be a replay available?"
    with patch("interactions.views.polish_question", return_value=content):
        res = _client(attendee).post(
            POLISH_URL,
            {"event_id": event.id, "content": content},
            format="json",
        )

    assert res.status_code == 200
    assert res.json()["changed"] is False


@pytest.mark.django_db
def test_polish_does_not_create_question(event, attendee):
    """The polish endpoint must never create a Question row."""
    before = Question.objects.count()
    with patch("interactions.views.polish_question", return_value="Better question?"):
        _client(attendee).post(
            POLISH_URL,
            {"event_id": event.id, "content": "rough question text here"},
            format="json",
        )
    assert Question.objects.count() == before


@pytest.mark.django_db
def test_host_can_polish(event, host):
    """Event host can also use the polish endpoint."""
    with patch("interactions.views.polish_question", return_value="Polished question?"):
        res = _client(host).post(
            POLISH_URL,
            {"event_id": event.id, "content": "rough draft question"},
            format="json",
        )
    assert res.status_code == 200


# ──────────────────────────────────────────────────────────────────────────────
# Validation rejections
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_polish_rejects_empty_content(event, attendee):
    res = _client(attendee).post(
        POLISH_URL,
        {"event_id": event.id, "content": ""},
        format="json",
    )
    assert res.status_code == 400
    assert "content" in res.json().get("detail", "").lower()


@pytest.mark.django_db
def test_polish_rejects_content_below_minimum(event, attendee):
    res = _client(attendee).post(
        POLISH_URL,
        {"event_id": event.id, "content": "hi"},  # 2 chars
        format="json",
    )
    assert res.status_code == 400
    assert "5" in res.json().get("detail", "")


@pytest.mark.django_db
def test_polish_rejects_content_above_maximum(event, attendee):
    res = _client(attendee).post(
        POLISH_URL,
        {"event_id": event.id, "content": "x" * 1001},
        format="json",
    )
    assert res.status_code == 400
    assert "1000" in res.json().get("detail", "")


@pytest.mark.django_db
def test_polish_rejects_missing_event_id(event, attendee):
    res = _client(attendee).post(
        POLISH_URL,
        {"content": "What is the agenda for this event?"},
        format="json",
    )
    assert res.status_code == 400
    assert "event_id" in res.json().get("detail", "").lower()


@pytest.mark.django_db
def test_polish_rejects_nonexistent_event(attendee):
    res = _client(attendee).post(
        POLISH_URL,
        {"event_id": 99999999, "content": "Will there be a recording?"},
        format="json",
    )
    assert res.status_code == 404


# ──────────────────────────────────────────────────────────────────────────────
# Authentication
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_polish_rejects_unauthenticated(event):
    res = APIClient().post(
        POLISH_URL,
        {"event_id": event.id, "content": "Can I get the slides after?"},
        format="json",
    )
    assert res.status_code in (401, 403)


# ──────────────────────────────────────────────────────────────────────────────
# Guest access
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_guest_can_polish_own_event(event, guest):
    """A guest with a valid session for the event can call polish."""
    with patch("interactions.views.polish_question", return_value="Polished guest question?"):
        res = _guest_client(guest).post(
            POLISH_URL,
            {"event_id": event.id, "content": "what time does the session start"},
            format="json",
        )
    assert res.status_code == 200


@pytest.mark.django_db
def test_guest_rejected_for_different_event(event, other_event, guest):
    """A guest session for event A cannot polish for event B."""
    # guest belongs to `event`, not `other_event`
    with patch("interactions.views.polish_question", return_value="Should not reach here"):
        res = _guest_client(guest).post(
            POLISH_URL,
            {"event_id": other_event.id, "content": "question about other event"},
            format="json",
        )
    assert res.status_code == 403


# ──────────────────────────────────────────────────────────────────────────────
# AI failure handling
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_polish_handles_ai_timeout(event, attendee):
    """AI timeout returns 503 with a friendly message; no exception propagates."""
    with patch(
        "interactions.views.polish_question",
        side_effect=ValueError("AI service timed out."),
    ):
        res = _client(attendee).post(
            POLISH_URL,
            {"event_id": event.id, "content": "What if the event gets cancelled?"},
            format="json",
        )
    assert res.status_code == 503
    assert "polish" in res.json().get("detail", "").lower() or "try again" in res.json().get("detail", "").lower()


@pytest.mark.django_db
def test_polish_handles_ai_api_error(event, attendee):
    """Any AI ValueError returns 503, not 500."""
    with patch(
        "interactions.views.polish_question",
        side_effect=ValueError("OpenAI API key not configured."),
    ):
        res = _client(attendee).post(
            POLISH_URL,
            {"event_id": event.id, "content": "Will the session be recorded?"},
            format="json",
        )
    assert res.status_code == 503


# ──────────────────────────────────────────────────────────────────────────────
# Unit tests for the AI service module
# ──────────────────────────────────────────────────────────────────────────────

def test_polish_question_returns_improved_text():
    """ai_question_polish.polish_question parses the OpenAI response correctly."""
    import json
    from interactions.ai_question_polish import polish_question

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {"improved": "Will there be a replay available after the event?"}
                    )
                }
            }
        ]
    }

    with patch("interactions.ai_question_polish.requests.post", return_value=mock_response):
        with patch("interactions.ai_question_polish.os.getenv", return_value="fake-key"):
            result = polish_question("will there be replay")

    assert result == "Will there be a replay available after the event?"


def test_polish_question_raises_on_missing_api_key():
    """polish_question raises ValueError when no API key is configured."""
    from interactions.ai_question_polish import polish_question

    with patch("interactions.ai_question_polish.os.getenv", return_value=""):
        with patch("django.conf.settings", OPENAI_API_KEY=""):
            with pytest.raises(ValueError, match="API key"):
                polish_question("what time does the event start")


def test_polish_question_raises_on_timeout():
    """polish_question raises ValueError on requests.Timeout."""
    import requests as req_lib
    from interactions.ai_question_polish import polish_question

    with patch("interactions.ai_question_polish.os.getenv", return_value="fake-key"):
        with patch(
            "interactions.ai_question_polish.requests.post",
            side_effect=req_lib.Timeout(),
        ):
            with pytest.raises(ValueError, match="timed out"):
                polish_question("will there be a recording after the session")


def test_polish_question_raises_on_bad_json():
    """polish_question raises ValueError when AI returns non-JSON."""
    from interactions.ai_question_polish import polish_question

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": "not valid json {"}}]
    }

    with patch("interactions.ai_question_polish.requests.post", return_value=mock_response):
        with patch("interactions.ai_question_polish.os.getenv", return_value="fake-key"):
            with pytest.raises(ValueError, match="non-JSON"):
                polish_question("what time does the event start today")
