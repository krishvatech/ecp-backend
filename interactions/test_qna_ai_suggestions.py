"""
Tests for POST /api/interactions/questions/ai-suggestions/

Covers:
  - Unauthenticated request rejected (401/403)
  - No context for event returns 404
  - Valid context returns 2-3 suggestions
  - count is capped at 3
  - No Question object is created
  - AI timeout returns 503
  - AI error returns 503
  - Guest with valid session can get suggestions
  - Guest session for different event is rejected (403)
  - Unit tests for suggest_questions() function

Run with:
  pytest interactions/test_qna_ai_suggestions.py -v
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from community.models import Community
from events.models import Event, GuestAttendee
from interactions.models import Question, QnAContentContext

User = get_user_model()

SUGGESTIONS_URL = "/api/interactions/questions/ai-suggestions/"


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def community(db):
    owner = User.objects.create_user(username="sugg_host", password="pw")
    org = Community.objects.create(name="SuggOrg", owner_id=owner.id, description="")
    return org


@pytest.fixture
def host(community):
    return User.objects.get(username="sugg_host")


@pytest.fixture
def event(community, host):
    return Event.objects.create(
        title="AI Suggestions Test Event",
        community=community,
        created_by=host,
        status="live",
    )


@pytest.fixture
def attendee(community):
    u = User.objects.create_user(username="sugg_attendee", password="pw")
    community.members.add(u)
    return u


@pytest.fixture
def guest(event):
    return GuestAttendee.objects.create(
        event=event,
        first_name="TestGuest",
        last_name="User",
        email="testguest@example.com",
    )


@pytest.fixture
def other_event(community, host):
    return Event.objects.create(
        title="Other Event",
        community=community,
        created_by=host,
        status="live",
    )


@pytest.fixture
def context(event):
    """A valid QnAContentContext for the test event."""
    return QnAContentContext.objects.create(
        event=event,
        source_type=QnAContentContext.SOURCE_HOST_NOTES,
        source_title="Session Overview",
        content_text="This session covers AI adoption in financial services, including risk management and regulatory compliance challenges.",
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


_MOCK_SUGGESTIONS = [
    {
        "id": "test-uuid-1",
        "question": "How will AI adoption change risk management practices?",
        "reason": "Based on the section discussing AI in financial services.",
    },
    {
        "id": "test-uuid-2",
        "question": "What regulatory challenges do banks face when deploying AI?",
        "reason": "Based on the compliance section of the presentation.",
    },
    {
        "id": "test-uuid-3",
        "question": "Are there proven frameworks for responsible AI in banking?",
        "reason": "Based on the regulatory compliance discussion.",
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# Authentication / access
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_suggestions_reject_unauthenticated(event, context):
    """Unauthenticated requests are rejected."""
    res = APIClient().post(
        SUGGESTIONS_URL,
        {"event_id": event.id},
        format="json",
    )
    assert res.status_code in (401, 403)


@pytest.mark.django_db
def test_suggestions_reject_missing_event_id(attendee):
    """Missing event_id returns 400."""
    res = _client(attendee).post(SUGGESTIONS_URL, {}, format="json")
    assert res.status_code == 400
    assert "event_id" in res.json().get("detail", "").lower()


@pytest.mark.django_db
def test_suggestions_reject_nonexistent_event(attendee):
    """Non-existent event returns 404."""
    res = _client(attendee).post(
        SUGGESTIONS_URL,
        {"event_id": 99999999},
        format="json",
    )
    assert res.status_code == 404


# ──────────────────────────────────────────────────────────────────────────────
# Context availability
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_suggestions_no_context_returns_404(event, attendee):
    """When no QnAContentContext exists for the event, return 404."""
    # No context fixture used here
    res = _client(attendee).post(
        SUGGESTIONS_URL,
        {"event_id": event.id},
        format="json",
    )
    assert res.status_code == 404
    assert "context" in res.json().get("detail", "").lower()


# ──────────────────────────────────────────────────────────────────────────────
# Success cases
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_suggestions_returns_list(event, attendee, context):
    """Valid request returns a list of suggestions."""
    with patch(
        "interactions.views.suggest_questions",
        return_value=_MOCK_SUGGESTIONS,
    ):
        res = _client(attendee).post(
            SUGGESTIONS_URL,
            {"event_id": event.id, "count": 3},
            format="json",
        )

    assert res.status_code == 200
    data = res.json()
    assert "suggestions" in data
    assert isinstance(data["suggestions"], list)
    assert len(data["suggestions"]) >= 1


@pytest.mark.django_db
def test_suggestions_have_required_fields(event, attendee, context):
    """Each suggestion has id, question, and reason fields."""
    with patch(
        "interactions.views.suggest_questions",
        return_value=_MOCK_SUGGESTIONS[:2],
    ):
        res = _client(attendee).post(
            SUGGESTIONS_URL,
            {"event_id": event.id},
            format="json",
        )

    assert res.status_code == 200
    for s in res.json()["suggestions"]:
        assert "question" in s
        assert "reason" in s
        assert s["question"]


@pytest.mark.django_db
def test_count_capped_at_3(event, attendee, context):
    """count > 3 is silently capped; suggest_questions called with count <= 3."""
    captured = {}

    def mock_suggest(event_title, session_title, context_text, count):
        captured["count"] = count
        return _MOCK_SUGGESTIONS[:count]

    with patch("interactions.views.suggest_questions", side_effect=mock_suggest):
        res = _client(attendee).post(
            SUGGESTIONS_URL,
            {"event_id": event.id, "count": 10},
            format="json",
        )

    assert res.status_code == 200
    assert captured["count"] == 3


@pytest.mark.django_db
def test_no_question_created(event, attendee, context):
    """The suggestions endpoint must never create a Question row."""
    before = Question.objects.count()
    with patch(
        "interactions.views.suggest_questions",
        return_value=_MOCK_SUGGESTIONS,
    ):
        _client(attendee).post(
            SUGGESTIONS_URL,
            {"event_id": event.id},
            format="json",
        )
    assert Question.objects.count() == before


# ──────────────────────────────────────────────────────────────────────────────
# Guest access
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_guest_can_get_suggestions(event, guest, context):
    """A guest with a valid session for the event can get suggestions."""
    with patch(
        "interactions.views.suggest_questions",
        return_value=_MOCK_SUGGESTIONS[:2],
    ):
        res = _guest_client(guest).post(
            SUGGESTIONS_URL,
            {"event_id": event.id},
            format="json",
        )
    assert res.status_code == 200
    assert len(res.json()["suggestions"]) >= 1


@pytest.mark.django_db
def test_guest_rejected_for_different_event(event, other_event, guest, context):
    """Guest session for event A cannot get suggestions for event B."""
    # guest belongs to `event`, not `other_event`
    with patch(
        "interactions.views.suggest_questions",
        return_value=_MOCK_SUGGESTIONS,
    ):
        res = _guest_client(guest).post(
            SUGGESTIONS_URL,
            {"event_id": other_event.id},
            format="json",
        )
    assert res.status_code == 403


# ──────────────────────────────────────────────────────────────────────────────
# AI failure handling
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_ai_timeout_returns_503(event, attendee, context):
    """AI timeout returns 503 with a friendly message; does not propagate."""
    with patch(
        "interactions.views.suggest_questions",
        side_effect=ValueError("AI service timed out."),
    ):
        res = _client(attendee).post(
            SUGGESTIONS_URL,
            {"event_id": event.id},
            format="json",
        )
    assert res.status_code == 503
    assert "try again" in res.json().get("detail", "").lower() or \
           "suggestions" in res.json().get("detail", "").lower()


@pytest.mark.django_db
def test_ai_error_returns_503(event, attendee, context):
    """Any AI ValueError returns 503, not 500."""
    with patch(
        "interactions.views.suggest_questions",
        side_effect=ValueError("OpenAI API key not configured."),
    ):
        res = _client(attendee).post(
            SUGGESTIONS_URL,
            {"event_id": event.id},
            format="json",
        )
    assert res.status_code == 503


# ──────────────────────────────────────────────────────────────────────────────
# Unit tests for the AI service module
# ──────────────────────────────────────────────────────────────────────────────

def test_suggest_questions_returns_list():
    """suggest_questions parses OpenAI response correctly."""
    from interactions.ai_question_suggestions import suggest_questions

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "suggestions": [
                            {"question": "How does this affect SMEs?", "reason": "Based on market impact section."},
                            {"question": "What is the regulatory timeline?", "reason": "Based on compliance slide."},
                        ]
                    })
                }
            }
        ]
    }

    with patch("interactions.ai_question_suggestions.requests.post", return_value=mock_response):
        with patch("interactions.ai_question_suggestions.os.getenv", return_value="fake-key"):
            result = suggest_questions("Test Event", "Test Session", "Some context text", count=2)

    assert isinstance(result, list)
    assert len(result) == 2
    assert all("question" in s and "reason" in s and "id" in s for s in result)


def test_suggest_questions_raises_on_missing_api_key():
    """suggest_questions raises ValueError when no API key is configured."""
    from interactions.ai_question_suggestions import suggest_questions

    with patch("interactions.ai_question_suggestions.os.getenv", return_value=""):
        with patch("django.conf.settings", OPENAI_API_KEY=""):
            with pytest.raises(ValueError, match="API key"):
                suggest_questions("Event", "Session", "Some context text about the presentation")


def test_suggest_questions_raises_on_timeout():
    """suggest_questions raises ValueError on requests.Timeout."""
    import requests as req_lib
    from interactions.ai_question_suggestions import suggest_questions

    with patch("interactions.ai_question_suggestions.os.getenv", return_value="fake-key"):
        with patch(
            "interactions.ai_question_suggestions.requests.post",
            side_effect=req_lib.Timeout(),
        ):
            with pytest.raises(ValueError, match="timed out"):
                suggest_questions("Event", "Session", "Context text for the webinar session")


def test_suggest_questions_raises_on_bad_json():
    """suggest_questions raises ValueError when AI returns non-JSON."""
    from interactions.ai_question_suggestions import suggest_questions

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": "not valid json {"}}]
    }

    with patch("interactions.ai_question_suggestions.requests.post", return_value=mock_response):
        with patch("interactions.ai_question_suggestions.os.getenv", return_value="fake-key"):
            with pytest.raises(ValueError, match="non-JSON"):
                suggest_questions("Event", "Session", "Context text for the session")


def test_suggest_questions_raises_on_empty_context():
    """suggest_questions raises ValueError when context is empty."""
    from interactions.ai_question_suggestions import suggest_questions

    with pytest.raises(ValueError, match="context"):
        suggest_questions("Event", "Session", "")
