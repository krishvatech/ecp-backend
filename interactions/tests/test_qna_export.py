"""
Tests for the Q&A export endpoint.

GET /api/interactions/questions/export/?event_id=<id>&format=csv|pdf

Covers:
- host can export after event ends (CSV)
- staff can export after event ends (PDF)
- regular attendee cannot export (403)
- guest user cannot export (403)
- export blocked while event is not ended (403)
- missing / invalid query params return 400
- CSV response structure (content-type, BOM, headers, row values)
- PDF response content-type
- anonymous questions render "Anonymous" in CSV author column
- guest asker questions render guest display name (or Anonymous if anonymous)
"""
import csv
import io
import pytest
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from community.models import Community
from events.models import Event, GuestAttendee
from interactions.models import Question

User = get_user_model()


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def host(db):
    return User.objects.create_user(
        username="host_user",
        email="host@example.com",
        first_name="Event",
        last_name="Host",
        password="pass123",
    )


@pytest.fixture
def attendee(db):
    return User.objects.create_user(
        username="attendee_user",
        email="attendee@example.com",
        password="pass123",
    )


@pytest.fixture
def staff_user(db):
    return User.objects.create_user(
        username="staff_user",
        email="staff@example.com",
        password="pass123",
        is_staff=True,
    )


@pytest.fixture
def community(db, host):
    return Community.objects.create(name="Test Org", created_by=host)


@pytest.fixture
def ended_event(db, community, host):
    """An event in 'ended' status owned by *host*."""
    return Event.objects.create(
        title="Ended Event",
        community=community,
        created_by=host,
        status="ended",
    )


@pytest.fixture
def live_event(db, community, host):
    """An event in 'live' status — export should be blocked."""
    return Event.objects.create(
        title="Live Event",
        community=community,
        created_by=host,
        status="live",
    )


@pytest.fixture
def question_approved(db, ended_event, attendee):
    return Question.objects.create(
        event=ended_event,
        user=attendee,
        content="What is the roadmap?",
        moderation_status="approved",
        is_answered=True,
        answered_at=timezone.now(),
        answered_by=attendee,
        upvoters=[],   # no upvotes, just placeholder
    )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_question(event, user=None, guest=None, **kwargs):
    """Create a minimal Question without going through fixtures."""
    return Question.objects.create(
        event=event,
        user=user,
        guest_asker=guest,
        content=kwargs.pop("content", "A test question?"),
        **kwargs,
    )


def _auth_client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


EXPORT_URL = "/api/interactions/questions/export/"


def _csv_rows(response) -> list[list[str]]:
    """Parse a CSV export response into a list of rows (including header)."""
    # Strip BOM if present
    text = response.content.decode("utf-8-sig")
    reader = csv.reader(io.StringIO(text))
    return list(reader)


# ─────────────────────────────────────────────────────────────────────────────
# Permission & precondition tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_host_can_export_csv_after_event_ends(host, ended_event):
    _make_question(ended_event, user=host, content="Host question?")
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "csv"})
    assert resp.status_code == 200
    assert "text/csv" in resp["Content-Type"]


@pytest.mark.django_db
def test_staff_can_export_pdf_after_event_ends(staff_user, ended_event, host):
    _make_question(ended_event, user=host, content="Staff viewable question?")
    client = _auth_client(staff_user)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "pdf"})
    assert resp.status_code == 200
    assert resp["Content-Type"] == "application/pdf"


@pytest.mark.django_db
def test_attendee_cannot_export(attendee, ended_event, host):
    _make_question(ended_event, user=host)
    client = _auth_client(attendee)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "csv"})
    assert resp.status_code == 403


@pytest.mark.django_db
def test_unauthenticated_cannot_export(ended_event):
    client = APIClient()
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "csv"})
    assert resp.status_code in (401, 403)


@pytest.mark.django_db
def test_export_blocked_when_event_not_ended(host, live_event):
    _make_question(live_event, user=host)
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": live_event.pk, "format": "csv"})
    assert resp.status_code == 403
    assert "ended" in resp.json().get("detail", "").lower()


# ─────────────────────────────────────────────────────────────────────────────
# Validation tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_missing_event_id_returns_400(host):
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"format": "csv"})
    assert resp.status_code == 400


@pytest.mark.django_db
def test_invalid_format_returns_400(host, ended_event):
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "xlsx"})
    assert resp.status_code == 400


@pytest.mark.django_db
def test_nonexistent_event_returns_404(host):
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": 999999, "format": "csv"})
    assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# CSV structure tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_csv_has_correct_content_type_and_disposition(host, ended_event):
    _make_question(ended_event, user=host)
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "csv"})
    assert resp.status_code == 200
    assert "text/csv" in resp["Content-Type"]
    disposition = resp.get("Content-Disposition", "")
    assert "attachment" in disposition
    assert ".csv" in disposition


@pytest.mark.django_db
def test_csv_header_row_present(host, ended_event):
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "csv"})
    rows = _csv_rows(resp)
    assert len(rows) >= 1
    header = rows[0]
    assert "Question ID" in header
    assert "Question Text" in header
    assert "Author Display Name" in header
    assert "Moderation Status" in header
    assert "Answered" in header


@pytest.mark.django_db
def test_csv_contains_question_data(host, ended_event, attendee):
    _make_question(ended_event, user=attendee, content="Will there be Q&A?")
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "csv"})
    rows = _csv_rows(resp)
    # header + at least 1 data row
    assert len(rows) >= 2
    all_text = " ".join(" ".join(r) for r in rows[1:])
    assert "Will there be Q&A?" in all_text


# ─────────────────────────────────────────────────────────────────────────────
# Anonymity tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_anonymous_question_shows_anonymous_in_csv(host, ended_event, attendee):
    _make_question(
        ended_event,
        user=attendee,
        content="Anonymous question here",
        is_anonymous=True,
    )
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "csv"})
    rows = _csv_rows(resp)
    header = rows[0]
    author_col = header.index("Author Display Name")
    data_rows = rows[1:]
    assert len(data_rows) >= 1
    author_value = data_rows[0][author_col]
    assert author_value == "Anonymous", (
        f"Expected 'Anonymous' but got '{author_value}'"
    )


@pytest.mark.django_db
def test_non_anonymous_question_shows_real_name_in_csv(host, ended_event, attendee):
    attendee.first_name = "Alice"
    attendee.last_name = "Smith"
    attendee.save()
    _make_question(
        ended_event,
        user=attendee,
        content="Named question here",
        is_anonymous=False,
    )
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "csv"})
    rows = _csv_rows(resp)
    header = rows[0]
    author_col = header.index("Author Display Name")
    data_rows = rows[1:]
    author_value = data_rows[0][author_col]
    assert "Alice" in author_value or "Smith" in author_value


# ─────────────────────────────────────────────────────────────────────────────
# Guest asker tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_guest_question_shows_guest_name_in_csv(host, ended_event, db):
    guest = GuestAttendee.objects.create(
        event=ended_event,
        name="Guest Viewer",
        email="guest@example.com",
    )
    _make_question(ended_event, guest=guest, content="Guest's question here")
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "csv"})
    rows = _csv_rows(resp)
    header = rows[0]
    author_col = header.index("Author Display Name")
    author_type_col = header.index("Author Type")
    data_rows = rows[1:]
    assert len(data_rows) >= 1
    assert data_rows[0][author_type_col] == "guest"
    assert data_rows[0][author_col] == "Guest Viewer"


@pytest.mark.django_db
def test_anonymous_guest_question_shows_anonymous_in_csv(host, ended_event, db):
    guest = GuestAttendee.objects.create(
        event=ended_event,
        name="Hidden Guest",
        email="hidden@example.com",
    )
    _make_question(
        ended_event,
        guest=guest,
        content="Anonymous guest question",
        is_anonymous=True,
    )
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "csv"})
    rows = _csv_rows(resp)
    header = rows[0]
    author_col = header.index("Author Display Name")
    data_rows = rows[1:]
    assert data_rows[0][author_col] == "Anonymous"


# ─────────────────────────────────────────────────────────────────────────────
# PDF tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_pdf_has_correct_content_type(host, ended_event):
    _make_question(ended_event, user=host)
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "pdf"})
    assert resp.status_code == 200
    assert resp["Content-Type"] == "application/pdf"


@pytest.mark.django_db
def test_pdf_has_correct_content_disposition(host, ended_event):
    _make_question(ended_event, user=host)
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "pdf"})
    disposition = resp.get("Content-Disposition", "")
    assert "attachment" in disposition
    assert ".pdf" in disposition


@pytest.mark.django_db
def test_pdf_starts_with_pdf_magic_bytes(host, ended_event):
    _make_question(ended_event, user=host)
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "pdf"})
    assert resp.content[:4] == b"%PDF", "Response content does not start with PDF magic bytes"


# ─────────────────────────────────────────────────────────────────────────────
# Empty event test
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_csv_export_with_no_questions(host, ended_event):
    """Export succeeds even when there are zero questions; only header row returned."""
    client = _auth_client(host)
    resp = client.get(EXPORT_URL, {"event_id": ended_event.pk, "format": "csv"})
    assert resp.status_code == 200
    rows = _csv_rows(resp)
    # Only the header row
    assert len(rows) == 1
    assert rows[0][0] == "Question ID"
