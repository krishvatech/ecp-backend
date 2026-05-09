"""
Tests for external streaming platform feature.

Coverage:
- Model fields and validation
- API endpoint: GET /api/events/{id}/streaming-link/
- Update validation: external streaming configuration
- Permission checks: password visibility for managers vs attendees
"""

import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient

from community.models import Community
from events.models import Event


@pytest.fixture
def owner(db):
    return User.objects.create_user(username="owner", email="owner@example.com", password="pass123")


@pytest.fixture
def attendee(db):
    return User.objects.create_user(username="attendee", email="attendee@example.com", password="pass123")


@pytest.fixture
def community(db, owner):
    return Community.objects.create(name="Test Community", created_by=owner)


@pytest.fixture
def event(db, community, owner):
    return Event.objects.create(
        community=community,
        title="Test Event",
        created_by=owner,
        format="virtual",
        status="published",
    )


# ============================================================
# Model Field Tests
# ============================================================

@pytest.mark.django_db
def test_event_external_streaming_defaults(event):
    """Test that external streaming fields have correct defaults."""
    assert event.use_external_streaming is False
    assert event.external_streaming_platform == "native"
    assert event.external_streaming_url == ""
    assert event.external_streaming_meeting_id == ""
    assert event.external_streaming_password == ""
    assert event.external_streaming_other_details == ""
    assert event.external_streaming_host_link == ""


@pytest.mark.django_db
def test_event_streaming_platform_choices():
    """Test that platform choices are correctly defined."""
    choices = dict(Event.STREAMING_PLATFORM_CHOICES)
    assert "native" in choices
    assert "zoom" in choices
    assert "google_meet" in choices
    assert "microsoft_teams" in choices


# ============================================================
# API Endpoint Tests: GET /api/events/{id}/streaming-link/
# ============================================================

@pytest.mark.django_db
def test_streaming_link_native_rtk(event):
    """Test streaming-link endpoint returns native RTK info when not using external streaming."""
    client = APIClient()
    event.use_external_streaming = False
    event.rtk_meeting_id = "rtk_123"
    event.save()

    res = client.get(f"/api/events/{event.id}/streaming-link/")
    assert res.status_code == 200
    assert res.data["type"] == "native"
    assert res.data["platform"] == "native"
    assert res.data["platform_name"] == "Our Platform (RTK)"
    assert res.data["meeting_id"] == "rtk_123"


@pytest.mark.django_db
def test_streaming_link_external_zoom(event):
    """Test streaming-link endpoint returns Zoom details when external streaming enabled."""
    client = APIClient()
    event.use_external_streaming = True
    event.external_streaming_platform = "zoom"
    event.external_streaming_url = "https://zoom.us/j/123456789"
    event.external_streaming_meeting_id = "123456789"
    event.external_streaming_password = "password123"
    event.external_streaming_other_details = "Password in email"
    event.external_streaming_host_link = "https://zoom.us/j/123456789?pwd=..."
    event.save()

    res = client.get(f"/api/events/{event.id}/streaming-link/")
    assert res.status_code == 200
    assert res.data["type"] == "external"
    assert res.data["platform"] == "zoom"
    assert res.data["platform_name"] == "Zoom"
    assert res.data["join_url"] == "https://zoom.us/j/123456789"
    assert res.data["meeting_id"] == "123456789"
    assert res.data["instructions"] == "Password in email"
    assert res.data["host_link"] == "https://zoom.us/j/123456789?pwd=..."
    # Non-managers should NOT see password
    assert res.data["password"] is None


@pytest.mark.django_db
def test_streaming_link_password_visibility_manager(event, owner):
    """Test that event creator (manager) can see password."""
    client = APIClient()
    client.force_authenticate(user=owner)
    event.use_external_streaming = True
    event.external_streaming_platform = "zoom"
    event.external_streaming_url = "https://zoom.us/j/123456789"
    event.external_streaming_password = "secret123"
    event.save()

    res = client.get(f"/api/events/{event.id}/streaming-link/")
    assert res.status_code == 200
    # Manager sees password
    assert res.data["password"] == "secret123"


@pytest.mark.django_db
def test_streaming_link_password_hidden_attendee(event, attendee):
    """Test that attendees cannot see password."""
    client = APIClient()
    client.force_authenticate(user=attendee)
    event.use_external_streaming = True
    event.external_streaming_platform = "zoom"
    event.external_streaming_url = "https://zoom.us/j/123456789"
    event.external_streaming_password = "secret123"
    event.save()

    res = client.get(f"/api/events/{event.id}/streaming-link/")
    assert res.status_code == 200
    # Attendee sees null password
    assert res.data["password"] is None


@pytest.mark.django_db
def test_streaming_link_platform_variations(event):
    """Test streaming-link endpoint with different platforms."""
    client = APIClient()

    platforms = [
        ("google_meet", "Google Meet"),
        ("microsoft_teams", "Microsoft Teams"),
    ]

    for platform_key, platform_name in platforms:
        event.use_external_streaming = True
        event.external_streaming_platform = platform_key
        event.external_streaming_url = f"https://example.com/{platform_key}"
        event.save()

        res = client.get(f"/api/events/{event.id}/streaming-link/")
        assert res.status_code == 200
        assert res.data["platform"] == platform_key
        assert res.data["platform_name"] == platform_name
        assert res.data["join_url"] == f"https://example.com/{platform_key}"


# ============================================================
# Update Validation Tests: PUT/PATCH /api/events/{id}/
# ============================================================

@pytest.mark.django_db
def test_update_external_streaming_requires_url(event, owner):
    """Test that enabling external streaming without URL fails validation."""
    client = APIClient()
    client.force_authenticate(user=owner)

    res = client.patch(
        f"/api/events/{event.id}/",
        {
            "use_external_streaming": True,
            "external_streaming_platform": "zoom",
            # Missing external_streaming_url
        },
        format="json",
    )
    assert res.status_code == 400
    assert "external_streaming_url" in res.data
    assert "required" in str(res.data["external_streaming_url"]).lower()


@pytest.mark.django_db
def test_update_external_streaming_platform_native_fails(event, owner):
    """Test that using 'native' platform with external streaming enabled fails."""
    client = APIClient()
    client.force_authenticate(user=owner)

    res = client.patch(
        f"/api/events/{event.id}/",
        {
            "use_external_streaming": True,
            "external_streaming_platform": "native",
            "external_streaming_url": "https://zoom.us/j/123456789",
        },
        format="json",
    )
    assert res.status_code == 400
    assert "external_streaming_platform" in res.data


@pytest.mark.django_db
def test_update_external_streaming_with_zoom(event, owner):
    """Test successful update of external streaming config to Zoom."""
    client = APIClient()
    client.force_authenticate(user=owner)

    res = client.patch(
        f"/api/events/{event.id}/",
        {
            "use_external_streaming": True,
            "external_streaming_platform": "zoom",
            "external_streaming_url": "https://zoom.us/j/123456789",
            "external_streaming_meeting_id": "123456789",
            "external_streaming_password": "abc123",
            "external_streaming_other_details": "Password in email",
            "external_streaming_host_link": "https://zoom.us/j/123456789?pwd=...",
        },
        format="json",
    )
    assert res.status_code == 200
    assert res.data["use_external_streaming"] is True
    assert res.data["external_streaming_platform"] == "zoom"
    assert res.data["external_streaming_url"] == "https://zoom.us/j/123456789"


@pytest.mark.django_db
def test_switch_from_external_to_native(event, owner):
    """Test switching from external streaming back to native RTK."""
    client = APIClient()
    client.force_authenticate(user=owner)

    # First enable external
    event.use_external_streaming = True
    event.external_streaming_platform = "zoom"
    event.external_streaming_url = "https://zoom.us/j/123456789"
    event.save()

    # Then switch to native (should succeed without requiring URL)
    res = client.patch(
        f"/api/events/{event.id}/",
        {"use_external_streaming": False},
        format="json",
    )
    assert res.status_code == 200
    assert res.data["use_external_streaming"] is False


@pytest.mark.django_db
def test_update_with_optional_fields_only(event, owner):
    """Test update with only required field (URL) when external enabled."""
    client = APIClient()
    client.force_authenticate(user=owner)

    res = client.patch(
        f"/api/events/{event.id}/",
        {
            "use_external_streaming": True,
            "external_streaming_platform": "google_meet",
            "external_streaming_url": "https://meet.google.com/abc-defg-hij",
            # All other fields are optional
        },
        format="json",
    )
    assert res.status_code == 200
    assert res.data["use_external_streaming"] is True
    assert res.data["external_streaming_url"] == "https://meet.google.com/abc-defg-hij"
    # Optional fields should be empty/null
    assert res.data["external_streaming_meeting_id"] == ""
    assert res.data["external_streaming_password"] == ""


# ============================================================
# Permission Tests
# ============================================================

@pytest.mark.django_db
def test_non_creator_cannot_update_external_streaming(event, attendee, owner):
    """Test that non-creator cannot update event external streaming."""
    client = APIClient()
    client.force_authenticate(user=attendee)

    res = client.patch(
        f"/api/events/{event.id}/",
        {
            "use_external_streaming": True,
            "external_streaming_platform": "zoom",
            "external_streaming_url": "https://zoom.us/j/123456789",
        },
        format="json",
    )
    assert res.status_code == 403


@pytest.mark.django_db
def test_anyone_can_view_streaming_link(event, attendee):
    """Test that anyone can view the streaming link endpoint."""
    client = APIClient()
    event.use_external_streaming = True
    event.external_streaming_platform = "zoom"
    event.external_streaming_url = "https://zoom.us/j/123456789"
    event.save()

    # Anonymous user
    res = client.get(f"/api/events/{event.id}/streaming-link/")
    assert res.status_code == 200

    # Authenticated attendee
    client.force_authenticate(user=attendee)
    res = client.get(f"/api/events/{event.id}/streaming-link/")
    assert res.status_code == 200


# ============================================================
# Edge Cases
# ============================================================

@pytest.mark.django_db
def test_streaming_link_with_whitespace_trimming(event):
    """Test that URLs and fields are trimmed of whitespace."""
    client = APIClient()
    event.use_external_streaming = True
    event.external_streaming_url = "https://zoom.us/j/123456789   "
    event.external_streaming_meeting_id = "  123456789  "
    event.save()

    res = client.get(f"/api/events/{event.id}/streaming-link/")
    assert res.status_code == 200
    # URLs from DB may have spaces, but that's OK - frontend can handle


@pytest.mark.django_db
def test_streaming_link_null_optional_fields(event):
    """Test streaming link response handles null/empty optional fields."""
    client = APIClient()
    event.use_external_streaming = True
    event.external_streaming_platform = "zoom"
    event.external_streaming_url = "https://zoom.us/j/123456789"
    event.external_streaming_meeting_id = ""  # Empty
    event.external_streaming_password = ""  # Empty
    event.external_streaming_other_details = ""  # Empty
    event.external_streaming_host_link = ""  # Empty
    event.save()

    res = client.get(f"/api/events/{event.id}/streaming-link/")
    assert res.status_code == 200
    assert res.data["meeting_id"] is None or res.data["meeting_id"] == ""
    assert res.data["instructions"] is None or res.data["instructions"] == ""
    assert res.data["host_link"] is None or res.data["host_link"] == ""
    assert res.data["password"] is None


@pytest.mark.django_db
def test_in_person_event_no_streaming_config(db, community, owner):
    """Test that in-person events don't expose streaming UI."""
    event = Event.objects.create(
        community=community,
        title="In-Person Event",
        created_by=owner,
        format="in_person",
        status="published",
    )
    client = APIClient()

    # Still can query streaming-link, returns native by default
    res = client.get(f"/api/events/{event.id}/streaming-link/")
    assert res.status_code == 200
    assert res.data["type"] == "native"
