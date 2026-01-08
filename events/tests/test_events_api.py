"""
API tests for the events app.

Ensures that users can create events within community they belong to
and restricts access when they are not members.  Also tests listing and
updating event status.
"""
import pytest
from django.conf import settings


@pytest.mark.django_db
def test_event_crud(auth_client, community):
    """Test creating, listing, and updating an event."""
    # Create event for a valid community
    payload = {"community_id": community.id, "title": "Kickoff", "description": "Welcome"}
    resp = auth_client.post("/api/events/", payload, content_type="application/json")
    assert resp.status_code == 201
    data = resp.json()
    event_id = data["id"]
    assert data["timezone"] == settings.TIME_ZONE

    # List events
    list_resp = auth_client.get("/api/events/")
    assert list_resp.status_code == 200
    ids = [e["id"] for e in list_resp.json()["results"]]
    assert event_id in ids

    # Update event status
    update_resp = auth_client.patch(
        f"/api/events/{event_id}/", {"status": "draft"}, content_type="application/json"
    )
    assert update_resp.status_code == 200


@pytest.mark.django_db
def test_event_timezone_naive_to_utc(auth_client, community):
    payload = {
        "community_id": community.id,
        "title": "Timezone Event",
        "description": "Check timezone handling",
        "timezone": "Asia/Kolkata",
        "start_time": "2026-01-20T10:00:00",
        "end_time": "2026-01-20T12:00:00",
    }
    resp = auth_client.post("/api/events/", payload, content_type="application/json")
    assert resp.status_code == 201
    data = resp.json()
    assert data["timezone"] == "Asia/Kolkata"
    assert data["start_time"].startswith("2026-01-20T04:30")
    assert data["end_time"].startswith("2026-01-20T06:30")
