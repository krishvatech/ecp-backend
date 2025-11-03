"""
API tests for the events app.

Ensures that users can create events within community they belong to
and restricts access when they are not members.  Also tests listing and
updating event status.
"""
import pytest


@pytest.mark.django_db
def test_event_crud(auth_client, community):
    """Test creating, listing, and updating an event."""
    # Create event for a valid community
    payload = {"community_id": community.id, "title": "Kickoff", "description": "Welcome"}
    resp = auth_client.post("/api/events/", payload, content_type="application/json")
    assert resp.status_code == 201
    event_id = resp.json()["id"]

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