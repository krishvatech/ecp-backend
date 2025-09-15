"""
API tests for the events app.

Ensures that users can create events within organizations they belong to
and restricts access when they are not members.  Also tests listing and
updating event status.
"""
import pytest


@pytest.mark.django_db
def test_event_crud(auth_client, organization):
    """Test creating, listing, and updating an event."""
    # Create event for a valid organization
    payload = {"organization_id": organization.id, "title": "Kickoff", "description": "Welcome"}
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


@pytest.mark.django_db
def test_event_start_and_stop(auth_client, organization):
    """Ensure event start/stop endpoints change state and enforce permissions."""
    # Create event
    payload = {"organization_id": organization.id, "title": "Kickoff", "description": "Welcome"}
    r = auth_client.post("/api/events/", payload, content_type="application/json")
    event_id = r.json()["id"]

    # Start the event as the creator
    r_start = auth_client.post(f"/api/events/{event_id}/start/")
    assert r_start.status_code == 200
    data = r_start.json()
    assert data["status"] == "live"
    assert data["is_live"] is True
    assert data.get("live_started_at") is not None

    # Stop the event
    r_stop = auth_client.post(f"/api/events/{event_id}/stop/")
    assert r_stop.status_code == 200
    data2 = r_stop.json()
    assert data2["status"] == "ended"
    assert data2["is_live"] is False
    assert data2.get("live_ended_at") is not None


@pytest.mark.django_db
def test_event_start_permission_denied(auth_client, user, organization):
    """Users who are not event creator or organization owner cannot start events."""
    # Create event by user (owner) and add another member
    payload = {"organization_id": organization.id, "title": "Townhall", "description": "Monthly"}
    resp = auth_client.post("/api/events/", payload, content_type="application/json")
    event_id = resp.json()["id"]
    # Create another user and add as member but not owner
    from django.contrib.auth.models import User
    other = User.objects.create_user(username="bob", password="pass12345", email="bob@example.com")
    organization.members.add(other)
    # Authenticate as other user
    resp_login = auth_client.post(
        "/api/auth/token/", {"username": "bob", "password": "pass12345"}, content_type="application/json"
    )
    token = resp_login.json()["access"]
    auth_client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    # Attempt to start event
    start_resp = auth_client.post(f"/api/events/{event_id}/start/")
    assert start_resp.status_code == 403
