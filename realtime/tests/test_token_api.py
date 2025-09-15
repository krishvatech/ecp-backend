"""
Tests for the realtime token issuance endpoint.

These tests verify that authenticated members of an organization can
obtain short‑lived streaming tokens for an event, that only the event
creator or organization owner can request a publisher token, and that
non‑members are denied.
"""
import pytest
from django.contrib.auth.models import User


@pytest.mark.django_db
def test_audience_token(auth_client, organization):
    """Members should receive an audience token for events they belong to."""
    # Create event
    payload = {"organization_id": organization.id, "title": "Kickoff", "description": "Live"}
    resp = auth_client.post("/api/events/", payload, content_type="application/json")
    event_id = resp.json()["id"]
    # Request token as audience (default)
    t_resp = auth_client.post(f"/api/events/{event_id}/token/")
    assert t_resp.status_code == 200
    data = t_resp.json()
    assert "token" in data
    assert data["role"] == "audience"
    assert data["channel"]
    assert data["app_id"] == "" or data["app_id"]
    assert data["expires_at"].endswith("Z")


@pytest.mark.django_db
def test_publisher_token_permissions(auth_client, organization):
    """Only event creator or org owner can request a publisher token."""
    # Create event as authenticated user
    payload = {"organization_id": organization.id, "title": "Meetup", "description": "Welcome"}
    resp = auth_client.post("/api/events/", payload, content_type="application/json")
    event_id = resp.json()["id"]
    # Creator requests publisher token
    pub_resp = auth_client.post(f"/api/events/{event_id}/token/", {"role": "publisher"}, content_type="application/json")
    assert pub_resp.status_code == 200
    assert pub_resp.json()["role"] == "publisher"
    # Create another member who is not owner
    other = User.objects.create_user(username="charlie", password="pass12345", email="charlie@example.com")
    organization.members.add(other)
    # Login as charlie
    login_resp = auth_client.post(
        "/api/auth/token/",
        {"username": "charlie", "password": "pass12345"},
        content_type="application/json",
    )
    token = login_resp.json()["access"]
    auth_client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    # Charlie requests publisher token → should be forbidden
    pub_denied = auth_client.post(
        f"/api/events/{event_id}/token/", {"role": "publisher"}, content_type="application/json"
    )
    assert pub_denied.status_code == 403
    # Audience token should still be allowed
    aud_resp = auth_client.post(f"/api/events/{event_id}/token/", {"role": "audience"}, content_type="application/json")
    assert aud_resp.status_code == 200
    assert aud_resp.json()["role"] == "audience"


@pytest.mark.django_db
def test_token_denied_for_non_members(auth_client, organization):
    """Users who are not members of the organization cannot obtain a token."""
    # Create event
    payload = {"organization_id": organization.id, "title": "Session", "description": "Open"}
    resp = auth_client.post("/api/events/", payload, content_type="application/json")
    event_id = resp.json()["id"]
    # Create another user who is not a member
    outsider = User.objects.create_user(username="outsider", password="pass12345", email="out@example.com")
    # Authenticate as outsider
    login_resp = auth_client.post(
        "/api/auth/token/",
        {"username": "outsider", "password": "pass12345"},
        content_type="application/json",
    )
    token = login_resp.json()["access"]
    auth_client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    # Attempt to fetch token
    denied_resp = auth_client.post(f"/api/events/{event_id}/token/")
    assert denied_resp.status_code == 403
