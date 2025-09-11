"""
Tests for authentication and profile management in the users app.

This module covers user registration, login via JWT, and the custom
`/api/users/me/` endpoint for retrieving and updating the authenticated
user's information.
"""
import pytest


@pytest.mark.django_db
def test_register_and_login(client):
    """Ensure a new user can register and obtain a JWT token."""
    # Register a new user
    payload = {
        "username": "alice",
        "email": "a@example.com",
        "password": "pass12345",
        "profile": {"full_name": "Alice A", "timezone": "Asia/Kolkata"},
    }
    response = client.post("/api/auth/register/", payload, content_type="application/json")
    assert response.status_code == 201
    assert response.json()["username"] == "alice"
    assert response.json()["profile"]["full_name"] == "Alice A"

    # Login to obtain tokens
    login_resp = client.post(
        "/api/auth/token/", {"username": "alice", "password": "pass12345"}, content_type="application/json"
    )
    assert login_resp.status_code == 200
    assert "access" in login_resp.json()


@pytest.mark.django_db
def test_me_endpoint(auth_client):
    """Verify that the /api/users/me/ endpoint returns and updates user info."""
    response = auth_client.get("/api/users/me/")
    assert response.status_code == 200
    assert response.json()["username"] == "u1"

    # Update profile bio
    update_resp = auth_client.put(
        "/api/users/me/",
        {"profile": {"bio": "Hello!"}},
        content_type="application/json",
    )
    assert update_resp.status_code == 200
    assert update_resp.json()["profile"]["bio"] == "Hello!"