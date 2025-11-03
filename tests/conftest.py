"""
Common test fixtures for Django REST Framework API tests.

Provides fixtures for creating a user and authenticating a client
with a JWT token.  Also provides an community fixture used in
community and events tests.
"""
import pytest
from django.contrib.auth.models import User
from community.models import Community


@pytest.fixture
def user(db):
    """Create a test user."""
    return User.objects.create_user(username="u1", password="pass12345", email="u1@example.com")


@pytest.fixture
def auth_client(client, db, user):
    """Authenticate the Django test client using JWT tokens."""
    resp = client.post(
        "/api/auth/token/",
        {"username": "u1", "password": "pass12345"},
        content_type="application/json",
    )
    assert resp.status_code == 200
    token = resp.json()["access"]
    client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return client


@pytest.fixture
def community(db, user):
    """Create an community with the given user as owner and member."""
    org = Community.objects.create(name="Org A", owner=user, description="Test org")
    org.members.add(user)
    return org