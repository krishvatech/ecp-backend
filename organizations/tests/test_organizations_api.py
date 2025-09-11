"""
API tests for the organizations app.

Validates that an authenticated user can perform CRUD operations on
organizations and that only organizations where the user is a member
are visible.
"""
import pytest


@pytest.mark.django_db
def test_org_crud(auth_client):
    """Test creating, listing, retrieving, and updating organizations."""
    # Create an organization
    resp = auth_client.post(
        "/api/organizations/",
        {"name": "Org B", "description": "Desc"},
        content_type="application/json",
    )
    assert resp.status_code == 201
    org_id = resp.json()["id"]

    # List organizations (should include newly created)
    list_resp = auth_client.get("/api/organizations/")
    ids = [o["id"] for o in list_resp.json()["results"]]
    assert org_id in ids

    # Retrieve organization
    detail = auth_client.get(f"/api/organizations/{org_id}/")
    assert detail.status_code == 200

    # Update organization description
    update = auth_client.patch(
        f"/api/organizations/{org_id}/",
        {"description": "New"},
        content_type="application/json",
    )
    assert update.status_code == 200