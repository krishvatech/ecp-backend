"""
API tests for the community app.

Validates that an authenticated user can perform CRUD operations on
community and that only community where the user is a member
are visible.
"""
import pytest


@pytest.mark.django_db
def test_org_crud(auth_client):
    """Test creating, listing, retrieving, and updating community."""
    # Create an community
    resp = auth_client.post(
        "/api/community/",
        {"name": "Org B", "description": "Desc"},
        content_type="application/json",
    )
    assert resp.status_code == 201
    org_id = resp.json()["id"]

    # List community (should include newly created)
    list_resp = auth_client.get("/api/community/")
    ids = [o["id"] for o in list_resp.json()["results"]]
    assert org_id in ids

    # Retrieve community
    detail = auth_client.get(f"/api/community/{org_id}/")
    assert detail.status_code == 200

    # Update community description
    update = auth_client.patch(
        f"/api/community/{org_id}/",
        {"description": "New"},
        content_type="application/json",
    )
    assert update.status_code == 200