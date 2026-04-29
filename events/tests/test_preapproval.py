import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient

from community.models import Community
from events.models import Event, EventApplication, EventPreApprovalAllowlist, EventPreApprovalCode


@pytest.fixture
def owner(db):
    return User.objects.create_user(username="owner", email="owner@example.com", password="pass123")


@pytest.fixture
def user(db):
    return User.objects.create_user(username="user1", email="user1@example.com", password="pass123")


@pytest.fixture
def event_apply(db, owner):
    community = Community.objects.create(name="PreApproval Community", created_by=owner)
    return Event.objects.create(
        community=community,
        title="Selective Event",
        created_by=owner,
        registration_type="apply",
    )


@pytest.mark.django_db
def test_event_preapproval_defaults_false(event_apply):
    assert event_apply.preapproval_code_enabled is False
    assert event_apply.preapproval_allowlist_enabled is False
    assert event_apply.attendee_marker_enabled is False
    assert event_apply.attendee_marker_label == ""


@pytest.mark.django_db
def test_check_code_valid_used_revoked(event_apply):
    client = APIClient()
    event_apply.preapproval_code_enabled = True
    event_apply.save(update_fields=["preapproval_code_enabled"])

    code = EventPreApprovalCode.objects.create(event=event_apply, code="OX-001")
    res = client.post(f"/api/events/{event_apply.id}/preapproval/check-code/", {"code": "OX-001"}, format="json")
    assert res.status_code == 200
    assert res.data["preapproved"] is True

    code.status = EventPreApprovalCode.STATUS_USED
    code.save(update_fields=["status"])
    res = client.post(f"/api/events/{event_apply.id}/preapproval/check-code/", {"code": "OX-001"}, format="json")
    assert res.data["preapproved"] is False
    assert res.data["reason"] == "used"

    code.status = EventPreApprovalCode.STATUS_REVOKED
    code.save(update_fields=["status"])
    res = client.post(f"/api/events/{event_apply.id}/preapproval/check-code/", {"code": "OX-001"}, format="json")
    assert res.data["preapproved"] is False
    assert res.data["reason"] == "revoked"


@pytest.mark.django_db
def test_check_email_case_insensitive(event_apply):
    client = APIClient()
    event_apply.preapproval_allowlist_enabled = True
    event_apply.save(update_fields=["preapproval_allowlist_enabled"])
    EventPreApprovalAllowlist.objects.create(
        event=event_apply, first_name="Alice", last_name="Brown", email="alice@example.com"
    )
    res = client.post(
        f"/api/events/{event_apply.id}/preapproval/check-email/",
        {"email": "ALICE@EXAMPLE.COM"},
        format="json",
    )
    assert res.status_code == 200
    assert res.data["preapproved"] is True
    assert res.data["source"] == "email"
    assert res.data["first_name"] == "Alice"


@pytest.mark.django_db
def test_apply_with_code_auto_approves_and_consumes(monkeypatch, event_apply, user):
    client = APIClient()
    client.force_authenticate(user=user)

    event_apply.preapproval_code_enabled = True
    event_apply.save(update_fields=["preapproval_code_enabled"])
    EventPreApprovalCode.objects.create(event=event_apply, code="OXFORD-SPONSOR-001")

    called = {"ack": 0}

    def fake_ack(_app):
        called["ack"] += 1

    monkeypatch.setattr("users.email_utils.send_application_acknowledgement_email", fake_ack)

    payload = {
        "first_name": "Alice",
        "last_name": "Brown",
        "email": "alice@example.com",
        "job_title": "Partner",
        "company_name": "Example Capital",
        "linkedin_url": "",
        "attendee_marker_value": True,
        "comments": "Invited by sponsor.",
        "preapproved_code": "OXFORD-SPONSOR-001",
    }
    res = client.post(f"/api/events/{event_apply.id}/apply/", payload, format="json")
    assert res.status_code == 201

    app = EventApplication.objects.get(event=event_apply, email="alice@example.com")
    assert app.status == "approved"
    assert app.is_preapproved is True
    assert app.preapproval_source == "code"
    assert app.attendee_marker_value is True
    assert app.comments == "Invited by sponsor."
    assert app.preapproved_at is not None

    code = EventPreApprovalCode.objects.get(event=event_apply, code="OXFORD-SPONSOR-001")
    assert code.status == EventPreApprovalCode.STATUS_USED
    assert code.used_by_application_id == app.id
    assert code.used_by_email == "alice@example.com"
    assert code.used_at is not None
    assert called["ack"] == 0


@pytest.mark.django_db
def test_apply_with_allowlist_auto_approves(event_apply):
    client = APIClient()
    event_apply.preapproval_allowlist_enabled = True
    event_apply.save(update_fields=["preapproval_allowlist_enabled"])
    EventPreApprovalAllowlist.objects.create(
        event=event_apply, first_name="Alice", last_name="Brown", email="alice@example.com"
    )
    payload = {
        "first_name": "Alice",
        "last_name": "Brown",
        "email": "alice@example.com",
        "job_title": "Partner",
        "company_name": "Example Capital",
        "linkedin_url": "",
        "attendee_marker_value": False,
        "comments": "Allowlisted",
    }
    res = client.post(f"/api/events/{event_apply.id}/apply/", payload, format="json")
    assert res.status_code == 201
    app = EventApplication.objects.get(event=event_apply, email="alice@example.com")
    assert app.status == "approved"
    assert app.preapproval_source == "email"


@pytest.mark.django_db
def test_apply_without_preapproval_stays_pending(monkeypatch, event_apply):
    client = APIClient()
    called = {"ack": 0}

    def fake_ack(_app):
        called["ack"] += 1

    monkeypatch.setattr("users.email_utils.send_application_acknowledgement_email", fake_ack)

    payload = {
        "first_name": "Bob",
        "last_name": "Miller",
        "email": "bob@example.com",
        "job_title": "Associate",
        "company_name": "Firm",
        "linkedin_url": "",
        "comments": "",
    }
    res = client.post(f"/api/events/{event_apply.id}/apply/", payload, format="json")
    assert res.status_code == 201
    app = EventApplication.objects.get(event=event_apply, email="bob@example.com")
    assert app.status == "pending"
    assert app.is_preapproved is False
    assert called["ack"] == 1
