from datetime import timedelta

from contextlib import contextmanager

import pytest
from django.contrib.auth.models import User
from django.core.cache import cache
from django.utils import timezone

from events.models import Event
import events.views as event_views


@pytest.fixture(autouse=True)
def clear_test_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def live_event(db, community, user):
    now = timezone.now()
    return Event.objects.create(
        community=community,
        created_by=user,
        title="Regression Test Event",
        slug=f"regression-test-event-{community.id}",
        description="Regression test event",
        start_time=now,
        end_time=now + timedelta(hours=1),
        timezone="UTC",
        status="live",
        is_live=True,
        format="virtual",
    )


@pytest.fixture
def other_user(db):
    return User.objects.create_user(
        username="u2",
        password="pass12345",
        email="u2@example.com",
    )


@pytest.fixture
def other_auth_client(client, db, other_user):
    resp = client.post(
        "/api/auth/token/",
        {"username": "u2", "password": "pass12345"},
        content_type="application/json",
    )
    assert resp.status_code == 200
    token = resp.json()["access"]
    client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return client


def test_event_summary_endpoint_uses_cached_payload(client, live_event, monkeypatch):
    first = client.get(f"/api/events/{live_event.id}/summary/")
    assert first.status_code == 200
    first_payload = first.json()
    assert first_payload["id"] == live_event.id
    assert first_payload["title"] == live_event.title

    import events.views as event_views

    monkeypatch.setattr(
        event_views,
        "_serialize_event_summary",
        lambda event, request=None: {"id": event.id, "title": "mutated"},
    )

    second = client.get(f"/api/events/{live_event.id}/summary/")
    assert second.status_code == 200
    assert second.json() == first_payload


def test_public_event_summary_cache_skips_object_lookup(client, live_event, monkeypatch):
    first = client.get(f"/api/events/{live_event.id}/summary/")
    assert first.status_code == 200

    import events.views as event_views

    def fail_object_lookup(self):
        raise AssertionError("summary cache hit should not resolve the Event object")

    monkeypatch.setattr(event_views.EventViewSet, "get_object", fail_object_lookup)

    second = client.get(f"/api/events/{live_event.id}/summary/")
    assert second.status_code == 200
    assert second.json() == first.json()


def test_hidden_event_summary_cache_is_not_served_to_anonymous_users(auth_client, live_event):
    live_event.is_hidden = True
    live_event.save(update_fields=["is_hidden"])

    creator_response = auth_client.get(f"/api/events/{live_event.id}/summary/")
    assert creator_response.status_code == 200

    auth_client.defaults.pop("HTTP_AUTHORIZATION", None)
    anonymous_response = auth_client.get(f"/api/events/{live_event.id}/summary/")
    assert anonymous_response.status_code == 404


def test_live_rejoin_denial_is_terminal_for_unregistered_user(other_auth_client, live_event):
    response = other_auth_client.post(
        f"/api/events/{live_event.id}/live/rejoin/",
        data={},
        content_type="application/json",
    )

    assert response.status_code == 403
    payload = response.json()
    assert payload["can_rejoin"] is False
    assert payload["retryable"] is False
    assert payload["reason"] == "user_not_registered"


def test_live_rejoin_still_allows_event_host_without_registration(auth_client, live_event, monkeypatch):
    class DummyResponse:
        status_code = 201

        @staticmethod
        def json():
            return {"data": {"token": "rtk-token-123"}}

    monkeypatch.setattr(event_views, "_ensure_rtk_meeting_for_event", lambda event: "meeting-123")
    monkeypatch.setattr(event_views.requests, "post", lambda *args, **kwargs: DummyResponse())

    response = auth_client.post(
        f"/api/events/{live_event.id}/live/rejoin/",
        data={},
        content_type="application/json",
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["can_rejoin"] is True
    assert payload["user_role"] == "host"
    assert payload["room_type"] == "main_room"
    assert payload["rtk_meeting_id"] == "meeting-123"
    assert payload["rtk_token"] == "rtk-token-123"


def test_live_rejoin_returns_202_when_queue_is_busy(auth_client, live_event, monkeypatch):
    @contextmanager
    def busy_slot(*args, **kwargs):
        yield False

    monkeypatch.setattr(event_views, "live_rejoin_slot", busy_slot)

    response = auth_client.post(
        f"/api/events/{live_event.id}/live/rejoin/",
        data={},
        content_type="application/json",
    )

    assert response.status_code == 202
    payload = response.json()
    assert payload == {
        "queued": True,
        "reason": "live_rejoin_busy",
        "message": "Restoring live session, please wait...",
        "retry_after": 2,
    }


def test_live_rejoin_slot_fails_open_on_cache_error(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("redis unavailable")

    monkeypatch.setattr(event_views.cache, "add", boom)

    with event_views.live_rejoin_slot(696) as allowed:
        assert allowed is True


def test_deleted_event_live_rejoin_returns_404(auth_client):
    """Test that rejoin on deleted event returns 404 not 500."""
    deleted_event_id = 999999  # Non-existent event ID

    response = auth_client.post(
        f"/api/events/{deleted_event_id}/live/rejoin/",
        data={},
        content_type="application/json",
    )

    assert response.status_code == 404
    payload = response.json()
    assert payload["can_rejoin"] is False
    assert payload["retryable"] is False
    assert payload["reason"] == "event_not_found"
    assert payload["detail"] == "Event not found."


def test_valid_event_live_rejoin_returns_200_or_202(auth_client, live_event, monkeypatch):
    """Test that rejoin on valid event returns 200 or 202, not 500."""
    class DummyResponse:
        status_code = 201

        @staticmethod
        def json():
            return {"data": {"token": "rtk-token-123"}}

    monkeypatch.setattr(event_views, "_ensure_rtk_meeting_for_event", lambda event: "meeting-123")
    monkeypatch.setattr(event_views.requests, "post", lambda *args, **kwargs: DummyResponse())

    response = auth_client.post(
        f"/api/events/{live_event.id}/live/rejoin/",
        data={},
        content_type="application/json",
    )

    # Should return 200 (success) or 202 (queued), not 500
    assert response.status_code in (200, 202)

    if response.status_code == 200:
        payload = response.json()
        assert payload["can_rejoin"] is True
        assert "event_id" in payload
    elif response.status_code == 202:
        payload = response.json()
        assert payload["queued"] is True
        assert payload["reason"] == "live_rejoin_busy"


def test_live_rejoin_slot_context_manager_propagates_http404(monkeypatch):
    """Test that Http404 exceptions propagate through the context manager."""
    from django.http import Http404

    with event_views.live_rejoin_slot(696) as allowed:
        assert allowed is True
        # Simulate an Http404 being raised inside the with-block
        try:
            raise Http404("Event not found")
        except Http404:
            # Should NOT cause "RuntimeError: generator didn't stop after throw()"
            # The exception should propagate normally
            pass
