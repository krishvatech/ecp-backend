from datetime import timedelta

import pytest
from django.contrib.auth.models import User
from django.core.cache import cache
from django.utils import timezone

from events.models import Event


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
    import events.views as event_views

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
