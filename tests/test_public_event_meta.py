from types import SimpleNamespace

import pytest
from django.http import Http404
from django.test import RequestFactory, override_settings

import ecp_backend.views as meta_views


class _FakeQuerySet:
    def __init__(self, event):
        self.event = event

    def select_related(self, *_args):
        return self

    def first(self):
        return self.event


class _Image:
    def __init__(self, url):
        self.url = url

    def __bool__(self):
        return True


def _event(**overrides):
    values = {
        "title": "Example Event",
        "slug": "example-event",
        "description": "<p>Useful <strong>event</strong> description.</p>",
        "preview_image": _Image("https://media.example.com/preview.jpg"),
        "cover_image": _Image("https://media.example.com/cover.jpg"),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _install_event(monkeypatch, event, captured_filters=None):
    def fake_filter(**kwargs):
        if captured_filters is not None:
            captured_filters.update(kwargs)
        return _FakeQuerySet(event)

    monkeypatch.setattr(meta_views.Event.objects, "filter", fake_filter)


@pytest.mark.parametrize("route_prefix", ["events", "public", "landing"])
@override_settings(FRONTEND_URL="https://www.connect.imaa-institute.org/")
def test_event_metadata_uses_matching_frontend_route(monkeypatch, route_prefix):
    event = _event()
    captured_filters = {}
    _install_event(monkeypatch, event, captured_filters)
    request = RequestFactory().get(f"/{route_prefix}/{event.slug}/")

    response = meta_views.public_event_meta(
        request,
        event.slug,
        route_prefix=route_prefix,
    )
    response.render()

    html = response.content.decode("utf-8")
    expected_url = (
        f"https://www.connect.imaa-institute.org/{route_prefix}/{event.slug}/"
    )

    assert response.status_code == 200
    assert captured_filters == {
        "slug": event.slug,
        "status__in": meta_views.PUBLIC_EVENT_STATUSES,
        "is_hidden": False,
    }
    assert '<meta property="og:title" content="Example Event"' in html
    assert 'content="Useful event description."' in html
    assert f'<link rel="canonical" href="{expected_url}"' in html
    assert f'<meta property="og:url" content="{expected_url}"' in html
    assert (
        '<meta property="og:image" '
        'content="https://media.example.com/preview.jpg"' in html
    )
    assert "og:image:width" not in html
    assert "og:image:height" not in html
    assert 'window.location.replace' in html
    assert response["Cache-Control"] == "public, max-age=300, s-maxage=900"


@override_settings(FRONTEND_URL="https://www.connect.imaa-institute.org/")
def test_cover_image_is_used_when_preview_image_is_missing(monkeypatch):
    event = _event(preview_image=None)
    _install_event(monkeypatch, event)
    request = RequestFactory().get(f"/events/{event.slug}/")

    response = meta_views.public_event_meta(request, event.slug, route_prefix="events")
    response.render()

    assert (
        '<meta property="og:image" '
        'content="https://media.example.com/cover.jpg"'
        in response.content.decode("utf-8")
    )


def test_non_public_event_is_not_exposed(monkeypatch):
    _install_event(monkeypatch, None)
    request = RequestFactory().get("/events/not-public/")

    with pytest.raises(Http404):
        meta_views.public_event_meta(request, "not-public", route_prefix="events")


def test_plain_text_description_removes_markup_and_limits_length():
    value = "<p>Hello&nbsp;world</p>" + (" x" * 150)

    result = meta_views._plain_text_description(value, max_length=40)

    assert "<" not in result
    assert "&nbsp;" not in result
    assert len(result) <= 40
    assert result.endswith("...")
