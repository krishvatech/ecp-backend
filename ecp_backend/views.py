import mimetypes
import re
from html import unescape
from urllib.parse import urlparse

from django.conf import settings
from django.http import Http404, JsonResponse
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.utils.html import strip_tags

from events.models import Event
from ecp_backend.health_checks import get_health_status
from events.services.live_instance_state import heartbeat_instance


PUBLIC_EVENT_STATUSES = ("published", "live", "ended", "cancelled")
PUBLIC_EVENT_ROUTE_PREFIXES = {"events", "public", "landing"}

def health(request):
    """Simple health check for ALB. Must only return {"status": "ok"} without deep checks."""
    try:
        heartbeat_instance()
    except Exception:
        pass
    return JsonResponse({"status": "ok"})


def live_health(request):
    """Deep monitoring health check. Returns detailed status of all dependencies."""
    result = get_health_status()
    status_code = 200 if result["status"] == "ok" else 503
    return JsonResponse(result, status=status_code)


def index(request):
    # Logged in? send to your app home (dashboard)
    if request.user.is_authenticated:
        return redirect(settings.AUTH_HOME_URL)
    # Not logged in? send to your SPA landing (no frontend changes needed)
    return redirect(settings.FRONTEND_URL)


def _plain_text_description(value, *, max_length=200):
    """Convert rich event descriptions into a compact social-preview summary."""
    description = re.sub(r"\s+", " ", unescape(strip_tags(value or ""))).strip()
    if not description:
        return "Join this event."
    if len(description) <= max_length:
        return description
    return f"{description[: max_length - 3].rstrip()}..."


def _frontend_event_url(slug, route_prefix):
    """Build the public frontend URL corresponding to the requested route."""
    frontend_base = (getattr(settings, "FRONTEND_URL", "") or "").rstrip("/")
    route_prefix = (
        route_prefix if route_prefix in PUBLIC_EVENT_ROUTE_PREFIXES else "events"
    )
    return f"{frontend_base}/{route_prefix}/{slug}/" if frontend_base else ""


def _event_image_url(request, event):
    """Return an absolute image URL suitable for Open Graph crawlers."""
    # preview_image is the dedicated sharing/card image; cover_image is fallback.
    for field_name in ("preview_image", "cover_image"):
        image_field = getattr(event, field_name, None)
        if not image_field:
            continue
        try:
            return request.build_absolute_uri(image_field.url)
        except (AttributeError, ValueError):
            continue
    return ""


def public_event_meta(request, slug, route_prefix="events"):
    """
    Render server-side Open Graph/Twitter metadata for one public event.

    The frontend remains a React SPA for normal visitors. CloudFront sends only
    social-link crawlers to this endpoint, because those crawlers generally do
    not wait for React to fetch event data and update the document head.
    """
    event = (
        Event.objects.filter(
            slug=slug,
            status__in=PUBLIC_EVENT_STATUSES,
            is_hidden=False,
        )
        .select_related("community")
        .first()
    )
    if not event:
        raise Http404("Event not found")

    title = (event.title or "").strip() or "Event"
    description = _plain_text_description(event.description)
    event_url = _frontend_event_url(slug, route_prefix) or request.build_absolute_uri(
        request.path
    )
    image_url = _event_image_url(request, event)
    image_type = ""
    if image_url:
        image_type = mimetypes.guess_type(urlparse(image_url).path)[0] or "image/jpeg"

    response = TemplateResponse(
        request,
        "public_event_meta.html",
        {
            "title": title,
            "description": description,
            "image_url": image_url,
            "image_type": image_type,
            "event_url": event_url,
            "site_name": "IMAA Events & Community",
        },
    )
    # Keep event edits reasonably fresh while reducing repeated crawler traffic.
    response["Cache-Control"] = "public, max-age=300, s-maxage=900"
    return response
