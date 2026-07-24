from django.conf import settings
from django.shortcuts import redirect
from django.http import JsonResponse, Http404
from django.template.response import TemplateResponse
from django.utils.html import strip_tags

from events.models import Event
from ecp_backend.health_checks import get_health_status
from events.services.live_instance_state import heartbeat_instance


SOCIAL_PREVIEW_PAGE_TYPES = {"public", "events", "landing"}
SOCIAL_PREVIEW_STATUSES = ("published", "live", "ended")

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


def public_event_meta(request, slug, page_type="events"):
    """
    Return server-rendered Open Graph and Twitter metadata for public event URLs.

    Supported frontend routes:
    - /public/<slug>/
    - /events/<slug>/
    - /landing/<slug>/
    """
    if page_type not in SOCIAL_PREVIEW_PAGE_TYPES:
        raise Http404("Unsupported event page type")

    event = (
        Event.objects.filter(
            slug=slug,
            status__in=SOCIAL_PREVIEW_STATUSES,
            is_hidden=False,
        )
        .select_related("community")
        .first()
    )
    if not event:
        raise Http404("Event not found")

    title = (event.title or "").strip() or "Event"
    description = strip_tags(event.description or "").strip()
    if len(description) > 200:
        description = f"{description[:197]}..."
    if not description:
        description = "Join this event."

    image_url = ""
    image_field = event.cover_image or event.preview_image
    if image_field:
        try:
            image_url = request.build_absolute_uri(image_field.url)
        except Exception:
            image_url = ""

    frontend_base = (settings.FRONTEND_URL or "").rstrip("/")
    event_url = (
        f"{frontend_base}/{page_type}/{slug}/"
        if frontend_base
        else request.build_absolute_uri(request.path)
    )

    context = {
        "title": title,
        "description": description,
        "image_url": image_url,
        "event_url": event_url,
    }
    return TemplateResponse(request, "public_event_meta.html", context)

