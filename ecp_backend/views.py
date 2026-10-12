import html
import re
from urllib.parse import urlsplit

from django.conf import settings
from django.shortcuts import redirect
from django.http import JsonResponse, Http404
from django.template.response import TemplateResponse
from django.utils.html import strip_tags
from django.views.decorators.http import require_safe

from events.models import Event
from groups.models import Group
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


GROUP_PREVIEW_DESCRIPTION_LIMIT = 200
GROUP_PREVIEW_FALLBACK_DESCRIPTION = "Join this group."
# Query parameters that indicate a signed/expiring storage URL. Such URLs must
# never be published in social previews.
SIGNED_URL_MARKERS = ("x-amz-signature", "x-amz-credential", "signature=", "x-goog-signature")


def _plain_preview_text(value):
    """Strip HTML tags/entities and collapse whitespace; the template escapes output."""
    text = html.unescape(strip_tags(value or ""))
    return re.sub(r"\s+", " ", text).strip()


def _public_image_url(request, image_field):
    if not image_field:
        return ""
    try:
        url = request.build_absolute_uri(image_field.url)
    except Exception:
        return ""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    if any(marker in parts.query.lower() for marker in SIGNED_URL_MARKERS):
        return ""
    return url


@require_safe
def public_group_meta(request, slug):
    """
    Return server-rendered Open Graph and Twitter metadata for the public group
    landing page (frontend route /groups/public/<slug>).

    Uses the same exposure rules as groups.views.PublicGroupLandingView: only
    public, landing-enabled, non-deleted groups (default manager) are served.
    """
    group = Group.objects.filter(
        slug=slug,
        visibility=Group.VISIBILITY_PUBLIC,
        public_landing_enabled=True,
    ).first()
    if not group:
        raise Http404("Public group not found")

    title = _plain_preview_text(group.name) or "Group"
    description = (
        _plain_preview_text(group.short_description)
        or _plain_preview_text(group.description)
        or GROUP_PREVIEW_FALLBACK_DESCRIPTION
    )
    if len(description) > GROUP_PREVIEW_DESCRIPTION_LIMIT:
        description = f"{description[:GROUP_PREVIEW_DESCRIPTION_LIMIT - 3].rstrip()}..."

    image_url = _public_image_url(request, group.cover_image) or _public_image_url(
        request, group.logo
    )

    frontend_base = (settings.FRONTEND_URL or "").rstrip("/")
    group_url = (
        f"{frontend_base}/groups/public/{group.slug}"
        if frontend_base
        else request.build_absolute_uri(request.path)
    )

    context = {
        "title": title,
        "description": description,
        "image_url": image_url,
        "group_url": group_url,
    }
    return TemplateResponse(request, "public_group_meta.html", context)

