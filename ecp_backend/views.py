from django.conf import settings
from django.shortcuts import redirect
from django.http import JsonResponse, Http404
from django.template.response import TemplateResponse
from django.utils.html import strip_tags

from events.models import Event

def health(request):
    return JsonResponse({"status": "ok"})

def index(request):
    # Logged in? send to your app home (dashboard)
    if request.user.is_authenticated:
        return redirect(settings.AUTH_HOME_URL)
    # Not logged in? send to your SPA landing (no frontend changes needed)
    return redirect(settings.FRONTEND_URL)


def public_event_meta(request, slug):
    """
    Server-rendered public page containing OG/Twitter tags for social crawlers.
    """
    event = (
        Event.objects.filter(slug=slug, status__in=["published", "live"])
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
    image_field = event.preview_image or event.cover_image
    if image_field:
        try:
            image_url = request.build_absolute_uri(image_field.url)
        except Exception:
            image_url = ""

    frontend_base = (settings.FRONTEND_URL or "").rstrip("/")
    event_url = f"{frontend_base}/public/{slug}/" if frontend_base else request.build_absolute_uri(request.path)

    context = {
        "title": title,
        "description": description,
        "image_url": image_url,
        "event_url": event_url,
    }
    return TemplateResponse(request, "public_event_meta.html", context)
