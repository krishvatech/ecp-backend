# users/middleware.py
from django.utils import timezone

class LastActivityMiddleware:
    """
    Update profile.last_activity_at for every authenticated request.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            profile = getattr(user, "profile", None)
            if profile is not None:
                now = timezone.now()
                # Only update if >60s difference to avoid extra writes
                if (
                    not profile.last_activity_at
                    or (now - profile.last_activity_at).total_seconds() > 60
                ):
                    profile.last_activity_at = now
                    profile.save(update_fields=["last_activity_at"])

        return response

from django.http import HttpResponseForbidden

PLATFORM_ADMIN_GROUP = "platform_admin"

class WagtailPlatformAdminOnlyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/cms/"):
            if request.user.is_authenticated:
                in_group = request.user.groups.filter(name=PLATFORM_ADMIN_GROUP).exists()
                if not in_group:
                    return HttpResponseForbidden("Wagtail is restricted to platform_admin only.")
        return self.get_response(request)
