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

from django.http import HttpResponseForbidden, JsonResponse

PLATFORM_ADMIN_GROUP = "platform_admin"

# Profile statuses that should block operations
BLOCKED_PROFILE_STATUSES = ("suspended", "fake", "deceased")


class SuspendedUserMiddleware:
    """
    Block suspended/fake users from making ANY requests (Read or Write).

    This middleware runs after AuthenticationMiddleware so request.user is available.
    """

    # Endpoints that should always work even for suspended users
    ALLOWED_PATHS = (
        "/api/users/logout/",
        "/api/session/logout/",
        "/api/auth/logout/",
        "/admin/",  # Django admin (has its own auth)
        "/cms/",    # Wagtail CMS
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Allow specific paths that should always work
        if any(request.path.startswith(p) for p in self.ALLOWED_PATHS):
            return self.get_response(request)

        # Check user's profile status
        user = getattr(request, "user", None)
        # Import logger if not available (or assume it's available in the file context, adding import to fail safe)
        import logging
        logger = logging.getLogger(__name__)

        if user and user.is_authenticated:
            profile = getattr(user, "profile", None)
            status = profile.profile_status if profile else "NO_PROFILE"
            # logger.info(f"SuspendedUserMiddleware: Checking user {user.username} (ID: {user.id}). Status: {status}")
            
            if profile and profile.profile_status in BLOCKED_PROFILE_STATUSES:
                logger.warning(f"SuspendedUserMiddleware: Blocking user {user.username} due to status {status}")
                return JsonResponse(
                    {
                        "detail": "Your account has been suspended. You cannot perform this action.",
                        "code": "account_suspended",
                        "profile_status": profile.profile_status,
                    },
                    status=403
                )
        else:
            # logger.debug("SuspendedUserMiddleware: User is Anonymous or not authenticated")
            pass

        return self.get_response(request)


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
