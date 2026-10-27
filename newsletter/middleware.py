from . import marketing_cache

MARKETING_ADMIN_PATH_PREFIX = "/api/newsletter/admin/"
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Refused before any view code ran, so nothing in Mautic can have changed.
UNCHANGED_STATUS_CODES = frozenset({401, 403, 405})
# Writes that only touch ECP state (exports read Mautic; notifications are ECP's).
NON_MAUTIC_WRITE_PREFIXES = (
    f"{MARKETING_ADMIN_PATH_PREFIX}notifications/",
    f"{MARKETING_ADMIN_PATH_PREFIX}contacts/exports/",
)


class MarketingCacheInvalidationMiddleware:
    """Invalidate the Marketing Hub read cache after any Marketing write.

    Hooked here rather than in each view so new write endpoints are covered
    automatically. Failed writes invalidate too: a provider error can follow a
    partial Mautic change (for example a bulk stage update)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if (
            request.method in WRITE_METHODS
            and request.path_info.startswith(MARKETING_ADMIN_PATH_PREFIX)
            and not request.path_info.startswith(NON_MAUTIC_WRITE_PREFIXES)
            and response.status_code not in UNCHANGED_STATUS_CODES
        ):
            marketing_cache.invalidate()
        return response
