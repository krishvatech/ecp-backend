"""Shared DRF permissions for user/account-level access rules."""

from rest_framework.permissions import BasePermission

from users.cognito_auth import is_platform_admin


class IsPlatformAdminForOpenAPIDocs(BasePermission):
    """Allow OpenAPI documentation only to the canonical platform admin role.

    This deliberately does *not* grant access to ordinary ``is_staff`` users.
    The project-level ``is_platform_admin`` helper remains the single source of
    truth, so Cognito ``platform_admin`` claims, synchronized Django group
    membership, and the existing staff+superuser fallback stay consistent with
    the rest of ECP.
    """

    message = "Only platform_admin can access API documentation."

    def has_permission(self, request, view):
        return is_platform_admin(request)
