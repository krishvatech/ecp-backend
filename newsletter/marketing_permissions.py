"""Authorization for Marketing Hub APIs.

Two different questions, deliberately answered by two different classes:

* **Using** the Marketing Hub needs an active ECP superuser *with an active
  Mautic mapping*. Superuser alone is not enough, and an inactive mapping is
  not enough.
* **Managing** who has Marketing access needs an active ECP superuser only —
  otherwise the first superuser could never grant access to anybody, including
  themselves.

The frontend hides what a user may not use, but this is where it is enforced.
"""

from rest_framework.permissions import BasePermission

from .marketing_access_services import has_marketing_hub_access, is_marketing_manager


class HasMarketingHubAccess(BasePermission):
    """Active ECP superuser with an active Mautic user connection."""

    message = (
        "Marketing Hub access requires an ECP superuser account with an active "
        "Mautic user connection."
    )

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        if not (user and user.is_authenticated):
            return False
        return has_marketing_hub_access(user)


class CanManageMarketingAccess(BasePermission):
    """Active ECP superuser, mapped or not."""

    message = "Only ECP superusers can manage Marketing access."

    def has_permission(self, request, view):
        return is_marketing_manager(getattr(request, "user", None))
