from rest_framework.permissions import BasePermission


class IsSuperuserOnly(BasePermission):
    """
    Grants access only to superusers (platform admins).
    Used for Virtual Speaker CRUD operations that should be restricted to Super Admin users.
    """
    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        return bool(user and user.is_authenticated and user.is_superuser)
