# groups/permissions.py
from rest_framework.permissions import BasePermission, SAFE_METHODS
from .models import GroupMembership

class GroupCreateByAdminOnly(BasePermission):
    """
    Existing rule:
    - CREATE group: staff only
    - READ: anyone
    - UPDATE/DELETE: staff or creator
    """
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        if request.method == 'POST':  # create group
            return bool(request.user and request.user.is_authenticated and request.user.is_staff)
        return True

    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        if request.user and request.user.is_authenticated:
            return request.user.is_staff or obj.created_by_id == request.user.id
        return False


# -------- Moderator helpers --------
def is_moderator(user, group) -> bool:
    if not user or not getattr(user, "is_authenticated", False) or not group:
        return False
    try:
        mem = GroupMembership.objects.get(
            group=group, user=user, status=GroupMembership.STATUS_ACTIVE
        )
    except GroupMembership.DoesNotExist:
        return False
    return mem.role == GroupMembership.ROLE_MODERATOR


def can_moderate_content(user, group) -> bool:
    return is_moderator(user, group)


class IsGroupModerator(BasePermission):
    """Attach to views that require a moderator of the group."""
    def has_object_permission(self, request, view, obj):
        group = obj if hasattr(obj, "memberships") else getattr(obj, "group", None)
        return is_moderator(request.user, group)
