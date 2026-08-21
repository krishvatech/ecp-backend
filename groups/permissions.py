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

        user = request.user
        if not (user and user.is_authenticated):
            return False

        # Only owners (superusers) can create new top-level groups
        if request.method == "POST":
            return bool(user.is_superuser)

        # For other non-safe methods, defer to object-level checks
        return True

    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True

        user = request.user
        if not (user and user.is_authenticated):
            return False

        # Owners (superusers) can always edit/delete
        if user.is_superuser:
            return True

        # Otherwise only the creator of the group can update/delete
        return obj.created_by_id == user.id


# ---------------------------------------------------------------------------
# Group-level roles.
#
# Two independent axes decide what somebody may do:
#
#   user.is_staff / is_superuser -> Django admin and platform-wide management
#   GroupMembership.role         -> permissions inside one specific group
#
# They are deliberately not mixed: a normal user can hold ``role=moderator``
# on one group and gets moderation rights there and nowhere else, without ever
# becoming Django staff. Platform staff keep every capability they had before.
#
# Hierarchy: platform staff > owner > admin > moderator > member.
# ---------------------------------------------------------------------------

def _user_id(user):
    if not user or not getattr(user, "is_authenticated", False):
        return None
    return getattr(user, "id", None)


def is_platform_staff(user) -> bool:
    """Platform-level privilege. Unrelated to any group role."""
    return bool(
        user
        and getattr(user, "is_authenticated", False)
        and (getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))
    )


def is_group_owner(user, group) -> bool:
    uid = _user_id(user)
    if not uid or not group:
        return False
    return getattr(group, "owner_id", None) == uid or getattr(group, "created_by_id", None) == uid


def membership_role(user, group):
    """ACTIVE membership role for this user in this group, else ``None``.

    Only ACTIVE memberships grant anything: a banned, removed or still-pending
    member holding ``role=moderator`` has no moderation rights.
    """
    uid = _user_id(user)
    if not uid or not group:
        return None
    return (
        GroupMembership.objects
        .filter(group=group, user_id=uid, status=GroupMembership.STATUS_ACTIVE)
        .values_list("role", flat=True)
        .first()
    )


def is_group_admin(user, group) -> bool:
    """ACTIVE ``role=admin`` membership. Does not require Django staff."""
    return membership_role(user, group) == GroupMembership.ROLE_ADMIN


def is_moderator(user, group) -> bool:
    """ACTIVE ``role=moderator`` membership. Does not require Django staff."""
    return membership_role(user, group) == GroupMembership.ROLE_MODERATOR


def can_manage_group(user, group) -> bool:
    """Edit group details, manage members, and set roles — within this group."""
    return bool(
        is_platform_staff(user)
        or is_group_owner(user, group)
        or is_group_admin(user, group)
    )


def can_moderate_content(user, group) -> bool:
    """Hide/delete posts and messages — within this group."""
    return bool(can_manage_group(user, group) or is_moderator(user, group))


def can_review_join_requests(user, group) -> bool:
    """Approve or decline pending join requests.

    Moderators are included: gatekeeping who gets into the group is part of
    day-to-day moderation, separate from editing the group or setting roles.
    """
    return bool(can_manage_group(user, group) or is_moderator(user, group))


def can_assign_admin_role(user, group) -> bool:
    """Granting or revoking ``role=admin`` is reserved for owner/platform staff.

    A group admin may promote members to moderator and demote them again, but
    may not mint further admins or unseat a peer.
    """
    return bool(is_platform_staff(user) or is_group_owner(user, group))


def effective_group_role(user, group):
    """Highest role the user holds here, for display: owner/admin/moderator/member."""
    if is_group_owner(user, group):
        return "owner"
    return membership_role(user, group)


def group_permissions(user, group) -> dict:
    """Capability flags for one user on one group, as returned by the API."""
    # Resolve the membership once; the helpers would each re-query otherwise.
    staff = is_platform_staff(user)
    owner = is_group_owner(user, group)
    role = None if (staff or owner) else membership_role(user, group)

    manage = bool(staff or owner or role == GroupMembership.ROLE_ADMIN)
    moderate = bool(manage or role == GroupMembership.ROLE_MODERATOR)
    return {
        "can_edit": manage,
        "can_manage_members": manage,
        "can_set_roles": manage,
        "can_assign_admin_role": bool(staff or owner),
        "can_moderate_posts": moderate,
        "can_review_join_requests": moderate,
    }


class IsGroupModerator(BasePermission):
    """Attach to views that require a moderator of the group."""
    def has_object_permission(self, request, view, obj):
        group = obj if hasattr(obj, "memberships") else getattr(obj, "group", None)
        return is_moderator(request.user, group)


class GroupSuperuserOnly(BasePermission):
    """
    Allows access only to superusers.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.is_superuser)

    def has_object_permission(self, request, view, obj):
        return bool(request.user and request.user.is_authenticated and request.user.is_superuser)
