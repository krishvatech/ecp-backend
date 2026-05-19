"""
Permissions for events and post-acceptance forms.
"""
from rest_framework import permissions


class IsSuperuserOnly(permissions.BasePermission):
    """
    Grants access only to superusers (platform admins).
    Used for Virtual Speaker CRUD operations that should be restricted to Super Admin users.
    """
    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        return bool(user and user.is_authenticated and user.is_superuser)


class HasRestrictedDataPermission(permissions.BasePermission):
    """
    Permission to view restricted attendee data (emergency contact, medical info, accessibility needs).
    Allows:
    - Superusers
    - Staff users
    - Users in 'view_restricted_attendee_data' group
    """
    def has_permission(self, request, view):
        if request.user.is_superuser or request.user.is_staff:
            return True
        
        if request.user.is_authenticated:
            return request.user.groups.filter(name='view_restricted_attendee_data').exists()
        
        return False


class IsEventAdminOrSuperuser(permissions.BasePermission):
    """
    Permission to manage event forms (admin only).
    Allows event creator, superuser, or staff.
    """
    def has_object_permission(self, request, view, obj):
        event = obj.event if hasattr(obj, 'event') else obj
        return (
            event.created_by_id == request.user.id or
            request.user.is_superuser or
            request.user.is_staff
        )

    def has_permission(self, request, view):
        return request.user.is_authenticated
