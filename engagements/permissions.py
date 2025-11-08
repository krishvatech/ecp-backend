from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsOwnerOrStaffOrReadOnly(BasePermission):
    """
    Read for everyone (if view allows), write only for owner; staff bypass.
    Assumes the object has a `user` field.
    """
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        user = request.user
        if not user or not user.is_authenticated:
            return False
        return user.is_staff or getattr(obj, "user_id", None) == user.id
