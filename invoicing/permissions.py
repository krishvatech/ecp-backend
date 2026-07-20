from rest_framework import permissions


class IsInvoiceOwner(permissions.BasePermission):
    """Only invoice owner can view their invoices."""

    def has_object_permission(self, request, view, obj):
        return obj.customer.user == request.user


class IsAuthenticated(permissions.BasePermission):
    """Only authenticated users can access invoicing."""

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated


class IsPlatformAdmin(permissions.BasePermission):
    """Allow only the same platform-admin identities used by Saleor Manager.

    Cognito group claims are checked first, then the synchronized Django group,
    with the staff+superuser combination retained as the existing fallback.
    """

    message = "Only platform_admin can manage invoice settings."

    def has_permission(self, request, view):
        user = getattr(request, 'user', None)
        if not user or not getattr(user, 'is_authenticated', False):
            return False

        claims = getattr(request, 'cognito_claims', {}) or {}
        raw_groups = claims.get('cognito:groups') or []
        if isinstance(raw_groups, str):
            groups = {group.strip().lower() for group in raw_groups.split(',') if group.strip()}
        else:
            groups = {str(group).strip().lower() for group in raw_groups if str(group).strip()}

        if 'platform_admin' in groups:
            return True

        try:
            if user.groups.filter(name='platform_admin').exists():
                return True
        except Exception:
            pass

        return bool(getattr(user, 'is_staff', False) and getattr(user, 'is_superuser', False))
