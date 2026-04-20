from rest_framework import permissions


class IsInvoiceOwner(permissions.BasePermission):
    """Only invoice owner can view their invoices"""

    def has_object_permission(self, request, view, obj):
        return obj.customer.user == request.user


class IsAuthenticated(permissions.BasePermission):
    """Only authenticated users can access invoicing"""

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated
