"""
ViewSets for the organizations app.

Allows authenticated users to create, list, retrieve, update, and delete
organizations.  Users only see organizations in which they are members.
"""
from rest_framework import permissions, viewsets

from .models import Organization
from .serializers import OrganizationSerializer


class OrganizationViewSet(viewsets.ModelViewSet):
    """CRUD operations for organizations."""
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Users can only see organizations where they are members
        user = self.request.user
        return Organization.objects.filter(members=user).distinct()

    def perform_create(self, serializer):
        # Creator becomes the owner
        serializer.save()