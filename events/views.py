"""
ViewSets for the events app.

Users can list, create, retrieve, update, and delete events belonging to
organizations they are members of.  Creation is restricted to users
belonging to the target organization.
"""
from rest_framework import permissions, viewsets
from rest_framework.exceptions import PermissionDenied

from .models import Event
from .serializers import EventSerializer


class EventViewSet(viewsets.ModelViewSet):
    """CRUD operations for events."""
    serializer_class = EventSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # Restrict events to those where the user is a member of the organization
        return Event.objects.filter(organization__members=user).select_related("organization")

    def perform_create(self, serializer):
        org_id = serializer.validated_data["organization_id"]
        # Ensure the user is a member of the organization they are creating an event for
        if not self.request.user.organizations.filter(id=org_id).exists():
            raise PermissionDenied("You must be a member of the organization to create events.")
        serializer.save()