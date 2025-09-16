"""
ViewSets for the events app.

Users can list, create, retrieve, update, and delete events belonging to
organizations they are members of.  Creation is restricted to users
belonging to the target organization.
"""
from rest_framework import permissions, viewsets, status
from rest_framework.exceptions import PermissionDenied
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import Event
from .serializers import EventSerializer


class EventViewSet(viewsets.ModelViewSet):
    """CRUD operations for events."""
    serializer_class = EventSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = Event.objects.all().select_related("organization")
        mine = self.request.query_params.get("mine")
        if mine: 
            qs = qs.filter(created_by=self.request.user)
        return qs.order_by("-start_time")
    
    def perform_create(self, serializer):
        org_id = serializer.validated_data["organization_id"]
        # Ensure the user is a member of the organization they are creating an event for
        if not self.request.user.organizations.filter(id=org_id).exists():
            raise PermissionDenied("You must be a member of the organization to create events.")
        serializer.save()

    @action(detail=True, methods=["post"], permission_classes=[permissions.IsAuthenticated], url_path="start")
    def start_event(self, request, pk=None):
        """Start a live event.

        Sets the event status to ``live``, marks the ``is_live`` flag
        true and stores the start timestamp.  Only the event creator
        or the organization owner may perform this action.  If the
        event is already live or has ended, a 400 response is
        returned.
        """
        event = self.get_object()
        user = request.user
        if event.status in {"live", "ended"}:
            return Response(
                {"error": "invalid_state", "detail": "Event is already live or has ended."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # Check permission: must be event creator or organization owner
        if not (event.created_by_id == user.id or event.organization.owner_id == user.id):
            raise PermissionDenied("You do not have permission to start this event.")
        # Update fields
        event.status = "live"
        event.is_live = True
        from django.utils import timezone

        event.live_started_at = timezone.now()
        event.active_speaker = user  # default to starter as speaker
        event.save()
        return Response(EventSerializer(event, context=self.get_serializer_context()).data)

    @action(detail=True, methods=["post"], permission_classes=[permissions.IsAuthenticated], url_path="stop")
    def stop_event(self, request, pk=None):
        """End a live event.

        Sets the event status to ``ended``, clears the ``is_live`` flag
        and stores the end timestamp.  Only the event creator or the
        organization owner may perform this action.  If the event is
        not currently live, a 400 response is returned.
        """
        event = self.get_object()
        user = request.user
        if event.status != "live":
            return Response(
                {"error": "invalid_state", "detail": "Event is not currently live."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not (event.created_by_id == user.id or event.organization.owner_id == user.id):
            raise PermissionDenied("You do not have permission to stop this event.")
        event.status = "ended"
        event.is_live = False
        from django.utils import timezone

        event.live_ended_at = timezone.now()
        # Do not clear active_speaker to allow analytics; leaving as last speaker
        event.save()
        return Response(EventSerializer(event, context=self.get_serializer_context()).data)