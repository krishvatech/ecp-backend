"""
Public Participant Directory API for in-person events.
Allows anonymous/public access to attendee directory without requiring authentication.
"""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.shortcuts import get_object_or_404
from django.db.models import Prefetch, Q
from .models import Event, EventRegistration, EventBadgeLabel
from .serializers import EventParticipantDirectorySerializer
from .services.post_acceptance_forms import is_online_event
import logging

logger = logging.getLogger(__name__)


class ParticipantDirectoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public API for fetching participant directory for in-person events.

    GET /api/events/{event_id}/participants/directory/
    - No authentication required
    - Only shows data for in-person events
    - Returns: List of registered attendees with badge labels
    """
    permission_classes = [AllowAny]
    serializer_class = EventParticipantDirectorySerializer

    def get_queryset(self):
        """Override to prevent direct access."""
        return EventRegistration.objects.none()

    @action(detail=False, methods=['get'], url_path='directory')
    def directory(self, request, event_id=None):
        """
        Get participant directory for an event.

        Query params:
        - search: Search by name, company, or job title
        - badge: Filter by badge label ID
        - limit: Number of results (default 100, max 500)
        - offset: Pagination offset
        """
        event = get_object_or_404(Event, id=event_id)

        # Only allow directory access for in-person events
        if is_online_event(event):
            return Response(
                {
                    'detail': 'Participant directory is only available for in-person events.',
                    'available': False,
                },
                status=status.HTTP_403_FORBIDDEN
            )

        # Check if event is published
        if event.status not in ['published', 'live', 'ended']:
            return Response(
                {
                    'detail': 'Event is not available.',
                    'available': False,
                },
                status=status.HTTP_404_NOT_FOUND
            )

        # Get registrations for confirmed attendees only
        registrations = EventRegistration.objects.filter(
            event=event,
            status='registered',
            attendee_status='confirmed'
        ).select_related('user', 'user__profile').prefetch_related('badge_labels')

        # Apply search filter
        search_query = request.query_params.get('search', '').strip()
        if search_query:
            registrations = registrations.filter(
                Q(user__first_name__icontains=search_query) |
                Q(user__last_name__icontains=search_query) |
                Q(user__profile__company__icontains=search_query) |
                Q(user__profile__job_title__icontains=search_query)
            )

        # Apply badge filter
        badge_id = request.query_params.get('badge')
        if badge_id:
            try:
                badge = EventBadgeLabel.objects.get(id=badge_id, event=event)
                registrations = registrations.filter(badge_labels=badge)
            except EventBadgeLabel.DoesNotExist:
                pass

        # Order by registration date
        registrations = registrations.order_by('-registered_at')

        # Pagination
        limit = min(int(request.query_params.get('limit', 100)), 500)
        offset = int(request.query_params.get('offset', 0))

        total_count = registrations.count()
        paginated = registrations[offset : offset + limit]

        # Serialize
        serializer = self.serializer_class(paginated, many=True, context={'request': request})

        return Response({
            'count': total_count,
            'next': offset + limit < total_count,
            'results': serializer.data,
            'available': True,
            'event': {
                'id': event.id,
                'title': event.title,
                'slug': event.slug,
                'format': event.format,
                'badge_labels': [
                    {'id': label.id, 'name': label.name, 'color': label.color}
                    for label in event.badge_labels.all()
                ],
            },
        })

    @action(detail=False, methods=['get'], url_path='search')
    def search(self, request, event_id=None):
        """
        Search participants in an event.

        Query params:
        - q: Search query
        """
        event = get_object_or_404(Event, id=event_id)

        # Only allow for in-person events
        if is_online_event(event):
            return Response({'results': []})

        search_query = request.query_params.get('q', '').strip()
        if not search_query or len(search_query) < 2:
            return Response({'results': []})

        registrations = EventRegistration.objects.filter(
            event=event,
            status='registered',
            attendee_status='confirmed'
        ).select_related('user', 'user__profile').filter(
            Q(user__first_name__icontains=search_query) |
            Q(user__last_name__icontains=search_query) |
            Q(user__profile__company__icontains=search_query) |
            Q(user__profile__job_title__icontains=search_query)
        )[:20]

        serializer = self.serializer_class(registrations, many=True, context={'request': request})
        return Response({'results': serializer.data})
