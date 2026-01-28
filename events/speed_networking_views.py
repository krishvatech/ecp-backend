"""
Views for Speed Networking functionality.

Provides API endpoints for:
- Session management (CRUD, start/stop)
- Queue operations (join/leave)
- Matching logic
- Current match retrieval
"""
from django.utils import timezone
from django.db import transaction
from django.db.models import Q
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
import uuid

from .models import SpeedNetworkingSession, SpeedNetworkingMatch, SpeedNetworkingQueue, Event
from .serializers import (
    SpeedNetworkingSessionSerializer,
    SpeedNetworkingMatchSerializer,
    SpeedNetworkingQueueSerializer
)
from .utils import (
    create_dyte_meeting,
    add_dyte_participant,
    send_speed_networking_message,
    send_speed_networking_user_message,
    DYTE_PRESET_PARTICIPANT
)


class SpeedNetworkingSessionViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing Speed Networking sessions.
    
    Endpoints:
    - GET /api/events/{event_id}/speed-networking/ - List sessions
    - POST /api/events/{event_id}/speed-networking/ - Create session
    - GET /api/events/{event_id}/speed-networking/{id}/ - Get session
    - PATCH /api/events/{event_id}/speed-networking/{id}/ - Update session
    - POST /api/events/{event_id}/speed-networking/{id}/start/ - Start session
    - POST /api/events/{event_id}/speed-networking/{id}/stop/ - Stop session
    - GET /api/events/{event_id}/speed-networking/{id}/stats/ - Get statistics
    """
    serializer_class = SpeedNetworkingSessionSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        event_id = self.kwargs.get('event_id')
        if event_id:
            return SpeedNetworkingSession.objects.filter(event_id=event_id)
        return SpeedNetworkingSession.objects.all()
    
    def perform_create(self, serializer):
        event_id = self.kwargs.get('event_id')
        event = Event.objects.get(id=event_id)
        serializer.save(created_by=self.request.user, event=event)
    
    @action(detail=True, methods=['post'])
    def start(self, request, event_id=None, pk=None):
        """Start a speed networking session."""
        session = self.get_object()
        
        if session.status != 'PENDING':
            return Response(
                {'error': 'Session is not in PENDING status'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        session.status = 'ACTIVE'
        session.started_at = timezone.now()
        session.save()
        
        # Reset queue (clear any stale entries from previous runs)
        session.queue.update(is_active=False, current_match=None)
        session.matches.filter(status='ACTIVE').update(status='COMPLETED', ended_at=timezone.now())
        
        # Broadcast via WebSocket
        send_speed_networking_message(event_id, 'speed_networking.session_started', {
            'session_id': session.id,
            'duration_minutes': session.duration_minutes
        })
        
        serializer = self.get_serializer(session)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    def stop(self, request, event_id=None, pk=None):
        """Stop a speed networking session."""
        session = self.get_object()
        
        if session.status != 'ACTIVE':
            return Response(
                {'error': 'Session is not ACTIVE'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # End all active matches
        active_matches = session.matches.filter(status='ACTIVE')
        for match in active_matches:
            match.status = 'COMPLETED'
            match.ended_at = timezone.now()
            match.save()
        
        # Clear queue
        session.queue.update(is_active=False)
        
        session.status = 'ENDED'
        session.ended_at = timezone.now()
        session.save()
        
        # Broadcast via WebSocket
        send_speed_networking_message(event_id, 'speed_networking.session_ended', {
            'session_id': session.id
        })
        
        serializer = self.get_serializer(session)
        return Response(serializer.data)
    
    @action(detail=True, methods=['get'])
    def stats(self, request, event_id=None, pk=None):
        """Get session statistics."""
        session = self.get_object()
        
        total_matches = session.matches.count()
        active_matches = session.matches.filter(status='ACTIVE').count()
        completed_matches = session.matches.filter(status='COMPLETED').count()
        queue_count = session.queue.filter(is_active=True, current_match__isnull=True).count()
        
        return Response({
            'session_id': session.id,
            'status': session.status,
            'total_matches': total_matches,
            'active_matches': active_matches,
            'completed_matches': completed_matches,
            'queue_count': queue_count,
            'duration_minutes': session.duration_minutes,
            'started_at': session.started_at,
            'ended_at': session.ended_at,
        })


class SpeedNetworkingQueueViewSet(viewsets.ViewSet):
    """
    ViewSet for queue operations.
    
    Endpoints:
    - POST /api/events/{event_id}/speed-networking/{session_id}/join/ - Join queue
    - POST /api/events/{event_id}/speed-networking/{session_id}/leave/ - Leave queue
    - GET /api/events/{event_id}/speed-networking/{session_id}/my-match/ - Get current match
    - POST /api/events/{event_id}/speed-networking/matches/{match_id}/next/ - Skip to next
    """
    permission_classes = [IsAuthenticated]

    def _get_dyte_token_for_user(self, match, user):
        if not match.dyte_room_name:
            return None

        display_name = f"{user.first_name} {user.last_name}".strip() or user.username
        meeting_id = match.dyte_room_name
        token, _ = add_dyte_participant(
            meeting_id,
            user.id,
            display_name,
            DYTE_PRESET_PARTICIPANT
        )
        if token:
            return token

        # Fallback: if we only have a placeholder "match-..." value, create a real Dyte meeting
        # and persist it so future calls use the correct ID.
        if meeting_id.startswith("match-"):
            real_meeting_id = create_dyte_meeting(meeting_id)
            if real_meeting_id:
                if real_meeting_id != meeting_id:
                    match.dyte_room_name = real_meeting_id
                    match.save(update_fields=["dyte_room_name"])
                token, _ = add_dyte_participant(
                    real_meeting_id,
                    user.id,
                    display_name,
                    DYTE_PRESET_PARTICIPANT
                )
                if token:
                    return token

        return None
    
    @action(detail=False, methods=['post'])
    def join(self, request, event_id=None, session_id=None):
        """Join the speed networking queue."""
        try:
            session = SpeedNetworkingSession.objects.get(id=session_id, event_id=event_id)
        except SpeedNetworkingSession.DoesNotExist:
            return Response(
                {'error': 'Session not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if session.status != 'ACTIVE':
            return Response(
                {'error': 'Session is not active'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = request.user
        
        # Get or create queue entry
        queue_entry, created = SpeedNetworkingQueue.objects.get_or_create(
            session=session,
            user=user,
            defaults={'is_active': True}
        )
        
        if not created and not queue_entry.is_active:
            queue_entry.is_active = True
            queue_entry.save()
        
        # Try to find a match immediately
        match = self._find_and_create_match(session, user)
        
        if match:
            serializer = SpeedNetworkingMatchSerializer(match)
            data = serializer.data
            
            # Add Dyte token
            if match.dyte_room_name:
                token = self._get_dyte_token_for_user(match, user)
                if token:
                    data['dyte_token'] = token

            return Response({
                'status': 'matched',
                'match': data,
                'message': 'Match found!'
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'status': 'queued',
                'message': 'Waiting for a match...'
            }, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['post'])
    def leave(self, request, event_id=None, session_id=None):
        """Leave the speed networking queue."""
        try:
            queue_entry = SpeedNetworkingQueue.objects.get(
                session_id=session_id,
                user=request.user,
                is_active=True
            )
        except SpeedNetworkingQueue.DoesNotExist:
            return Response(
                {'error': 'Not in queue'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # End current match if any
        if queue_entry.current_match and queue_entry.current_match.status == 'ACTIVE':
            match = queue_entry.current_match
            match.status = 'COMPLETED'
            match.ended_at = timezone.now()
            match.save()
            
            # Try to match the partner with someone else
            partner = match.participant_1 if match.participant_2 == request.user else match.participant_2
            self._find_and_create_match(queue_entry.session, partner)
        
        queue_entry.is_active = False
        queue_entry.current_match = None
        queue_entry.save()
        
        return Response({'message': 'Left queue successfully'})
    
    @action(detail=False, methods=['get'])
    def my_match(self, request, event_id=None, session_id=None):
        """Get current active match for the user."""
        try:
            queue_entry = SpeedNetworkingQueue.objects.get(
                session_id=session_id,
                user=request.user,
                is_active=True
            )
        except SpeedNetworkingQueue.DoesNotExist:
            return Response(
                {'error': 'Not in queue'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if queue_entry.current_match and queue_entry.current_match.status == 'ACTIVE':
            match = queue_entry.current_match
            serializer = SpeedNetworkingMatchSerializer(match)
            data = serializer.data
            
            # Add Dyte token for current user
            if match.dyte_room_name:
                token = self._get_dyte_token_for_user(match, request.user)
                if token:
                    data['dyte_token'] = token
                    
            return Response(data)
        else:
            # Self-healing: active retry logic
            # If user is waiting, try to find a match right now during the poll
            session = queue_entry.session
            new_match = self._find_and_create_match(session, request.user)
            
            if new_match:
                serializer = SpeedNetworkingMatchSerializer(new_match)
                data = serializer.data
                
                if new_match.dyte_room_name:
                    token = self._get_dyte_token_for_user(new_match, request.user)
                    if token:
                        data['dyte_token'] = token
                
                return Response({
                    'status': 'matched',
                    'match': data,
                    'message': 'Match found!'
                })

            return Response({
                'status': 'waiting',
                'message': 'No active match'
            })
    
    @action(detail=True, methods=['post'], url_path='matches/(?P<match_id>[^/.]+)/next')
    def next_match(self, request, event_id=None, session_id=None, match_id=None):
        """Skip to next match."""
        with transaction.atomic():
            try:
                # Lock the match to prevent race conditions (double skippage)
                match = SpeedNetworkingMatch.objects.select_for_update().get(id=match_id)
            except SpeedNetworkingMatch.DoesNotExist:
                return Response(
                    {'error': 'Match not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Verify user is part of this match
            if request.user not in [match.participant_1, match.participant_2]:
                return Response(
                    {'error': 'Not authorized'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Idempotency: If already skipped/completed, client is out of sync or double-clicked.
            # Just try to find them a new match (or return existing queue status).
            if match.status != 'ACTIVE':
                # Check if they already have a new match?
                # For simplicity, just tell them they are queued/waiting.
                return Response({
                    'status': 'queued',
                    'message': 'Match already ended. Waiting for next match...'
                })
            
            # End current match
            match.status = 'SKIPPED'
            match.ended_at = timezone.now()
            match.save()
            
            # Release users from this match in the queue
            SpeedNetworkingQueue.objects.filter(
                session=match.session,
                user__in=[match.participant_1, match.participant_2]
            ).update(current_match=None)
            
            # Try to find new matches for both participants
            session = match.session
            
            # Note: _find_and_create_match sends its own 'match_found' notifications via WebSocket.
            # We ONLY need to send notifications if a match was NOT found (to tell them "Match Ended, Back to Queue").
            new_match_1 = self._find_and_create_match(session, match.participant_1)
            new_match_2 = self._find_and_create_match(session, match.participant_2)
            
            # Handle notifications for "No Match Found" (Back to Queue)
            # We check both participants.
            for user, new_match in [(match.participant_1, new_match_1), (match.participant_2, new_match_2)]:
                if not new_match:
                    print(f"DEBUG: No new match for {user.username}. Sending match_ended.")
                    send_speed_networking_user_message(user.id, 'speed_networking.match_ended', {
                         "message": "Match ended. Returning to queue..."
                    })

            # Prepare response for the *requesting* user
            user_match = new_match_1 if match.participant_1 == request.user else new_match_2
            
            if user_match:
                print(f"DEBUG: Returning new match {user_match.id} to requester")
                serializer = SpeedNetworkingMatchSerializer(user_match)
                data = serializer.data
                
                # Add Dyte token (logic duplicated from serializer/utils but needed for immediate response)
                if user_match.dyte_room_name:
                    token = self._get_dyte_token_for_user(user_match, request.user)
                    if token:
                        data['dyte_token'] = token

                return Response({
                    'status': 'matched',
                    'match': data
                })
            else:
                print("DEBUG: No match found for requester. Returning to queue.")
                return Response({
                    'status': 'queued',
                    'message': 'Waiting for next match...'
                })
    
    def _find_and_create_match(self, session, user):
        """
        Find a match for the user and create a SpeedNetworkingMatch.
        Uses select_for_update(skip_locked=True) to prevent race conditions.
        Crucial: Dyte API calls are performed AFTER the transaction to avoid holding locks.
        """
        match = None
        match_data = None
        
        # PHASE 1: Database Operations (Atomic & Fast)
        with transaction.atomic():
            # 1. Lock the INITIATOR
            try:
                user_queue = SpeedNetworkingQueue.objects.select_for_update().get(
                    session=session,
                    user=user
                )
            except SpeedNetworkingQueue.DoesNotExist:
                return None
            
            if user_queue.current_match is not None:
                return None

            # 2. Find a PARTNER
            available_users = SpeedNetworkingQueue.objects.filter(
                session=session,
                is_active=True,
                current_match__isnull=True
            ).exclude(user=user)
            
            # Filter history
            already_matched_user_ids = SpeedNetworkingMatch.objects.filter(
                session=session
            ).filter(
                Q(participant_1=user) | Q(participant_2=user)
            ).values_list('participant_1_id', 'participant_2_id')
            
            matched_ids = set()
            for p1_id, p2_id in already_matched_user_ids:
                matched_ids.add(p1_id)
                matched_ids.add(p2_id)
            matched_ids.discard(user.id)
            
            # Find partner using SKIP LOCKED
            partner_queue = available_users.exclude(user_id__in=matched_ids).select_for_update(skip_locked=True).first()
            
            if not partner_queue:
                # Fallback for small pools
                partner_queue = available_users.select_for_update(skip_locked=True).first()

            if not partner_queue:
                return None
            
            partner = partner_queue.user
            
            # Pre-generate ID to store in DB (valid even if Dyte fails later)
            dyte_meeting_room = f"match-{session.id}-{uuid.uuid4().hex[:8]}"

            # Create Match Record
            match = SpeedNetworkingMatch.objects.create(
                session=session,
                participant_1=user,
                participant_2=partner,
                dyte_room_name=dyte_meeting_room,
                status='ACTIVE'
            )
            
            # Update Queue
            user_queue.current_match = match
            user_queue.save()
            
            partner_queue.current_match = match
            partner_queue.save()
            
            match_data = SpeedNetworkingMatchSerializer(match).data

        # PHASE 2: External API Calls & Notifications (Outside Transaction)
        if match and match_data:
            # Create Dyte Meeting (Idempotent-ish)
            meeting_id = create_dyte_meeting(match.dyte_room_name) # Uses room_name as title
            # Consider: If create fails, we still proceed with the match (just no video).
            # But create_dyte_meeting returns an ID. If logic uses room_name as meeting ID, ensure consistency.
            # actually utils.create_dyte_meeting returns a NEW ID from Dyte. 
            # We should probably update the match with the REAL Dyte ID if different, 
            # Or just use the one we generated if using V2 preset logic?
            # Let's assume create_dyte_meeting makes the room exist.
            real_meeting_id = meeting_id or match.dyte_room_name
            if meeting_id and meeting_id != match.dyte_room_name:
                match.dyte_room_name = meeting_id
                match.save(update_fields=["dyte_room_name"])
            
            # Generate Tokens
            p1_token = None
            p2_token = None
            
            try:
                p1_token, _ = add_dyte_participant(
                    real_meeting_id,
                    user.id,
                    f"{user.first_name} {user.last_name}".strip() or user.username,
                    DYTE_PRESET_PARTICIPANT
                )
            except Exception as e:
                print(f"ERROR: Dyte P1 failed: {e}")

            try:
                p2_token, _ = add_dyte_participant(
                    real_meeting_id,
                    partner.id,
                    f"{partner.first_name} {partner.last_name}".strip() or partner.username,
                    DYTE_PRESET_PARTICIPANT
                )
            except Exception as e:
                print(f"ERROR: Dyte P2 failed: {e}")
            
            # Notify User 1
            p1_data = match_data.copy()
            if p1_token:
                p1_data['dyte_token'] = p1_token
                
            send_speed_networking_user_message(user.id, 'speed_networking.match_found', {
                'match_id': match.id,
                'user_id': user.id,
                'match': p1_data
            })
            
            # Notify User 2
            p2_data = match_data.copy()
            if p2_token:
                p2_data['dyte_token'] = p2_token

            send_speed_networking_user_message(partner.id, 'speed_networking.match_found', {
                'match_id': match.id,
                'user_id': partner.id,
                'match': p2_data
            })
            
        return match
