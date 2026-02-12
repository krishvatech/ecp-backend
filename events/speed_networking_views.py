"""
Views for Speed Networking functionality.

Provides API endpoints for:
- Session management (CRUD, start/stop)
- Queue operations (join/leave)
- Matching logic (BOTH rule-based + criteria-based)
- Current match retrieval
"""
import logging
import uuid
from django.utils import timezone
from django.db import transaction
from django.db.models import Q, Avg
from django.contrib.auth.models import User
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

# Import BOTH matching engines
from .matching_engine import MatchingEngine
from .criteria_matching_engine import CriteriaBasedMatchingEngine

from .models import (
    SpeedNetworkingSession, SpeedNetworkingMatch, SpeedNetworkingQueue, Event,
    UserMatchingProfile, UserCriteriaProfile, SpeedNetworkingRule
)
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

logger = logging.getLogger(__name__)


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
        """Start session and precompute profiles for both matching systems."""
        from .models import EventRegistration

        session = self.get_object()

        if session.status != 'PENDING':
            return Response(
                {'error': 'Session is not in PENDING status'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get all registered users
        registered_users = EventRegistration.objects.filter(
            event=session.event,
            status='registered'
        ).values_list('user_id', flat=True)

        # Precompute rule-based profiles
        if session.matching_strategy in ['rule_only', 'both']:
            logger.info(f"[SESSION_START] Precomputing rule profiles for {len(registered_users)} users")
            rule_engine = MatchingEngine(session)
            rule_engine.bulk_precompute_profiles(registered_users)

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

    @action(detail=True, methods=['post'])
    def create_rule(self, request, event_id=None, pk=None):
        """Create a matching rule for this session."""
        session = self.get_object()

        if session.status != 'PENDING':
            return Response(
                {'error': 'Can only add rules to PENDING sessions'},
                status=status.HTTP_400_BAD_REQUEST
            )

        rule = SpeedNetworkingRule.objects.create(
            session=session,
            name=request.data.get('name'),
            rule_type=request.data.get('rule_type'),
            category=request.data.get('category'),
            segment_a_type=request.data.get('segment_a_type'),
            segment_a_values=request.data.get('segment_a_values', []),
            segment_b_type=request.data.get('segment_b_type'),
            segment_b_values=request.data.get('segment_b_values', []),
        )

        return Response({
            'id': rule.id,
            'name': rule.name,
            'rule_type': rule.rule_type
        }, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['get'])
    def rules(self, request, event_id=None, pk=None):
        """Get all matching rules for this session."""
        session = self.get_object()
        rules = session.matching_rules.all()

        return Response({
            'rules': [
                {
                    'id': r.id,
                    'name': r.name,
                    'rule_type': r.rule_type,
                    'category': r.category,
                    'segment_a_type': r.segment_a_type,
                    'segment_a_values': r.segment_a_values,
                    'segment_b_type': r.segment_b_type,
                    'segment_b_values': r.segment_b_values,
                    'is_active': r.is_active,
                }
                for r in rules
            ]
        })

    @action(detail=True, methods=['post'])
    def set_matching_strategy(self, request, event_id=None, pk=None):
        """Set matching strategy for session."""
        session = self.get_object()

        if session.status != 'PENDING':
            return Response(
                {'error': 'Can only change strategy on PENDING sessions'},
                status=status.HTTP_400_BAD_REQUEST
            )

        strategy = request.data.get('strategy')
        if strategy not in ['rule_only', 'criteria_only', 'both']:
            return Response(
                {'error': 'Invalid strategy'},
                status=status.HTTP_400_BAD_REQUEST
            )

        session.matching_strategy = strategy
        session.save()

        return Response({
            'strategy': session.matching_strategy
        })

    @action(detail=True, methods=['get'])
    def match_quality(self, request, event_id=None, pk=None):
        """Get match quality metrics for session."""
        session = self.get_object()

        matches = session.matches.all()
        completed = matches.filter(status='COMPLETED')

        avg_score = completed.aggregate(avg=Avg('match_score'))['avg'] or 0
        total = matches.count()

        return Response({
            'total_matches': total,
            'completed_matches': completed.count(),
            'avg_match_score': round(avg_score, 2),
            'completion_rate': round(completed.count() / total * 100, 2) if total > 0 else 0,
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

            # Get the partner before clearing the reference
            partner = match.participant_1 if match.participant_2 == request.user else match.participant_2

            # CRITICAL: Notify the partner that the match has ended via WebSocket
            # This must happen IMMEDIATELY so their UI updates to "Finding your match..."
            logger.info(f"[LEAVE] User {request.user.id} left match {match.id}. Notifying partner {partner.id}")
            send_speed_networking_user_message(partner.id, 'speed_networking.match_ended', {
                "message": "Your partner left the session. Looking for a new match..."
            })

            # Release both users from this match in the queue
            SpeedNetworkingQueue.objects.filter(
                session=match.session,
                user__in=[match.participant_1, match.participant_2]
            ).update(current_match=None)

            # Try to match the partner with someone else
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

        # Always refresh the queue entry to get the latest match assignment
        # This prevents showing stale matches after NEXT MATCH is clicked
        queue_entry.refresh_from_db()

        # Re-fetch the match object from database to ensure it's not stale
        # (refresh_from_db only refreshes the queue_entry, not the related match)
        if queue_entry.current_match_id:
            try:
                current_match = SpeedNetworkingMatch.objects.get(id=queue_entry.current_match_id)
                logger.debug(f"[MY_MATCH] User {request.user.id} has match {current_match.id} with status: {current_match.status}")

                # CRITICAL: Only return the match if:
                # 1. Status is ACTIVE, AND
                # 2. User is still part of the match
                is_participant = request.user in [current_match.participant_1, current_match.participant_2]

                if current_match.status == 'ACTIVE' and is_participant:
                    serializer = SpeedNetworkingMatchSerializer(current_match)
                    data = serializer.data

                    # Add Dyte token for current user
                    if current_match.dyte_room_name:
                        token = self._get_dyte_token_for_user(current_match, request.user)
                        if token:
                            data['dyte_token'] = token

                    logger.info(f"[MY_MATCH] ✅ Returning VALID active match {current_match.id} for user {request.user.id}")
                    return Response(data)
                else:
                    # Match is no longer active or user is not a participant anymore
                    logger.warning(f"[MY_MATCH] ❌ Match {current_match.id} INVALID for user {request.user.id} - Status: {current_match.status}, Is participant: {is_participant}")
                    queue_entry.current_match = None
                    queue_entry.save()
                    logger.info(f"[MY_MATCH] Cleared invalid match. User {request.user.id} will search for new match.")
            except SpeedNetworkingMatch.DoesNotExist:
                logger.warning(f"[MY_MATCH] Match {queue_entry.current_match_id} does not exist. Clearing queue entry.")
                queue_entry.current_match = None
                queue_entry.save()
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

                # Return match at root level (same structure as when match already exists)
                logger.info(f"[MY_MATCH] Self-healing found new match {new_match.id} for user {request.user.id}")
                return Response(data)

            # Return empty response (not wrapped) so frontend can detect no match via missing 'id'
            logger.info(f"[MY_MATCH] No match found for waiting user {request.user.id}")
            return Response({})
    
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
            logger.info(f"[NEXT_MATCH] Match {match.id} marked as SKIPPED")

            # Release users from this match in the queue
            SpeedNetworkingQueue.objects.filter(
                session=match.session,
                user__in=[match.participant_1, match.participant_2]
            ).update(current_match=None)
            logger.info(f"[NEXT_MATCH] Released both users from queue")

            # CRITICAL: Notify BOTH participants that the old match has ended IMMEDIATELY
            # This must happen BEFORE creating new matches to ensure frontend updates without delay
            logger.info(f"[NEXT_MATCH] Notifying both participants that match {match.id} has ended")
            send_speed_networking_user_message(match.participant_1.id, 'speed_networking.match_ended', {
                "message": "Match ended. Your partner moved to a new match."
            })
            send_speed_networking_user_message(match.participant_2.id, 'speed_networking.match_ended', {
                "message": "Match ended. Your partner moved to a new match."
            })
            logger.info(f"[NEXT_MATCH] Match ended notifications sent to both participants")

            # Try to find new matches for both participants
            session = match.session

            # IMPORTANT: Exclude the previous match participant to prevent rematching the same users
            new_match_1 = self._find_and_create_match(session, match.participant_1, exclude_user=match.participant_2)
            new_match_2 = self._find_and_create_match(session, match.participant_2, exclude_user=match.participant_1)

            # Handle notifications for "Match Found" (for users who found new matches)
            # These are sent by _find_and_create_match automatically, so we're good there.
            # Note: _find_and_create_match sends its own 'match_found' notifications via WebSocket.

            # Prepare response for the *requesting* user
            user_match = new_match_1 if match.participant_1 == request.user else new_match_2

            if user_match:
                print(f"DEBUG: Returning new match {user_match.id} to requester")

                # Refresh the user's queue entry to ensure it points to the new match
                try:
                    user_queue_entry = SpeedNetworkingQueue.objects.get(
                        session=session,
                        user=request.user
                    )
                    if user_queue_entry.current_match_id != user_match.id:
                        logger.warning(
                            f"[NEXT_MATCH] Queue entry mismatch: "
                            f"expected {user_match.id}, got {user_queue_entry.current_match_id}. "
                            f"Updating queue entry."
                        )
                        user_queue_entry.current_match = user_match
                        user_queue_entry.save()
                except SpeedNetworkingQueue.DoesNotExist:
                    logger.error(f"[NEXT_MATCH] Queue entry not found for user {request.user.id}")

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
    
    def _find_and_create_match(self, session, user, exclude_user=None):
        """
        Combined rule-based + criteria-based matching.

        Args:
            session: The speed networking session
            user: The user to find a match for
            exclude_user: User to exclude from matching (deprecated, kept for backward compatibility)

        STEP 1: Apply rule-based filtering (business logic)
        STEP 2: Score with criteria-based matching (quality optimization)
        STEP 3: Create match with both scores
        """
        logger.info(f"[BOTH_MATCH] Starting combined matching for user_id={user.id}")

        # Get ALL previous match partners in this session (comprehensive exclusion)
        exclude_user_ids = self._get_previous_match_partners(session, user)

        # Also exclude the immediate previous match partner if specified (for backward compatibility)
        if exclude_user:
            exclude_user_ids.append(exclude_user.id)
            logger.info(f"[BOTH_MATCH] Also excluding immediate previous match user_id={exclude_user.id}")

        if exclude_user_ids:
            logger.info(f"[BOTH_MATCH] Total users to exclude from candidates: {exclude_user_ids}")

        # ===============================================================
        # STEP 1: RULE-BASED FILTERING
        # ===============================================================

        if session.matching_strategy in ['rule_only', 'both']:
            logger.info("[BOTH_MATCH] Applying rule-based filtering")

            rule_engine = MatchingEngine(session)

            # Get user's rule-based profile
            try:
                rule_profile = UserMatchingProfile.objects.get(
                    session=session,
                    user=user
                )
            except UserMatchingProfile.DoesNotExist:
                logger.warning(f"[BOTH_MATCH] No rule profile for user {user.id}, creating default")
                rule_profile = UserMatchingProfile.objects.create(
                    session=session,
                    user=user,
                    user_type='attendee',
                    ticket_tier='basic'
                )

            # Apply rules to get eligible candidates
            candidates_after_rules = rule_engine.get_eligible_candidates(user)
            logger.info(f"[BOTH_MATCH] After rule filtering: {len(candidates_after_rules)} candidates")

            # Exclude all previous match partners in this session
            if exclude_user_ids:
                candidates_after_rules = [c for c in candidates_after_rules if c.id not in exclude_user_ids]
                logger.info(f"[BOTH_MATCH] After excluding {len(exclude_user_ids)} previous partners: {len(candidates_after_rules)} candidates remain")

            if not candidates_after_rules:
                logger.warning(f"[BOTH_MATCH] No candidates available after excluding previous partners for user {user.id}")
                return None
        else:
            # No rules, use all available candidates
            candidates_query = SpeedNetworkingQueue.objects.filter(
                session=session,
                is_active=True,
                current_match__isnull=True
            ).exclude(user=user)

            # Exclude all previous match partners in this session
            if exclude_user_ids:
                candidates_query = candidates_query.exclude(user_id__in=exclude_user_ids)
                logger.info(f"[BOTH_MATCH] Excluded {len(exclude_user_ids)} previous partners from candidates")

            candidates_after_rules = candidates_query.values_list('user_id', flat=True)

            if not candidates_after_rules:
                logger.warning(f"[BOTH_MATCH] No candidates available after excluding previous partners for user {user.id}")
                return None

        # ===============================================================
        # STEP 2: CRITERIA-BASED SCORING (on filtered candidates)
        # ===============================================================

        if session.matching_strategy in ['criteria_only', 'both']:
            logger.info("[BOTH_MATCH] Applying criteria-based scoring")

            # Build user profile from UserSkill (primary source of truth)
            user_profile_dict = self._build_user_profile_from_skills(user)

            # Build candidate profiles from UserSkill
            from django.contrib.auth.models import User as DjangoUser

            # Extract candidate IDs (candidates_after_rules contains User objects from rule engine)
            # or IDs directly from no-rules path
            if candidates_after_rules and hasattr(candidates_after_rules[0], 'id'):
                # Rule-based path returns User objects
                candidate_ids = [c.id for c in candidates_after_rules]
            else:
                # No-rules path returns IDs directly
                candidate_ids = candidates_after_rules

            candidate_users = DjangoUser.objects.filter(id__in=candidate_ids)
            candidate_profiles = [
                self._build_user_profile_from_skills(candidate)
                for candidate in candidate_users
            ]

            logger.debug(f"[BOTH_MATCH] Built profiles for user and {len(candidate_profiles)} candidates from UserSkill")

            # If no candidates have skills, fall back to basic matching
            if not candidate_profiles:
                logger.warning("[BOTH_MATCH] No candidates with skill data")
                return self._basic_match_from_candidates(
                    session, user, candidates_after_rules
                )

            # Initialize criteria matching engine
            criteria_config = self._get_criteria_config(session)
            criteria_engine = CriteriaBasedMatchingEngine(session, criteria_config)

            # Find best matches based on criteria
            matches = criteria_engine.find_best_matches(
                user_profile_dict,
                candidate_profiles,
                top_n=1
            )

            if matches:
                score, partner_dict, breakdown = matches[0]
                logger.info(f"[BOTH_MATCH] Found match with criteria score {score:.1f}")
            else:
                # Try fallback strategy
                logger.info("[BOTH_MATCH] No direct match, trying fallback")
                match_result, fallback_step = criteria_engine.find_match_with_fallback(
                    user_profile_dict,
                    candidate_profiles
                )

                if not match_result:
                    logger.warning("[BOTH_MATCH] No match found even with fallback")
                    return None

                score, partner_dict, breakdown = match_result
                logger.info(f"[BOTH_MATCH] Fallback matched at step {fallback_step}")
        else:
            # Criteria-only not enabled, do basic match from filtered candidates
            return self._basic_match_from_candidates(
                session, user, candidates_after_rules
            )

        # ===============================================================
        # STEP 3: CREATE MATCH WITH BOTH SCORES
        # ===============================================================

        logger.info(f"[BOTH_MATCH] Creating match between user_id={user.id} "
                   f"and user_id={partner_dict['user_id']}")

        try:
            partner = User.objects.get(id=partner_dict['user_id'])
        except User.DoesNotExist:
            logger.error(f"[BOTH_MATCH] Partner user {partner_dict['user_id']} not found")
            return None

        match = None
        match_data = None

        # Atomic database operations
        with transaction.atomic():
            try:
                user_queue = SpeedNetworkingQueue.objects.select_for_update().get(
                    session=session,
                    user=user
                )
            except SpeedNetworkingQueue.DoesNotExist:
                logger.error(f"[BOTH_MATCH] Queue entry not found for user {user.id}")
                return None

            if user_queue.current_match is not None:
                logger.debug(f"[BOTH_MATCH] User {user.id} already has a match")
                return None

            # Lock partner's queue entry
            try:
                partner_queue = SpeedNetworkingQueue.objects.select_for_update(
                    skip_locked=True
                ).get(session=session, user=partner)
            except SpeedNetworkingQueue.DoesNotExist:
                logger.error(f"[BOTH_MATCH] Queue entry not found for partner {partner.id}")
                return None

            if partner_queue.current_match is not None:
                logger.debug(f"[BOTH_MATCH] Partner {partner.id} was claimed by another thread")
                return None

            # Create Dyte room ID
            dyte_meeting_room = f"match-{session.id}-{uuid.uuid4().hex[:8]}"

            # Create match record with both systems' data
            match = SpeedNetworkingMatch.objects.create(
                session=session,
                participant_1=user,
                participant_2=partner,
                dyte_room_name=dyte_meeting_room,
                status='ACTIVE',
                match_score=score if 'score' in locals() else 0,
                match_breakdown=breakdown if 'breakdown' in locals() else {},
                rule_compliance=True  # Already validated by rule engine
            )

            # Update queue entries
            user_queue.current_match = match
            user_queue.save()

            partner_queue.current_match = match
            partner_queue.save()

            # Record match history (rule-based system)
            if session.matching_strategy in ['rule_only', 'both']:
                rule_engine.record_match_history(user, partner, match)

            match_data = SpeedNetworkingMatchSerializer(match).data

        # ===============================================================
        # STEP 4: EXTERNAL API CALLS (Dyte)
        # ===============================================================

        if match and match_data:
            # Create Dyte meeting
            meeting_id = create_dyte_meeting(match.dyte_room_name)
            real_meeting_id = meeting_id or match.dyte_room_name

            if meeting_id and meeting_id != match.dyte_room_name:
                match.dyte_room_name = meeting_id
                match.save(update_fields=["dyte_room_name"])

            # Add participants to Dyte
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
                logger.error(f"[BOTH_MATCH] Dyte P1 failed: {e}")

            try:
                p2_token, _ = add_dyte_participant(
                    real_meeting_id,
                    partner.id,
                    f"{partner.first_name} {partner.last_name}".strip() or partner.username,
                    DYTE_PRESET_PARTICIPANT
                )
            except Exception as e:
                logger.error(f"[BOTH_MATCH] Dyte P2 failed: {e}")

            # Notify both users
            p1_data = match_data.copy()
            if p1_token:
                p1_data['dyte_token'] = p1_token
            p1_data['match_score'] = score if 'score' in locals() else 0
            p1_data['match_breakdown'] = breakdown if 'breakdown' in locals() else {}

            send_speed_networking_user_message(user.id, 'speed_networking.match_found', {
                'match_id': match.id,
                'match': p1_data
            })

            p2_data = match_data.copy()
            if p2_token:
                p2_data['dyte_token'] = p2_token
            p2_data['match_score'] = score if 'score' in locals() else 0
            p2_data['match_breakdown'] = breakdown if 'breakdown' in locals() else {}

            send_speed_networking_user_message(partner.id, 'speed_networking.match_found', {
                'match_id': match.id,
                'match': p2_data
            })

            logger.info(f"[BOTH_MATCH] Successfully matched user {user.id} with {partner.id}")

        return match

    def _basic_match_from_candidates(self, session, user, candidate_pool):
        """
        Basic matching when criteria matching is not available.
        Used as fallback when user doesn't have criteria profile.
        """
        if not candidate_pool:
            logger.warning(f"[BOTH_MATCH] No candidates available for basic matching")
            return None

        # Handle both User objects and ID lists
        if candidate_pool and isinstance(candidate_pool[0], User):
            # Already User objects
            candidate = candidate_pool[0] if len(candidate_pool) > 0 else None
        else:
            # Get first available candidate by ID
            candidate = User.objects.filter(id__in=candidate_pool).first()

        if not candidate:
            logger.warning(f"[BOTH_MATCH] No candidate found for basic matching")
            return None

        logger.debug(f"[BOTH_MATCH] Using basic matching (no criteria profile) with user {candidate.id}")

        # Create match without criteria scoring
        dyte_meeting_room = f"match-{session.id}-{uuid.uuid4().hex[:8]}"

        try:
            with transaction.atomic():
                user_queue = SpeedNetworkingQueue.objects.select_for_update().get(
                    session=session,
                    user=user
                )

                if user_queue.current_match is not None:
                    return None

                partner_queue = SpeedNetworkingQueue.objects.select_for_update(
                    skip_locked=True
                ).get(session=session, user=candidate)

                if partner_queue.current_match is not None:
                    return None

                match = SpeedNetworkingMatch.objects.create(
                    session=session,
                    participant_1=user,
                    participant_2=candidate,
                    dyte_room_name=dyte_meeting_room,
                    status='ACTIVE',
                    match_score=50,  # Default score when no criteria profile
                    match_breakdown={'skill': 50, 'experience': 50, 'location': 50, 'education': 50},
                    rule_compliance=True
                )

                user_queue.current_match = match
                user_queue.save()

                partner_queue.current_match = match
                partner_queue.save()

                logger.info(f"[BOTH_MATCH] Basic match created: {user.id} <-> {candidate.id}")
                return match

        except Exception as e:
            logger.error(f"[BOTH_MATCH] Error creating basic match: {e}")
            return None

    def _build_user_profile_from_skills(self, user):
        """
        Build a profile dict for matching by reading from UserSkill directly.
        This avoids the need for UserCriteriaProfile duplication.

        Returns dict with keys: user_id, skills, experience_years, experience_level, etc.
        """
        from users.models import UserSkill, UserProfile, Experience, Education

        # Get skills from UserSkill model
        user_skills = UserSkill.objects.filter(user=user).select_related('skill')
        skills_list = [
            {
                'name': skill_obj.skill.preferred_label,
                'level': skill_obj.proficiency_level,
                'years': 5  # Default
            }
            for skill_obj in user_skills
        ]

        # Get user profile for location and basic data
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            user_profile = None

        # Get experience data
        try:
            user_experience = Experience.objects.filter(user=user).order_by('-start_date').first()
            if user_experience:
                experience_years = getattr(user_experience, 'years_of_experience', 0) or 0
                experience_level = 2  # Default mid-level
            else:
                experience_years = 0
                experience_level = 0
        except Exception:
            experience_years = 0
            experience_level = 0

        # Get education data
        try:
            user_education = Education.objects.filter(user=user).first()
            if user_education:
                education_degree = getattr(user_education, 'degree', '')
                education_field = getattr(user_education, 'field_of_study', '')
                education_institution = getattr(user_education, 'school', '')
                # Convert degree to numeric level for matching
                education_level = self._convert_degree_to_level(education_degree)
            else:
                education_degree = ''
                education_field = ''
                education_level = 1  # Default to Bachelor's level
                education_institution = ''
        except Exception:
            education_degree = ''
            education_field = ''
            education_level = 1  # Default to Bachelor's level
            education_institution = ''

        # Build profile dict in the format expected by matching engine
        profile_dict = {
            'user_id': user.id,
            'skills': skills_list,
            'experience_years': experience_years,
            'experience_level': experience_level,
            'location': {
                'city': getattr(user_profile, 'location', '') if user_profile else '',
                'country': '',  # Not directly available in UserProfile
                'lat': None,  # TODO: Implement geocoding to populate coordinates
                'lon': None,  # TODO: Implement geocoding to populate coordinates
                'timezone': getattr(user_profile, 'timezone', 'UTC') if user_profile else 'UTC',
            },
            'education': {
                'degree': education_degree,
                'field': education_field,
                'level': education_level,
                'institution': education_institution,
            },
            'preferred_match_type': 'any',
        }

        logger.debug(f"[PROFILE] Built profile for user {user.id} from UserSkill: {len(skills_list)} skills")
        return profile_dict

    def _convert_degree_to_level(self, degree_str):
        """
        Convert education degree string to numeric level for matching.

        Returns:
            int: 0=High School, 1=Bachelor's, 2=Master's, 3=PhD, 4=Professional Cert
        """
        if not degree_str:
            return 1  # Default to Bachelor's

        degree_lower = degree_str.lower()

        # PhD/Doctorate check
        if any(x in degree_lower for x in ['phd', 'doctorate', 'doctoral']):
            return 3

        # Master's check
        if any(x in degree_lower for x in ['master', 'masters', 'mba', 'ms', 'ma', 'msc']):
            return 2

        # Bachelor's check
        if any(x in degree_lower for x in ['bachelor', 'bachelors', 'b.s', 'b.a', 'bsc', 'ba', 'bs']):
            return 1

        # High School check
        if any(x in degree_lower for x in ['high school', 'secondary', 'hsc', '12th', 'diploma']):
            return 0

        # Professional cert check
        if any(x in degree_lower for x in ['professional', 'certification', 'cert', 'certificate']):
            return 4

        # Default to Bachelor's if no clear match
        return 1

    def _get_previous_match_partners(self, session, user):
        """
        Get all users that this user has already been matched with in the current session.

        Args:
            session: The speed networking session
            user: The user to find previous partners for

        Returns:
            List of User IDs that should be excluded from future matching
        """
        from django.db.models import Q

        # Find all matches (completed, skipped, or active) where this user was a participant
        previous_matches = SpeedNetworkingMatch.objects.filter(
            session=session,
            status__in=['ACTIVE', 'COMPLETED', 'SKIPPED']
        ).filter(
            Q(participant_1=user) | Q(participant_2=user)
        )

        # Extract all partners from previous matches
        previous_partners = set()
        for match in previous_matches:
            if match.participant_1 == user:
                previous_partners.add(match.participant_2.id)
            else:
                previous_partners.add(match.participant_1.id)

        logger.info(f"[MATCHING] User {user.id} has {len(previous_partners)} previous partners in session {session.id}: {previous_partners}")
        return list(previous_partners)

    def _get_criteria_config(self, session):
        """Get criteria configuration for session."""
        if session.criteria_config:
            return session.criteria_config

        # Return preset based on matching strategy
        if session.matching_strategy == 'criteria_only':
            # Default criteria-only config
            return CriteriaBasedMatchingEngine()._default_config()
        else:
            # For 'both' strategy, use balanced config
            return {
                'skill': {
                    'enabled': True,
                    'required': True,
                    'weight': 0.35,
                    'threshold': 40,
                    'match_mode': 'complementary'
                },
                'experience': {
                    'enabled': True,
                    'required': True,
                    'weight': 0.30,
                    'threshold': 50,
                    'match_type': 'mentorship'
                },
                'location': {
                    'enabled': True,
                    'required': False,
                    'weight': 0.20,
                    'threshold': 30,
                    'match_strategy': 'radius'
                },
                'education': {
                    'enabled': True,
                    'required': False,
                    'weight': 0.15,
                    'threshold': 40,
                    'match_type': 'complementary_fields'
                }
            }
