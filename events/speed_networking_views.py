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
from users.serializers import UserMiniSerializer
from .utils import (
    create_dyte_meeting,
    add_dyte_participant,
    send_speed_networking_message,
    send_speed_networking_user_message,
    DYTE_PRESET_PARTICIPANT
)

logger = logging.getLogger(__name__)

CRITERIA_KEYS = {'skill', 'experience', 'location', 'education'}
ADVANCED_CONFIG_KEYS = {'random_factor', 'prefer_new_users'}
ALLOWED_CRITERIA_CONFIG_KEYS = CRITERIA_KEYS | ADVANCED_CONFIG_KEYS


# ============================================================================
# Module-level helper functions for use in both ViewSets
# ============================================================================

def _get_criteria_config(session):
    """Get criteria configuration for session with proper defaults."""
    if session.criteria_config:
        return session.criteria_config

    # Return default config based on matching strategy
    if session.matching_strategy == 'criteria_only':
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
            },
            'random_factor': 0.1,
            'prefer_new_users': True
        }
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
            },
            'random_factor': 0.1,
            'prefer_new_users': True
        }


def _build_user_profile_from_skills(user):
    """
    Build a profile dict for matching by reading from UserSkill directly.

    Returns dict with keys: user_id, skills, experience_years, experience_level, etc.
    """
    from users.models import UserSkill, UserProfile, Experience, Education

    # Get skills from UserSkill model using the related name
    skills_query = user.user_skills.select_related('skill')
    skills_list = [
        {
            'name': skill_obj.skill.preferred_label,
            'level': skill_obj.proficiency_level,
            'years': 5  # Default
        }
        for skill_obj in skills_query
    ]

    # Get user profile for location and basic data
    user_profile = user.profile if hasattr(user, 'profile') else None

    # Get experience data
    user_experience = user.experiences.order_by('-start_date').first() if hasattr(user, 'experiences') else None
    if user_experience:
        experience_years = getattr(user_experience, 'years_of_experience', 0) or 0
        experience_level = 2  # Default mid-level
    else:
        experience_years = 0
        experience_level = 0

    # Get education data
    user_education = user.educations.first() if hasattr(user, 'educations') else None
    if user_education:
        education_degree = getattr(user_education, 'degree', '')
        education_field = getattr(user_education, 'field_of_study', '')
        education_institution = getattr(user_education, 'school', '')
        # Convert degree to numeric level for matching
        education_level = _convert_degree_to_level(education_degree)
    else:
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
            'country': '',
            'lat': None,
            'lon': None,
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


def _convert_degree_to_level(degree_str):
    """
    Convert education degree string to numeric level for matching.

    Returns:
        int: 0=High School, 1=Bachelor's, 2=Master's, 3=PhD, 4=Professional Cert
    """
    if not degree_str:
        return 1  # Default to Bachelor's

    degree_lower = degree_str.lower()

    if any(x in degree_lower for x in ['phd', 'doctorate', 'doctoral']):
        return 3
    if any(x in degree_lower for x in ['master', 'masters', 'mba', 'ms', 'ma', 'msc']):
        return 2
    if any(x in degree_lower for x in ['bachelor', 'bachelors', 'b.s', 'b.a', 'bsc', 'ba', 'bs']):
        return 1
    if any(x in degree_lower for x in ['high school', 'secondary', 'hsc', '12th', 'diploma']):
        return 0
    if any(x in degree_lower for x in ['professional', 'certification', 'cert', 'certificate']):
        return 4

    return 1


def _calculate_match_probability(score: float) -> float:
    """
    Convert raw score (0-100) to match probability (0-100).

    Logic:
    - 0-50: Linear (0% to 50%)
    - 50-75: Steep gradient (50% to 75%) - threshold crossing boost
    - 75-100: Linear (75% to 100%)

    Args:
        score: Raw score 0-100

    Returns:
        Probability 0-100
    """
    if score < 50:
        probability = score / 100
    elif score < 75:
        probability = 0.5 + (score - 50) / 100
    else:
        probability = 0.75 + (score - 75) / 100

    return min(100, probability * 100)


def _build_user_profiles_bulk(user_ids):
    """
    Build profiles for multiple users in ONE bulk operation (10x faster than one-by-one).

    Uses Django's Prefetch to load all related data efficiently:
    - All UserSkill records with related Skill objects
    - UserProfile for location/timezone
    - Experience for years_of_experience
    - Education for degree/field

    Performance improvement:
    - 100 users: 100+ queries → 2-3 queries (50x faster)
    - 500 users: 500+ queries → 2-3 queries (250x faster)

    Args:
        user_ids: List of user IDs to build profiles for

    Returns:
        dict: {user_id: profile_dict, ...}
    """
    from django.db.models import Prefetch
    from django.contrib.auth.models import User as DjangoUser
    from users.models import UserSkill, UserProfile, Experience, Education

    if not user_ids:
        return {}

    # Bulk fetch all users with prefetched relations (2-3 queries total)
    users = DjangoUser.objects.filter(id__in=user_ids).prefetch_related(
        Prefetch(
            'user_skills',
            queryset=UserSkill.objects.select_related('skill')
        ),
        Prefetch('experiences'),
        Prefetch('educations'),
    ).select_related('profile')

    profiles_dict = {}

    for user in users:
        # Extract skills from prefetched relations (no additional queries)
        skills_list = [
            {
                'name': skill_obj.skill.preferred_label,
                'level': skill_obj.proficiency_level,
                'years': 5  # Default
            }
            for skill_obj in user.user_skills.all()
        ]

        # Get user profile from prefetch
        user_profile = user.profile if hasattr(user, 'profile') else None

        # Get experience data from prefetch
        experience_records = list(user.experiences.all()) if hasattr(user, 'experiences') else []
        if experience_records:
            experience_records.sort(key=lambda x: getattr(x, 'start_date', None) or timezone.now(), reverse=True)

        if experience_records:
            user_experience = experience_records[0]
            experience_years = getattr(user_experience, 'years_of_experience', 0) or 0
            experience_level = 2  # Default mid-level
        else:
            experience_years = 0
            experience_level = 0

        # Get education data from prefetch
        education_records = list(user.educations.all()) if hasattr(user, 'educations') else []

        if education_records:
            user_education = education_records[0]
            education_degree = getattr(user_education, 'degree', '')
            education_field = getattr(user_education, 'field_of_study', '')
            education_institution = getattr(user_education, 'school', '')
            education_level = _convert_degree_to_level(education_degree)
        else:
            education_degree = ''
            education_field = ''
            education_level = 1
            education_institution = ''

        # Build profile dict
        profile_dict = {
            'user_id': user.id,
            'skills': skills_list,
            'experience_years': experience_years,
            'experience_level': experience_level,
            'location': {
                'city': getattr(user_profile, 'location', '') if user_profile else '',
                'country': '',
                'lat': None,
                'lon': None,
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

        profiles_dict[user.id] = profile_dict

    logger.info(f"[BULK_PROFILES] Built {len(profiles_dict)} profiles in 2-3 queries (vs {len(user_ids)}+ individual queries)")
    return profiles_dict


def _broadcast_queue_update(session, event_id):
    """Broadcast current queue state to all clients in the event group (for host panel)."""
    # Count ALL active queue entries (both waiting and in active matches)
    queue_count = session.queue.filter(is_active=True).count()
    active_matches = session.matches.filter(status='ACTIVE').count()

    logger.info(f"[BROADCAST_QUEUE_UPDATE] Event {event_id}, Session {session.id}: queue_count={queue_count}, active_matches={active_matches}")
    print(f"[BROADCAST_QUEUE_UPDATE] Event {event_id}, Session {session.id}: queue_count={queue_count}, active_matches={active_matches}")

    send_speed_networking_message(event_id, 'speed_networking.queue_update', {
        'queue_count': queue_count,
        'active_matches_count': active_matches,
    })

    logger.info(f"[BROADCAST_QUEUE_UPDATE] Message sent to event group: event_{event_id}")


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
            'session_name': session.name,
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

    @action(detail=True, methods=['patch'])
    def update_criteria(self, request, event_id=None, pk=None):
        """Update matching criteria configuration (allowed during ACTIVE sessions)."""
        session = self.get_object()

        if session.status == 'ENDED':
            return Response(
                {'error': 'Cannot update criteria on ended sessions'},
                status=status.HTTP_400_BAD_REQUEST
            )

        criteria_config = request.data.get('criteria_config', {})
        if not isinstance(criteria_config, dict):
            return Response(
                {'error': 'criteria_config must be an object'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate structure
        unknown_keys = sorted(set(criteria_config.keys()) - ALLOWED_CRITERIA_CONFIG_KEYS)
        if unknown_keys:
            allowed_keys = ', '.join(sorted(ALLOWED_CRITERIA_CONFIG_KEYS))
            return Response(
                {
                    'error': (
                        f"Invalid criteria config key(s): {', '.join(unknown_keys)}. "
                        f"Allowed keys: {allowed_keys}"
                    )
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate each criterion has required fields
        for criterion, config in criteria_config.items():
            if criterion not in CRITERIA_KEYS:
                continue
            if not isinstance(config, dict):
                return Response(
                    {'error': f'Criterion {criterion} config must be a dict'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate weights are floats 0-1
            if 'weight' in config:
                try:
                    weight = float(config['weight'])
                    if not (0 <= weight <= 1):
                        return Response(
                            {'error': f'Weight for {criterion} must be between 0 and 1'},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                except (TypeError, ValueError):
                    return Response(
                        {'error': f'Weight for {criterion} must be a number'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Validate thresholds are ints 0-100
            if 'threshold' in config:
                try:
                    threshold = int(config['threshold'])
                    if not (0 <= threshold <= 100):
                        return Response(
                            {'error': f'Threshold for {criterion} must be between 0 and 100'},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                except (TypeError, ValueError):
                    return Response(
                        {'error': f'Threshold for {criterion} must be an integer'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

        if 'random_factor' in criteria_config:
            try:
                random_factor = float(criteria_config['random_factor'])
                if not (0 <= random_factor <= 0.3):
                    return Response(
                        {'error': 'random_factor must be between 0 and 0.3'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except (TypeError, ValueError):
                return Response(
                    {'error': 'random_factor must be a number'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        if 'prefer_new_users' in criteria_config and not isinstance(criteria_config['prefer_new_users'], bool):
            return Response(
                {'error': 'prefer_new_users must be a boolean'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update session and increment config version
        session.criteria_config = criteria_config
        session.config_version = (session.config_version or 0) + 1
        session.save(update_fields=['criteria_config', 'config_version'])

        logger.info(f"[UPDATE_CRITERIA] Session {session.id} criteria updated to v{session.config_version}: {criteria_config}")

        # Mark all active/pending matches for recalculation
        session.matches.filter(
            status__in=['ACTIVE', 'COMPLETED']
        ).update(config_version=0)  # 0 = needs recalculation

        logger.info(f"[UPDATE_CRITERIA] Marked matches for recalculation with new config v{session.config_version}")

        # Broadcast config update to all clients via WebSocket
        send_speed_networking_message(event_id, 'speed_networking.config_updated', {
            'session_id': session.id,
            'config_version': session.config_version,
            'criteria_config': session.criteria_config,
            'updated_at': timezone.now().isoformat(),
            'message': 'Matching criteria have been updated. Preview will refresh automatically.'
        })
        logger.info(f"[UPDATE_CRITERIA] WebSocket broadcast sent for event {event_id}: config v{session.config_version}")

        return Response({
            'criteria_config': session.criteria_config,
            'config_version': session.config_version,
            'message': 'Settings updated. New matches will use these factors immediately.'
        })

    @action(detail=True, methods=['post'])
    def test_match_score(self, request, event_id=None, pk=None):
        """
        Preview match score for two specific users with current criteria config.
        Useful for admins to test settings before applying to live session.

        Request body:
        {
            'user_a_id': int,
            'user_b_id': int
        }

        Response:
        {
            'user_a': {...},
            'user_b': {...},
            'score': 75.5,
            'probability': 78.2,
            'breakdown': {'skill': 85, 'experience': 70, ...},
            'is_valid': true,
            'config_version': 1
        }
        """
        from django.contrib.auth.models import User as DjangoUser

        session = self.get_object()

        if session.status != 'ACTIVE':
            return Response(
                {'error': 'Session is not active'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user_a_id = request.data.get('user_a_id')
        user_b_id = request.data.get('user_b_id')

        if not user_a_id or not user_b_id:
            return Response(
                {'error': 'Both user_a_id and user_b_id are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Use bulk loading for consistency (even for 2 users, it's a single prefetch query)
        profiles = _build_user_profiles_bulk([user_a_id, user_b_id])

        if user_a_id not in profiles or user_b_id not in profiles:
            return Response(
                {'error': 'One or both users not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        profile_a = profiles[user_a_id]
        profile_b = profiles[user_b_id]

        # Get user objects for serialization
        try:
            user_a = DjangoUser.objects.get(id=user_a_id)
            user_b = DjangoUser.objects.get(id=user_b_id)
        except DjangoUser.DoesNotExist:
            return Response(
                {'error': 'One or both users not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Get current criteria config
        config = _get_criteria_config(session)
        engine = CriteriaBasedMatchingEngine(session, config)

        # Calculate combined score
        score, breakdown, is_valid = engine.calculate_combined_score(profile_a, profile_b)

        # Calculate probability
        probability = _calculate_match_probability(score)

        logger.info(f"[TEST_MATCH_SCORE] Session {session.id}: "
                   f"User {user_a_id} vs {user_b_id} = {score:.1f} score, {probability:.0f}% probability")

        return Response({
            'user_a': {
                'id': user_a.id,
                'name': user_a.get_full_name() or user_a.username,
                'avatar_url': user_a.profile.user_image.url if hasattr(user_a, 'profile') and user_a.profile.user_image else None
            },
            'user_b': {
                'id': user_b.id,
                'name': user_b.get_full_name() or user_b.username,
                'avatar_url': user_b.profile.user_image.url if hasattr(user_b, 'profile') and user_b.profile.user_image else None
            },
            'score': round(score, 1),
            'probability': round(probability, 1),
            'breakdown': {k: round(v, 1) for k, v in breakdown.items()},
            'is_valid': is_valid,
            'config_version': session.config_version,
            'message': 'Match test completed with current criteria config'
        })

    @action(detail=True, methods=['get'])
    def match_preview(self, request, event_id=None, pk=None):
        """
        Preview match quality and rates for current waiting queue.

        Returns:
        {
            'total_waiting': int,           # Number of users waiting for matches
            'potential_pairs': int,         # C(n, 2) combinations
            'matchable_pairs': int,         # Pairs that pass threshold with current config
            'match_rate': float,            # Percentage of pairs that are matchable
            'avg_score': float,             # Average match score among all pairs
            'score_distribution': {         # Count of pairs in each score bucket
                '0-25': int,
                '26-50': int,
                '51-75': int,
                '76-100': int
            }
        }
        """
        session = self.get_object()

        if session.status != 'ACTIVE':
            return Response(
                {'error': 'Session is not active'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get all waiting queue entries
        all_queue_entries = session.queue.all()
        waiting_entries = session.queue.filter(is_active=True, current_match__isnull=True)
        waiting_users = list(waiting_entries.values_list('user_id', flat=True))
        total_waiting = len(waiting_users)

        logger.info(
            f"[MATCH_PREVIEW] Session {session.id}: Total queue entries: {all_queue_entries.count()}, "
            f"Active: {session.queue.filter(is_active=True).count()}, "
            f"Waiting (no current_match): {total_waiting}"
        )

        # If less than 2 users waiting, no pairs possible
        if total_waiting < 2:
            return Response({
                'total_waiting': total_waiting,
                'potential_pairs': 0,
                'matchable_pairs': 0,
                'match_rate': 0.0,
                'avg_score': 0.0,
                'score_distribution': {'0-25': 0, '26-50': 0, '51-75': 0, '76-100': 0}
            })

        # Cap at 50 users for performance (C(50,2) = 1225 pairs)
        if total_waiting > 50:
            logger.warning(f"[MATCH_PREVIEW] Capping {total_waiting} waiting users to 50 for preview")
            waiting_users = waiting_users[:50]
            total_waiting = 50

        # Get user objects and build profiles in bulk (2-3 queries vs N+1)
        user_profiles = _build_user_profiles_bulk(waiting_users)

        # Initialize criteria engine with current config
        criteria_config = _get_criteria_config(session)
        criteria_engine = CriteriaBasedMatchingEngine(session, criteria_config)

        # Calculate scores for all unique pairs
        all_scores = []
        matchable_count = 0
        potential_pairs = len(waiting_users) * (len(waiting_users) - 1) // 2

        for i in range(len(waiting_users)):
            for j in range(i + 1, len(waiting_users)):
                user_a_id = waiting_users[i]
                user_b_id = waiting_users[j]

                profile_a = user_profiles.get(user_a_id)
                profile_b = user_profiles.get(user_b_id)

                if profile_a and profile_b:
                    score, breakdown, is_valid = criteria_engine.calculate_combined_score(
                        profile_a, profile_b
                    )
                    all_scores.append({
                        'score': score,
                        'is_valid': is_valid
                    })

                    if is_valid:
                        matchable_count += 1

        # Calculate statistics
        avg_score = sum(s['score'] for s in all_scores) / len(all_scores) if all_scores else 0
        match_rate = (matchable_count / potential_pairs * 100) if potential_pairs > 0 else 0

        # Score distribution
        score_distribution = {'0-25': 0, '26-50': 0, '51-75': 0, '76-100': 0}
        for score_data in all_scores:
            score = score_data['score']
            if score <= 25:
                score_distribution['0-25'] += 1
            elif score <= 50:
                score_distribution['26-50'] += 1
            elif score <= 75:
                score_distribution['51-75'] += 1
            else:
                score_distribution['76-100'] += 1

        logger.info(
            f"[MATCH_PREVIEW] Session {session.id}: "
            f"waiting={total_waiting}, matchable={matchable_count}/{potential_pairs}, "
            f"rate={match_rate:.1f}%, avg_score={avg_score:.1f}"
        )

        return Response({
            'total_waiting': total_waiting,
            'potential_pairs': potential_pairs,
            'matchable_pairs': matchable_count,
            'match_rate': round(match_rate, 1),
            'avg_score': round(avg_score, 1),
            'score_distribution': score_distribution
        })

    @action(detail=True, methods=['post'])
    def recalculate_matches(self, request, event_id=None, pk=None):
        """
        Manually trigger recalculation of stale matches.

        Useful for:
        - Testing recalculation logic
        - Admin debugging
        - Forcing immediate update after config change

        Returns count of recalculated matches.
        """
        from django.db.models import F

        session = self.get_object()

        if session.status != 'ACTIVE':
            return Response(
                {'error': 'Session is not active'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Find stale matches
        stale_matches = session.matches.filter(
            config_version__lt=F('session__config_version'),
            status__in=['ACTIVE', 'PENDING']
        )

        if not stale_matches.exists():
            return Response({
                'status': 'no_stale_matches',
                'message': 'All matches are up-to-date'
            })

        recalculated_count = 0
        error_count = 0

        for match in stale_matches:
            try:
                # Rebuild profiles
                profiles = _build_user_profiles_bulk([match.participant_1.id, match.participant_2.id])

                if match.participant_1.id not in profiles or match.participant_2.id not in profiles:
                    error_count += 1
                    continue

                profile_a = profiles[match.participant_1.id]
                profile_b = profiles[match.participant_2.id]

                # Get current config
                config = _get_criteria_config(session)
                engine = CriteriaBasedMatchingEngine(session, config)

                # Recalculate
                score, breakdown, is_valid = engine.calculate_combined_score(profile_a, profile_b)

                # Update match
                match.match_score = score
                match.match_breakdown = breakdown
                match.match_probability = _calculate_match_probability(score)
                match.config_version = session.config_version
                match.last_recalculated_at = timezone.now()
                match.save()

                recalculated_count += 1
                logger.info(f"[MANUAL_RECALC] Match {match.id}: {score:.1f} (v{session.config_version})")

            except Exception as e:
                error_count += 1
                logger.error(f"[MANUAL_RECALC] Failed match {match.id}: {e}")
                continue

        logger.info(f"[MANUAL_RECALC] Session {session.id}: {recalculated_count} done, {error_count} failed")

        return Response({
            'status': 'completed',
            'recalculated': recalculated_count,
            'errors': error_count,
            'session_config_version': session.config_version,
            'message': f'Recalculated {recalculated_count} matches (config v{session.config_version})'
        })

    @action(detail=True, methods=['get'])
    def suggest_weights(self, request, event_id=None, pk=None):
        """
        Analyze completed matches and suggest optimal criteria weights.

        GET /api/events/{event_id}/speed-networking/{session_id}/suggest_weights/

        Analyzes all completed matches in the session to identify which criteria
        (skill, experience, location, education) correlate most with successful matches.
        Returns suggested weight distribution based on correlation analysis.

        Success is defined as: Match completed + Duration > 5 minutes

        Response:
        {
            'suggested_weights': {
                'skill': 0.25,
                'experience': 0.30,
                'location': 0.20,
                'education': 0.25
            },
            'correlations': {
                'skill': 0.65,
                'experience': 0.72,
                'location': 0.45,
                'education': 0.55
            },
            'matches_analyzed': 42,
            'success_rate': 78.6,
            'avg_score': 72.4,
            'avg_duration': 450.2,
            'confidence': 'high'  # high (>50), medium (20-50), low (<20)
        }

        Returns 400 Bad Request if:
        - Less than 5 completed matches found (insufficient data)
        - No matches found for analysis
        """
        from .ml_optimizer import MatchingAnalyzer

        session = self.get_object()

        # Run analyzer
        analyzer = MatchingAnalyzer()
        suggestions = analyzer.analyze_session(session)

        if not suggestions:
            logger.warning(
                f"[ML_API] Not enough data to analyze session {session.id}. "
                f"Need at least 5 completed matches."
            )
            return Response({
                'error': 'Not enough completed matches to analyze',
                'suggestion': 'Run the session longer and come back when you have at least 5 completed matches',
                'current_completed': session.matches.filter(
                    status='COMPLETED',
                    ended_at__isnull=False
                ).count(),
                'current_total': session.matches.count()
            }, status=status.HTTP_400_BAD_REQUEST)

        logger.info(
            f"[ML_API] Weights suggested for session {session.id}: "
            f"{len(suggestions['suggested_weights'])} criteria analyzed"
        )

        return Response(suggestions)

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

    @action(detail=True, methods=['get'])
    def queue(self, request, event_id=None, pk=None):
        """Get list of all active queue entries (host only)."""
        session = self.get_object()
        queue_entries = session.queue.filter(is_active=True).select_related(
            'user', 'current_match', 'current_match__participant_1', 'current_match__participant_2'
        ).order_by('joined_at')
        serializer = SpeedNetworkingQueueSerializer(queue_entries, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='remove-from-queue/(?P<user_id>[^/.]+)')
    def remove_from_queue(self, request, event_id=None, pk=None, user_id=None):
        """Host removes a specific user from the queue."""
        session = self.get_object()
        try:
            queue_entry = SpeedNetworkingQueue.objects.get(
                session=session, user_id=user_id, is_active=True
            )
        except SpeedNetworkingQueue.DoesNotExist:
            return Response({'error': 'User not in queue'}, status=status.HTTP_404_NOT_FOUND)

        # End their current match if any
        if queue_entry.current_match and queue_entry.current_match.status == 'ACTIVE':
            match = queue_entry.current_match
            match.status = 'COMPLETED'
            match.ended_at = timezone.now()
            match.save()
            partner = match.participant_1 if match.participant_2_id == int(user_id) else match.participant_2
            send_speed_networking_user_message(partner.id, 'speed_networking.match_ended', {
                'message': 'Your partner was removed from the session.'
            })
            SpeedNetworkingQueue.objects.filter(session=session, user=partner).update(current_match=None)

        queue_entry.is_active = False
        queue_entry.current_match = None
        queue_entry.save()

        # Broadcast queue update to all hosts
        _broadcast_queue_update(session, event_id)

        return Response({'message': 'User removed from queue'})


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

        # Broadcast queue update to all clients (for host panel)
        _broadcast_queue_update(session, event_id)

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

        session = queue_entry.session

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

        # Broadcast queue update to all clients (for host panel)
        _broadcast_queue_update(session, event_id)

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

            # Verify the queue entries were actually cleared (defensive check)
            p1_queue = SpeedNetworkingQueue.objects.get(session=match.session, user=match.participant_1)
            p2_queue = SpeedNetworkingQueue.objects.get(session=match.session, user=match.participant_2)
            logger.info(f"[NEXT_MATCH] P1 queue cleared: {p1_queue.current_match is None}, P2 queue cleared: {p2_queue.current_match is None}")

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

            logger.info(f"[NEXT_MATCH] New match creation result: P1={new_match_1.id if new_match_1 else None}, P2={new_match_2.id if new_match_2 else None}")

            # Verify queue entries are properly updated with new matches
            p1_queue = SpeedNetworkingQueue.objects.get(session=session, user=match.participant_1)
            p2_queue = SpeedNetworkingQueue.objects.get(session=session, user=match.participant_2)
            logger.info(f"[NEXT_MATCH] Queue entries updated: P1.current_match={p1_queue.current_match_id}, P2.current_match={p2_queue.current_match_id}")

            # Broadcast queue update to all clients (for host panel)
            _broadcast_queue_update(session, event_id)

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
            user_profile_dict = _build_user_profile_from_skills(user)

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
                _build_user_profile_from_skills(candidate)
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
            criteria_config = _get_criteria_config(session)
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

            # Calculate probability from score
            calculated_score = score if 'score' in locals() else 0
            calculated_breakdown = breakdown if 'breakdown' in locals() else {}
            calculated_probability = _calculate_match_probability(calculated_score)

            # Create match record with both systems' data
            match = SpeedNetworkingMatch.objects.create(
                session=session,
                participant_1=user,
                participant_2=partner,
                dyte_room_name=dyte_meeting_room,
                status='ACTIVE',
                match_score=calculated_score,
                match_breakdown=calculated_breakdown,
                match_probability=calculated_probability,  # NEW
                config_version=session.config_version,  # NEW
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
                    match_probability=50,  # NEW: 50% default probability
                    config_version=session.config_version,  # NEW
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


    @action(detail=False, methods=['get'])
    def user_matches(self, request, event_id=None, session_id=None):
        """Get all completed matches for current user in a speed networking session."""
        try:
            session = SpeedNetworkingSession.objects.get(id=session_id, event_id=event_id)
        except SpeedNetworkingSession.DoesNotExist:
            return Response(
                {'error': 'Session not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        user = request.user

        # Get all completed/skipped matches where user is a participant
        matches = SpeedNetworkingMatch.objects.filter(
            session=session,
            status__in=['COMPLETED', 'SKIPPED']
        ).filter(
            Q(participant_1=user) | Q(participant_2=user)
        ).select_related('participant_1', 'participant_2').order_by('-ended_at')

        # Build response with partner info
        user_matches_data = []
        for match in matches:
            partner = match.participant_2 if match.participant_1 == user else match.participant_1

            # Use UserMiniSerializer to get avatar_url with proper context
            partner_serializer = UserMiniSerializer(partner, context={'request': request})

            user_matches_data.append({
                'match_id': match.id,
                'partner': partner_serializer.data,
                'status': match.status,
                'duration_seconds': (match.ended_at - match.created_at).total_seconds() if match.ended_at and match.created_at else 0,
                'started_at': match.created_at,
                'ended_at': match.ended_at,
                'match_score': match.match_score,
            })

        return Response({
            'session_id': session.id,
            'session_name': session.name,
            'total_matches': len(user_matches_data),
            'matches': user_matches_data
        })

    @action(detail=True, methods=['post'])
    def start_config_comparison(self, request, event_id=None, pk=None):
        """
        Start a comparison test between two matching configurations.
        Users are deterministically bucketed into Config A or Config B based on their ID.

        Request body:
        {
            'comparison_name': 'string (optional)',
            'config_a': {'skill': 0.25, 'experience': 0.25, 'location': 0.25, 'education': 0.25},
            'config_b': {'skill': 0.30, 'experience': 0.20, 'location': 0.25, 'education': 0.25},
            'split_ratio': 0.5  # Optional, default 0.5 (50/50 split)
        }

        Response:
        {
            'comparison_id': 'session_id',
            'comparison_name': 'string',
            'status': 'running',
            'config_a': {...},
            'config_b': {...},
            'split_ratio': 0.5,
            'started_at': ISO8601,
            'message': 'Configuration comparison started successfully'
        }
        """
        from .ab_testing import ABTest

        session = self.get_object()

        if session.status != 'ACTIVE':
            return Response(
                {'error': 'Session is not active'},
                status=status.HTTP_400_BAD_REQUEST
            )

        comparison_name = request.data.get('comparison_name', f'Config_Comparison_{session.id}')
        config_a = request.data.get('config_a')
        config_b = request.data.get('config_b')
        split_ratio = request.data.get('split_ratio', 0.5)

        if not config_a or not config_b:
            return Response(
                {'error': 'Both config_a and config_b are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate configurations
        is_valid, error_msg = ABTest.validate_configs(config_a, config_b)
        if not is_valid:
            return Response(
                {'error': error_msg},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate split ratio
        try:
            split_ratio = float(split_ratio)
            if not (0 < split_ratio < 1):
                return Response(
                    {'error': 'split_ratio must be between 0 and 1 (exclusive)'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except (TypeError, ValueError):
            return Response(
                {'error': 'split_ratio must be a number'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create ABTest instance for validation
        ab_test = ABTest(session, config_a, config_b, split_ratio)

        # Store comparison metadata in session
        session.ab_test_data = {
            'comparison_id': session.id,
            'comparison_name': comparison_name,
            'status': 'running',
            'config_a': config_a,
            'config_b': config_b,
            'split_ratio': split_ratio,
            'started_at': timezone.now().isoformat(),
            'created_by': request.user.id
        }
        session.save(update_fields=['ab_test_data'])

        logger.info(
            f"[CONFIG_COMPARISON] Comparison started for session {session.id}: "
            f"name={comparison_name}, split={split_ratio:.0%}, "
            f"criteria_validated"
        )

        return Response({
            'comparison_id': session.id,
            'comparison_name': comparison_name,
            'status': 'running',
            'config_a': config_a,
            'config_b': config_b,
            'split_ratio': split_ratio,
            'started_at': timezone.now().isoformat(),
            'message': 'Configuration comparison started successfully'
        }, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['get'])
    def get_comparison_results(self, request, event_id=None, pk=None):
        """
        Get current results of a running configuration comparison.

        Response:
        {
            'comparison_id': 'session_id',
            'comparison_name': 'string',
            'status': 'running',
            'current_metrics': {
                'config_a_score': 75.5,
                'config_b_score': 72.3,
                'winner': 'a',
                'improvement_percent': 4.4,
                'config_a_stats': {...},
                'config_b_stats': {...},
                'recommendation': 'Config A performing better...'
            },
            'matches_analyzed': {
                'total': 42,
                'config_a': 21,
                'config_b': 21
            },
            'comparison_duration_seconds': 3600
        }
        """
        from .ab_testing import ABTest

        session = self.get_object()

        if not session.ab_test_data or session.ab_test_data.get('status') != 'running':
            return Response(
                {'error': 'No active configuration comparison for this session'},
                status=status.HTTP_400_BAD_REQUEST
            )

        test_data = session.ab_test_data
        config_a = test_data.get('config_a')
        config_b = test_data.get('config_b')
        split_ratio = test_data.get('split_ratio', 0.5)

        # Recreate ABTest instance for analysis
        ab_test = ABTest(session, config_a, config_b, split_ratio)

        # Get matches and bucket them by config
        all_matches = session.matches.filter(status__in=['COMPLETED', 'SKIPPED']).select_related(
            'participant_1', 'participant_2'
        )

        matches_config_a = []
        matches_config_b = []

        for match in all_matches:
            # Determine which config this match belongs to based on user bucketing
            config, bucket = ab_test.get_config_for_user(match.participant_1.id)
            if bucket == 'A':
                matches_config_a.append(match)
            else:
                matches_config_b.append(match)

        # Calculate metrics for both configurations
        metrics = ab_test.measure_success(matches_config_a, matches_config_b)

        if not metrics:
            return Response({
                'comparison_id': session.id,
                'comparison_name': test_data.get('comparison_name'),
                'status': 'running',
                'current_metrics': None,
                'matches_analyzed': {
                    'total': 0,
                    'config_a': 0,
                    'config_b': 0
                },
                'message': 'Insufficient match data to analyze yet'
            })

        # Calculate elapsed time
        started_at = timezone.datetime.fromisoformat(test_data['started_at'])
        elapsed_seconds = (timezone.now() - started_at).total_seconds()

        logger.info(
            f"[CONFIG_COMPARISON] Results retrieved for session {session.id}: "
            f"Config_A={metrics['score_a']:.1f}, Config_B={metrics['score_b']:.1f}, "
            f"winner={metrics['winner']}, improvement={metrics['improvement']:.1f}%"
        )

        return Response({
            'comparison_id': session.id,
            'comparison_name': test_data.get('comparison_name'),
            'status': 'running',
            'current_metrics': {
                'config_a_score': metrics['score_a'],
                'config_b_score': metrics['score_b'],
                'winner': metrics['winner'],
                'improvement_percent': metrics['improvement'],
                'config_a_stats': metrics['metrics_a'],
                'config_b_stats': metrics['metrics_b'],
                'recommendation': metrics['recommendation']
            },
            'matches_analyzed': {
                'total': len(all_matches),
                'config_a': len(matches_config_a),
                'config_b': len(matches_config_b)
            },
            'comparison_duration_seconds': elapsed_seconds
        })

    @action(detail=True, methods=['post'])
    def finalize_comparison(self, request, event_id=None, pk=None):
        """
        Finalize the configuration comparison and get final results with recommendation.

        Response:
        {
            'comparison_id': 'session_id',
            'comparison_name': 'string',
            'status': 'completed',
            'final_metrics': {
                'config_a_score': 75.5,
                'config_b_score': 72.3,
                'winner': 'a',
                'improvement_percent': 4.4,
                'config_a_stats': {...},
                'config_b_stats': {...},
                'recommendation': 'Config A performing better...'
            },
            'total_matches_analyzed': 42,
            'comparison_duration_seconds': 3600,
            'action_recommended': 'Switch to Config A (4.4% improvement)',
            'confidence_level': 'high'
        }
        """
        from .ab_testing import ABTest

        session = self.get_object()

        if not session.ab_test_data or session.ab_test_data.get('status') != 'running':
            return Response(
                {'error': 'No active configuration comparison for this session'},
                status=status.HTTP_400_BAD_REQUEST
            )

        test_data = session.ab_test_data
        config_a = test_data.get('config_a')
        config_b = test_data.get('config_b')
        split_ratio = test_data.get('split_ratio', 0.5)

        # Recreate ABTest instance for final analysis
        ab_test = ABTest(session, config_a, config_b, split_ratio)

        # Get all completed matches for final analysis
        all_matches = session.matches.filter(status__in=['COMPLETED', 'SKIPPED']).select_related(
            'participant_1', 'participant_2'
        )

        if not all_matches.exists():
            return Response({
                'error': 'No completed matches to analyze',
                'suggestion': 'Complete more matches before finalizing the comparison'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Bucket matches by configuration
        matches_config_a = []
        matches_config_b = []

        for match in all_matches:
            config, bucket = ab_test.get_config_for_user(match.participant_1.id)
            if bucket == 'A':
                matches_config_a.append(match)
            else:
                matches_config_b.append(match)

        # Calculate final metrics
        metrics = ab_test.measure_success(matches_config_a, matches_config_b)

        if not metrics:
            return Response({
                'error': 'Insufficient data to finalize comparison',
                'suggestion': 'Need more completed matches for reliable analysis (recommend 20+)'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Generate actionable recommendation
        winner = metrics['winner']
        improvement = metrics['improvement']

        if winner == 'a':
            if improvement > 15:
                action = f"Switch to Config A ({improvement:.1f}% improvement) - Strong advantage"
                confidence = 'high'
            elif improvement > 5:
                action = f"Switch to Config A ({improvement:.1f}% improvement)"
                confidence = 'medium'
            else:
                action = f"Config A slightly better ({improvement:.1f}%) - Run more tests for confidence"
                confidence = 'low'
        elif winner == 'b':
            if improvement > 15:
                action = f"Switch to Config B ({improvement:.1f}% improvement) - Strong advantage"
                confidence = 'high'
            elif improvement > 5:
                action = f"Switch to Config B ({improvement:.1f}% improvement)"
                confidence = 'medium'
            else:
                action = f"Config B slightly better ({improvement:.1f}%) - Run more tests for confidence"
                confidence = 'low'
        else:
            action = "No significant difference - Either config performs equally well"
            confidence = 'medium'

        # Calculate elapsed time
        started_at = timezone.datetime.fromisoformat(test_data['started_at'])
        elapsed_seconds = (timezone.now() - started_at).total_seconds()

        # Mark comparison as completed
        session.ab_test_data['status'] = 'completed'
        session.ab_test_data['ended_at'] = timezone.now().isoformat()
        session.ab_test_data['final_metrics'] = metrics
        session.ab_test_data['confidence_level'] = confidence
        session.save(update_fields=['ab_test_data'])

        logger.info(
            f"[CONFIG_COMPARISON] Comparison finalized for session {session.id}: "
            f"Config_A={metrics['score_a']:.1f}, Config_B={metrics['score_b']:.1f}, "
            f"winner={winner}, action='{action}'"
        )

        return Response({
            'comparison_id': session.id,
            'comparison_name': test_data.get('comparison_name'),
            'status': 'completed',
            'final_metrics': {
                'config_a_score': metrics['score_a'],
                'config_b_score': metrics['score_b'],
                'winner': metrics['winner'],
                'improvement_percent': metrics['improvement'],
                'config_a_stats': metrics['metrics_a'],
                'config_b_stats': metrics['metrics_b'],
                'recommendation': metrics['recommendation']
            },
            'total_matches_analyzed': len(all_matches),
            'config_a_matches': len(matches_config_a),
            'config_b_matches': len(matches_config_b),
            'comparison_duration_seconds': elapsed_seconds,
            'action_recommended': action,
            'confidence_level': confidence
        })
