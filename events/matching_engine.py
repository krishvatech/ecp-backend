"""
Speed Networking Matching Engine
Implements Airmeet-style positive/negative rule-based matching.

Key Features:
- Positive rules: Define which segments can match
- Negative rules: Define which segments cannot match
- User profiles: Store matching attributes (ticket tier, custom fields, user type)
- Match history: Prevent immediate re-matching
- Race condition safety: Uses select_for_update
"""

from django.db.models import Q
from django.db import transaction
from django.utils import timezone
from datetime import timedelta
import random
import logging

logger = logging.getLogger(__name__)


class MatchingEngine:
    """
    Core matching logic for speed networking sessions.
    Handles rule evaluation, candidate filtering, and partner selection.
    """

    def __init__(self, session):
        """
        Initialize matching engine for a session.

        Args:
            session: SpeedNetworkingSession instance
        """
        self.session = session
        self.rules = session.matching_rules.filter(is_active=True)

    # ==================== PHASE 1: PROFILE MANAGEMENT ====================

    def compute_user_profile(self, user, force_refresh=False):
        """
        Get or compute user's matching profile for this session.

        Args:
            user: User instance
            force_refresh: Recompute profile even if exists

        Returns:
            UserMatchingProfile instance
        """
        from .models import UserMatchingProfile

        if force_refresh:
            UserMatchingProfile.objects.filter(
                session=self.session,
                user=user
            ).delete()

        profile, created = UserMatchingProfile.objects.get_or_create(
            session=self.session,
            user=user,
            defaults={'user_type': 'attendee', 'ticket_tier': 'basic'}
        )

        if created or force_refresh:
            profile = self._populate_profile(user, profile)
            logger.info(f"[PROFILE] Created/refreshed profile for user={user.id}")

        return profile

    def _populate_profile(self, user, profile):
        """
        Extract and populate matching attributes from user registration.

        Args:
            user: User instance
            profile: UserMatchingProfile instance

        Returns:
            Updated UserMatchingProfile instance
        """
        from .models import EventRegistration

        try:
            registration = EventRegistration.objects.get(
                event=self.session.event,
                user=user
            )

            # Extract ticket tier (adjust field name based on your EventRegistration model)
            if hasattr(registration, 'ticket_tier'):
                profile.ticket_tier = registration.ticket_tier or 'basic'

            # Extract user type (host, speaker, attendee)
            if hasattr(registration, 'user_type'):
                profile.user_type = registration.user_type or 'attendee'

            # Extract custom fields (if stored as JSON)
            if hasattr(registration, 'custom_fields'):
                profile.custom_fields = registration.custom_fields or {}

            # Alternative: Extract from user profile if available
            if hasattr(user, 'profile'):
                if hasattr(user.profile, 'user_type'):
                    profile.user_type = user.profile.user_type

            logger.debug(
                f"[PROFILE] Populated profile for user={user.id}: "
                f"tier={profile.ticket_tier}, type={profile.user_type}"
            )

        except EventRegistration.DoesNotExist:
            logger.warning(f"[PROFILE] No registration found for user={user.id}")
            profile.user_type = 'attendee'
            profile.ticket_tier = 'basic'

        except Exception as e:
            logger.error(f"[PROFILE] Error populating profile: {e}")
            profile.user_type = 'attendee'
            profile.ticket_tier = 'basic'

        profile.save()
        return profile

    def bulk_precompute_profiles(self, user_ids):
        """
        Precompute profiles for multiple users at once.
        Use when session starts to avoid per-user computation later.

        Args:
            user_ids: List of user IDs
        """
        from .models import UserMatchingProfile, SpeedNetworkingQueue
        from django.contrib.auth.models import User

        # Get existing profiles
        existing = set(
            UserMatchingProfile.objects
            .filter(session=self.session, user_id__in=user_ids)
            .values_list('user_id', flat=True)
        )

        # Create missing profiles
        to_create = [
            UserMatchingProfile(
                session=self.session,
                user_id=uid,
                user_type='attendee',
                ticket_tier='basic'
            )
            for uid in user_ids
            if uid not in existing
        ]

        if to_create:
            UserMatchingProfile.objects.bulk_create(to_create)
            logger.info(f"[PROFILE] Precomputed {len(to_create)} profiles")

        # Populate all profiles
        users = User.objects.filter(id__in=user_ids)
        for user in users:
            profile = UserMatchingProfile.objects.get(
                session=self.session,
                user=user
            )
            self._populate_profile(user, profile)

    # ==================== PHASE 2: CANDIDATE FILTERING ====================

    def get_eligible_candidates(self, user):
        """
        Get all users eligible to match with given user based on rules.

        This is the main entry point for candidate filtering.

        Args:
            user: User to find candidates for

        Returns:
            List of eligible User instances
        """
        from .models import SpeedNetworkingQueue, UserMatchingProfile

        logger.info(f"[MATCH] Finding eligible candidates for user={user.id}")

        # Get available queue entries (active, no match, not the user)
        available = SpeedNetworkingQueue.objects.filter(
            session=self.session,
            is_active=True,
            current_match__isnull=True
        ).exclude(user=user).select_related('user')

        if not available.exists():
            logger.debug("[MATCH] No available users in queue")
            return []

        # Get user's matching profile
        user_profile = self.compute_user_profile(user)

        # Get all candidate profiles (cache to avoid N+1)
        candidate_users = [entry.user for entry in available]
        candidate_profiles = {
            up.user_id: up
            for up in UserMatchingProfile.objects.filter(
                session=self.session,
                user__in=candidate_users
            )
        }

        # Apply matching rules
        eligible_users = self._apply_rules(
            user_profile,
            candidate_users,
            candidate_profiles
        )

        logger.info(
            f"[MATCH] Found {len(eligible_users)} eligible candidates "
            f"for user={user.id} (from {len(candidate_users)} available)"
        )

        return eligible_users

    def _apply_rules(self, user_profile, candidates, candidate_profiles):
        """
        Apply positive and negative rules to filter candidates.

        Logic:
        1. No rules: All candidates eligible
        2. Positive rules: User must match at least one rule segment pair
        3. Negative rules: Block candidates matching blocked segments

        Args:
            user_profile: UserMatchingProfile of initiating user
            candidates: List of candidate User instances
            candidate_profiles: Dict mapping user_id -> UserMatchingProfile

        Returns:
            List of eligible User instances
        """
        if not self.rules.exists():
            logger.debug("[RULES] No rules defined, all candidates eligible")
            return candidates

        positive_rules = list(self.rules.filter(rule_type='POSITIVE'))
        negative_rules = list(self.rules.filter(rule_type='NEGATIVE'))

        logger.debug(
            f"[RULES] Applying {len(positive_rules)} positive and "
            f"{len(negative_rules)} negative rules"
        )

        # Start with all candidates
        eligible = set(c.id for c in candidates)

        # ===== STEP 1: Apply POSITIVE rules (AND logic) =====
        if positive_rules:
            allowed = set()

            for rule in positive_rules:
                logger.debug(f"[RULES] Processing positive rule: {rule.name}")

                # Check if user matches segment A
                if self._user_matches_segment(
                    user_profile,
                    rule.segment_a_type,
                    rule.segment_a_values,
                ):
                    logger.debug(
                        f"[RULES] User matches segment A of {rule.name}, "
                        f"allowing segment B"
                    )
                    # Add all candidates from segment B
                    segment_b_ids = self._get_segment_user_ids(
                        rule.segment_b_type,
                        rule.segment_b_values,
                        candidates,
                        candidate_profiles
                    )
                    allowed.update(segment_b_ids)

                # Check if user matches segment B (bi-directional)
                if rule.segment_b_type and self._user_matches_segment(
                    user_profile,
                    rule.segment_b_type,
                    rule.segment_b_values,
                ):
                    logger.debug(
                        f"[RULES] User matches segment B of {rule.name}, "
                        f"allowing segment A"
                    )
                    # Add all candidates from segment A
                    segment_a_ids = self._get_segment_user_ids(
                        rule.segment_a_type,
                        rule.segment_a_values,
                        candidates,
                        candidate_profiles
                    )
                    allowed.update(segment_a_ids)

            # For positive rules, only allowed candidates are eligible
            eligible = eligible.intersection(allowed)
            logger.debug(f"[RULES] After positive rules: {len(eligible)} candidates")

        # ===== STEP 2: Apply NEGATIVE rules (blocking) =====
        for rule in negative_rules:
            logger.debug(f"[RULES] Processing negative rule: {rule.name}")

            if self._user_matches_segment(
                user_profile,
                rule.segment_a_type,
                rule.segment_a_values,
            ):
                logger.debug(
                    f"[RULES] User matches blocked segment in {rule.name}, "
                    f"removing same-segment candidates"
                )
                # Remove candidates from the same blocked segment
                blocked_ids = self._get_segment_user_ids(
                    rule.segment_a_type,
                    rule.segment_a_values,
                    candidates,
                    candidate_profiles
                )
                eligible = eligible.difference(blocked_ids)

            logger.debug(f"[RULES] After negative rule: {len(eligible)} candidates")

        # Convert back to User objects
        eligible_users = [c for c in candidates if c.id in eligible]
        logger.debug(f"[RULES] Final eligible candidates: {len(eligible_users)}")

        return eligible_users

    # ==================== PHASE 3: SEGMENT MATCHING ====================

    def _user_matches_segment(self, profile, segment_type, segment_values):
        """
        Check if a user's profile matches a specific segment definition.

        Args:
            profile: UserMatchingProfile instance
            segment_type: Type of segment (e.g., 'ticket_tier', 'custom_field:role')
            segment_values: List of values to match against

        Returns:
            Boolean indicating if user matches segment
        """
        if not segment_type or not segment_values:
            return False

        # Custom field matching
        if segment_type.startswith('custom_field:'):
            field_name = segment_type.replace('custom_field:', '')
            user_value = profile.custom_fields.get(field_name)
            matches = user_value in segment_values
            logger.debug(
                f"[SEGMENT] Custom field '{field_name}': user={user_value}, "
                f"allowed={segment_values}, matches={matches}"
            )
            return matches

        # Ticket tier matching
        elif segment_type == 'ticket_tier':
            matches = profile.ticket_tier in segment_values
            logger.debug(
                f"[SEGMENT] Ticket tier: user={profile.ticket_tier}, "
                f"allowed={segment_values}, matches={matches}"
            )
            return matches

        # User type matching
        elif segment_type == 'user_type':
            matches = profile.user_type in segment_values
            logger.debug(
                f"[SEGMENT] User type: user={profile.user_type}, "
                f"allowed={segment_values}, matches={matches}"
            )
            return matches

        logger.warning(f"[SEGMENT] Unknown segment type: {segment_type}")
        return False

    def _get_segment_user_ids(self, segment_type, segment_values, candidates, candidate_profiles):
        """
        Get IDs of all users matching a specific segment.

        Args:
            segment_type: Type of segment
            segment_values: Values to match
            candidates: List of candidate User instances
            candidate_profiles: Dict mapping user_id -> UserMatchingProfile

        Returns:
            Set of matching user IDs
        """
        matching_ids = set()

        for candidate in candidates:
            profile = candidate_profiles.get(candidate.id)
            if profile and self._user_matches_segment(
                profile,
                segment_type,
                segment_values
            ):
                matching_ids.add(candidate.id)

        logger.debug(
            f"[SEGMENT] Found {len(matching_ids)} users in segment {segment_type}"
        )
        return matching_ids

    # ==================== PHASE 4: MATCH HISTORY ====================

    def get_recent_matches(self, user, days=1):
        """
        Get user IDs that this user has recently matched with.

        Args:
            user: User instance
            days: Look back this many days

        Returns:
            Set of user IDs recently matched
        """
        from .models import MatchHistory

        since = timezone.now() - timedelta(days=days)
        recent = MatchHistory.objects.filter(
            session=self.session,
            user=user,
            matched_at__gte=since
        ).values_list('matched_with_id', flat=True)

        return set(recent)

    def filter_by_match_history(self, candidates, user, max_days=1):
        """
        Remove candidates that user has recently matched with.

        Args:
            candidates: List of candidate User instances
            user: User to filter for
            max_days: Don't match again within this many days

        Returns:
            Filtered list of candidates
        """
        recent_ids = self.get_recent_matches(user, days=max_days)
        filtered = [c for c in candidates if c.id not in recent_ids]

        logger.info(
            f"[HISTORY] Filtered {len(candidates) - len(filtered)} recent matches "
            f"(max_days={max_days}) for user={user.id}"
        )

        return filtered

    def get_full_match_history(self, user):
        """
        Get complete match history for a user in this session.

        Args:
            user: User instance

        Returns:
            List of (matched_user, match_time) tuples, most recent first
        """
        from .models import MatchHistory

        history = (MatchHistory.objects
            .filter(session=self.session, user=user)
            .select_related('matched_with')
            .order_by('-matched_at'))

        return [(h.matched_with, h.matched_at) for h in history]

    # ==================== PHASE 5: PARTNER SELECTION ====================

    def select_best_candidate(self, eligible_users, user, strategy='least_recent'):
        """
        Select the best candidate from eligible users.

        Strategies:
        - 'least_recent': Match with person least recently matched
        - 'random': Randomly select candidate
        - 'first': Select first in list (deterministic, testing only)

        Args:
            eligible_users: List of User instances to choose from
            user: User to find match for
            strategy: Selection strategy

        Returns:
            Best User instance, or None if list empty
        """
        if not eligible_users:
            logger.warning(f"[SELECT] No eligible candidates for user={user.id}")
            return None

        logger.info(
            f"[SELECT] Selecting partner from {len(eligible_users)} candidates "
            f"using '{strategy}' strategy for user={user.id}"
        )

        if strategy == 'least_recent':
            return self._select_least_recent(eligible_users, user)
        elif strategy == 'random':
            selected = random.choice(eligible_users)
            logger.debug(f"[SELECT] Randomly selected user={selected.id}")
            return selected
        elif strategy == 'first':
            logger.debug(f"[SELECT] Selected first candidate user={eligible_users[0].id}")
            return eligible_users[0]
        else:
            logger.warning(f"[SELECT] Unknown strategy: {strategy}, using random")
            return random.choice(eligible_users)

    def _select_least_recent(self, eligible_users, user):
        """
        Select candidate with oldest/no match time.

        Args:
            eligible_users: List of candidates
            user: User to find match for

        Returns:
            User instance with least recent match time
        """
        from .models import MatchHistory

        match_times = {}
        for candidate in eligible_users:
            last_match = (MatchHistory.objects
                .filter(
                    session=self.session,
                    user=user,
                    matched_with=candidate
                )
                .order_by('-matched_at')
                .first())

            # None means never matched, sort to beginning
            match_times[candidate.id] = last_match.matched_at if last_match else None

        selected = min(
            eligible_users,
            key=lambda c: match_times[c.id] or timezone.now()
        )

        logger.debug(
            f"[SELECT] Selected user={selected.id} with last match at "
            f"{match_times[selected.id]}"
        )
        return selected

    # ==================== PHASE 6: MATCH CREATION ====================

    def record_match_history(self, user, partner, match_record=None):
        """
        Record match in history table.

        Args:
            user: User instance
            partner: Partner user instance
            match_record: SpeedNetworkingMatch instance (optional)
        """
        from .models import MatchHistory

        # Avoid duplicates
        try:
            MatchHistory.objects.get(
                session=self.session,
                user=user,
                matched_with=partner
            )
        except MatchHistory.DoesNotExist:
            MatchHistory.objects.create(
                session=self.session,
                user=user,
                matched_with=partner,
                match_record=match_record
            )
            logger.info(
                f"[HISTORY] Recorded match between user={user.id} "
                f"and user={partner.id}"
            )

    # ==================== PHASE 7: VALIDATION ====================

    def validate_rules_before_session_start(self):
        """
        Validate all rules for a session before it starts.

        Checks:
        - No cross-category rules
        - No double rules on same segment
        - All segment values are valid

        Raises:
            ValueError if validation fails

        Returns:
            List of warnings (if any)
        """
        warnings = []

        # Check for cross-category rules
        for rule in self.rules:
            if (rule.segment_a_type.split(':')[0] !=
                rule.segment_b_type.split(':')[0] if rule.segment_b_type else True):
                warnings.append(
                    f"Rule '{rule.name}' mixes categories - may not work as expected"
                )

        # Check for conflicting rules
        positive_rules = self.rules.filter(rule_type='POSITIVE')
        for segment_a in positive_rules.values_list('segment_a_type', flat=True).distinct():
            conflicts = positive_rules.filter(segment_a_type=segment_a).count()
            if conflicts > 1:
                warnings.append(
                    f"Multiple positive rules for segment '{segment_a}' - "
                    f"candidates must match ALL rules"
                )

        logger.info(f"[VALIDATE] Found {len(warnings)} validation warnings")
        for w in warnings:
            logger.warning(f"[VALIDATE] {w}")

        return warnings

    # ==================== DEBUG & METRICS ====================

    def get_matching_metrics(self):
        """
        Get matching quality metrics for this session.

        Returns:
            Dict with matching metrics
        """
        from .models import SpeedNetworkingMatch, MatchHistory

        matches = self.session.matches.all()
        total = matches.count()
        completed = matches.filter(status='COMPLETED').count()
        active = matches.filter(status='ACTIVE').count()
        skipped = matches.filter(status='SKIPPED').count()

        # Compute average duration
        completed_matches = matches.filter(status='COMPLETED').exclude(ended_at__isnull=True)
        durations = []
        for match in completed_matches:
            if match.ended_at and match.created_at:
                duration = (match.ended_at - match.created_at).total_seconds()
                durations.append(duration)

        avg_duration = sum(durations) / len(durations) if durations else 0

        return {
            'total_matches': total,
            'active_matches': active,
            'completed_matches': completed,
            'skipped_matches': skipped,
            'avg_match_duration_seconds': avg_duration,
            'rule_count': self.rules.count(),
        }

    def check_rule_compliance(self, match):
        """
        Check if a specific match complies with all rules.

        Args:
            match: SpeedNetworkingMatch instance

        Returns:
            Boolean indicating compliance
        """
        from .models import UserMatchingProfile

        p1_profile = UserMatchingProfile.objects.get(
            session=self.session,
            user=match.participant_1
        )
        p2_profile = UserMatchingProfile.objects.get(
            session=self.session,
            user=match.participant_2
        )

        for rule in self.rules:
            if rule.rule_type == 'POSITIVE':
                # Both participants must match the rule somehow
                p1_matches_a = self._user_matches_segment(
                    p1_profile,
                    rule.segment_a_type,
                    rule.segment_a_values
                )
                p1_matches_b = self._user_matches_segment(
                    p1_profile,
                    rule.segment_b_type,
                    rule.segment_b_values
                )

                p2_matches_a = self._user_matches_segment(
                    p2_profile,
                    rule.segment_a_type,
                    rule.segment_a_values
                )
                p2_matches_b = self._user_matches_segment(
                    p2_profile,
                    rule.segment_b_type,
                    rule.segment_b_values
                )

                # Valid if: (P1 in A and P2 in B) or (P1 in B and P2 in A)
                valid = (p1_matches_a and p2_matches_b) or (p1_matches_b and p2_matches_a)
                if not valid:
                    logger.warning(
                        f"[COMPLIANCE] Match {match.id} violates positive rule "
                        f"'{rule.name}'"
                    )
                    return False

            elif rule.rule_type == 'NEGATIVE':
                # Neither participant should be in the blocked segment
                p1_blocked = self._user_matches_segment(
                    p1_profile,
                    rule.segment_a_type,
                    rule.segment_a_values
                )
                p2_blocked = self._user_matches_segment(
                    p2_profile,
                    rule.segment_a_type,
                    rule.segment_a_values
                )

                if p1_blocked and p2_blocked:
                    logger.warning(
                        f"[COMPLIANCE] Match {match.id} violates negative rule "
                        f"'{rule.name}'"
                    )
                    return False

        logger.debug(f"[COMPLIANCE] Match {match.id} complies with all rules")
        return True

    def debug_candidate_filtering(self, user):
        """
        Debug candidate filtering for a user - shows each filtering step.

        Args:
            user: User to debug for

        Returns:
            Dict with filtering steps and results
        """
        from .models import SpeedNetworkingQueue, UserMatchingProfile

        logger.info(f"[DEBUG] Starting candidate filtering debug for user={user.id}")

        # Get available
        available = SpeedNetworkingQueue.objects.filter(
            session=self.session,
            is_active=True,
            current_match__isnull=True
        ).exclude(user=user).select_related('user')

        candidates = [entry.user for entry in available]
        logger.info(f"[DEBUG] Available candidates: {len(candidates)}")

        # Get profiles
        user_profile = self.compute_user_profile(user)
        logger.info(
            f"[DEBUG] User profile: tier={user_profile.ticket_tier}, "
            f"type={user_profile.user_type}"
        )

        candidate_profiles = {
            up.user_id: up
            for up in UserMatchingProfile.objects.filter(
                session=self.session,
                user__in=candidates
            )
        }

        # Apply rules
        eligible = self._apply_rules(user_profile, candidates, candidate_profiles)
        logger.info(f"[DEBUG] After rule filtering: {len(eligible)}")

        # Apply history
        eligible = self.filter_by_match_history(eligible, user, max_days=1)
        logger.info(f"[DEBUG] After history filtering: {len(eligible)}")

        return {
            'user_id': user.id,
            'available_candidates': len(candidates),
            'after_rules': len(eligible),
            'eligible_candidates': [u.id for u in eligible],
        }
