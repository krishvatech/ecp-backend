"""
A/B Testing Framework - Compare different matching configurations.

This module provides the ABTest class which implements deterministic user
bucketing to run controlled experiments comparing two different matching
configurations on different user groups.

Key features:
- Deterministic bucketing: same user always gets same config
- Success measurement: completion rate + duration
- Statistical analysis: determines winning config
- No data loss: all matches recorded with their config version
"""

import logging
from datetime import datetime, timedelta
from django.utils import timezone

logger = logging.getLogger('events')


class ABTest:
    """
    Run A/B test comparing two different matching configurations.

    Bucketing:
    - Uses hash(user_id + test_id) % 100 for deterministic assignment
    - Ensures same user always gets same config throughout test
    - Supports configurable split ratio (default 50/50)

    Success Metrics:
    - Completion Rate: % of matches that complete (60% weight)
    - Average Duration: minutes spent in conversation (40% weight)
    - Combined Score: 0-100, higher is better

    Example:
        config_a = {'skill': 0.25, 'experience': 0.25, ...}
        config_b = {'skill': 0.30, 'experience': 0.20, ...}
        test = ABTest(session, config_a, config_b, split_ratio=0.5)

        # Get config for a user
        user_config = test.get_config_for_user(user_id)

        # Measure success after session completes
        results = test.measure_success()
    """

    def __init__(self, session, config_a, config_b, split_ratio=0.5):
        """
        Initialize A/B test.

        Args:
            session: SpeedNetworkingSession object
            config_a: Config dict for control group (current weights)
            config_b: Config dict for treatment group (new weights)
            split_ratio: Ratio for bucket A (0.5 = 50/50 split)
        """
        self.session = session
        self.config_a = config_a or {}
        self.config_b = config_b or {}
        self.split_ratio = split_ratio
        self.test_id = session.id

        logger.info(
            f"[AB_TEST] Test {self.test_id} created: "
            f"split_ratio={split_ratio:.1%}, config_a_version=1, config_b_version=2"
        )

    def get_config_for_user(self, user_id):
        """
        Deterministically assign user to bucket A or B.

        Uses hash-based bucketing to ensure:
        - Same user always gets same config
        - Consistent assignment across test duration
        - Supports any split ratio

        Args:
            user_id: User ID to bucket

        Returns:
            Tuple (config, bucket) where:
            - config: dict with criteria weights for this user
            - bucket: 'A' or 'B' for logging/analysis
        """
        # Create deterministic hash
        hash_value = hash(str(user_id) + str(self.test_id)) % 100

        # Bucket based on split ratio
        # If split_ratio=0.5, bucket A gets 0-49, bucket B gets 50-99
        bucket_threshold = int(self.split_ratio * 100)

        if hash_value < bucket_threshold:
            logger.debug(f"[AB_TEST] User {user_id}: bucket A (hash={hash_value})")
            return self.config_a, 'A'
        else:
            logger.debug(f"[AB_TEST] User {user_id}: bucket B (hash={hash_value})")
            return self.config_b, 'B'

    def measure_success(self, matches_a, matches_b):
        """
        Measure success of both configs.

        Success is measured by:
        1. Completion Rate (60% weight)
           - Percentage of matches that reached COMPLETED status
           - Higher completion = better matching algorithm

        2. Average Duration (40% weight)
           - Average time spent in conversation (minutes)
           - Longer conversations indicate better matches
           - Normalized to 0-1 (max 10 minutes = 1.0)

        Combined: (completion_rate * 0.6) + (duration_score * 0.4)

        Args:
            matches_a: QuerySet of matches for Config A
            matches_b: QuerySet of matches for Config B

        Returns:
            {
                'score_a': 0-100,
                'score_b': 0-100,
                'winner': 'a' or 'b',
                'improvement': percentage improvement,
                'metrics_a': {...},
                'metrics_b': {...}
            }
        """
        # Measure config A
        metrics_a = self._measure_config_success(matches_a, 'A')
        score_a = metrics_a['success_score'] if metrics_a else 0

        # Measure config B
        metrics_b = self._measure_config_success(matches_b, 'B')
        score_b = metrics_b['success_score'] if metrics_b else 0

        # Determine winner
        if score_a > score_b:
            winner = 'a'
            improvement = ((score_a - score_b) / score_b * 100) if score_b > 0 else 0
        elif score_b > score_a:
            winner = 'b'
            improvement = ((score_b - score_a) / score_a * 100) if score_a > 0 else 0
        else:
            winner = 'tie'
            improvement = 0

        result = {
            'score_a': round(score_a, 1),
            'score_b': round(score_b, 1),
            'winner': winner,
            'improvement': round(improvement, 1),
            'metrics_a': metrics_a,
            'metrics_b': metrics_b,
            'recommendation': self._get_recommendation(winner, improvement)
        }

        logger.info(
            f"[AB_TEST] Test {self.test_id} results: "
            f"A={score_a:.1f}, B={score_b:.1f}, winner={winner}, "
            f"improvement={improvement:.1f}%"
        )

        return result

    @staticmethod
    def _measure_config_success(matches, config_label):
        """
        Measure success metrics for a set of matches.

        Args:
            matches: QuerySet or list of SpeedNetworkingMatch objects
            config_label: 'A' or 'B' for logging

        Returns:
            {
                'total_matches': count,
                'completed_matches': count,
                'completion_rate': 0-1,
                'avg_duration_seconds': float,
                'avg_duration_minutes': float,
                'duration_score': 0-1,
                'success_score': 0-100
            }
        """
        try:
            match_list = list(matches)
            total = len(match_list)

            if total == 0:
                return None

            # Calculate completion rate
            completed = sum(1 for m in match_list if m.status == 'COMPLETED')
            completion_rate = completed / total if total > 0 else 0

            # Calculate average duration
            durations = []
            for match in match_list:
                if match.ended_at and match.created_at:
                    duration = (match.ended_at - match.created_at).total_seconds()
                    durations.append(duration)

            avg_duration_seconds = sum(durations) / len(durations) if durations else 0
            avg_duration_minutes = avg_duration_seconds / 60

            # Normalize duration (max 10 minutes = 1.0)
            max_duration_seconds = 600  # 10 minutes
            duration_score = min(1.0, avg_duration_seconds / max_duration_seconds)

            # Combined success score
            # 60% weight to completion rate, 40% to duration
            combined_score = (completion_rate * 0.6) + (duration_score * 0.4)
            success_score = combined_score * 100

            result = {
                'total_matches': total,
                'completed_matches': completed,
                'completion_rate': round(completion_rate, 3),
                'avg_duration_seconds': round(avg_duration_seconds, 1),
                'avg_duration_minutes': round(avg_duration_minutes, 2),
                'duration_score': round(duration_score, 3),
                'success_score': round(success_score, 1)
            }

            logger.info(
                f"[AB_TEST] Config {config_label}: {total} matches, "
                f"completion={completion_rate:.1%}, "
                f"duration={avg_duration_minutes:.1f}min, "
                f"score={success_score:.1f}"
            )

            return result

        except Exception as e:
            logger.error(f"[AB_TEST] Error measuring config {config_label}: {e}")
            return None

    @staticmethod
    def _get_recommendation(winner, improvement):
        """
        Generate human-readable recommendation based on results.

        Args:
            winner: 'a', 'b', or 'tie'
            improvement: percentage improvement

        Returns:
            String recommendation
        """
        if winner == 'tie':
            return "No significant difference between configs. Either can be used."
        elif improvement < 5:
            return f"Config {winner.upper()} slightly better (+{improvement:.1f}%). Consider running more tests."
        elif improvement < 15:
            return f"Config {winner.upper()} better (+{improvement:.1f}%). Recommend switching."
        else:
            return f"Config {winner.upper()} significantly better (+{improvement:.1f}%). Strongly recommend switching."

    @staticmethod
    def validate_configs(config_a, config_b):
        """
        Validate that both configs have required criteria.

        Args:
            config_a: Config dict
            config_b: Config dict

        Returns:
            Tuple (is_valid, error_message)
        """
        required_criteria = ['skill', 'experience', 'location', 'education']

        # Check config_a
        if not config_a:
            return False, "Config A is empty"

        missing_a = [c for c in required_criteria if c not in config_a]
        if missing_a:
            return False, f"Config A missing criteria: {missing_a}"

        # Check config_b
        if not config_b:
            return False, "Config B is empty"

        missing_b = [c for c in required_criteria if c not in config_b]
        if missing_b:
            return False, f"Config B missing criteria: {missing_b}"

        # Check weights sum to ~1.0
        sum_a = sum(config_a.values())
        sum_b = sum(config_b.values())

        if sum_a < 0.99 or sum_a > 1.01:
            return False, f"Config A weights don't sum to 1.0 (sum={sum_a:.2f})"

        if sum_b < 0.99 or sum_b > 1.01:
            return False, f"Config B weights don't sum to 1.0 (sum={sum_b:.2f})"

        return True, None

    @staticmethod
    def generate_test_id():
        """Generate unique test identifier."""
        return f"test_{timezone.now().timestamp()}"
