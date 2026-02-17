"""
ML Weight Optimizer - Analyzes match success rates and suggests optimal weights.

This module provides the MatchingAnalyzer class which analyzes completed matches
in a speed networking session to identify which criteria correlate most with
successful matches, then suggests optimal weight distributions.

Success is defined as matches where:
- Status is COMPLETED (match finished normally)
- Duration exceeded 5 minutes (300 seconds of conversation)

Output includes:
- Suggested weights for each criterion (normalized 0-1)
- Correlation coefficients for each criterion
- Confidence level (high/medium/low based on sample size)
- Success rate and average match score
"""

import logging
from django.db.models import F
from datetime import timedelta

logger = logging.getLogger('events')


class MatchingAnalyzer:
    """
    Analyzes match success rates and suggests optimal weight distribution.

    The analyzer uses correlation analysis on completed matches to identify
    which criteria (skill, experience, location, education) correlate most
    strongly with successful matches.

    Minimum 20 matches required for analysis; 50+ recommended for confidence.
    """

    @staticmethod
    def analyze_session(session):
        """
        Analyze completed matches in a session and suggest optimal weights.

        Args:
            session: SpeedNetworkingSession object to analyze

        Returns:
            dict with keys:
                - suggested_weights: {criterion: weight} (normalized 0-1)
                - correlations: {criterion: correlation} (0-1 scale)
                - matches_analyzed: number of completed matches found
                - success_rate: percentage of successful matches (0-100)
                - avg_score: average match score of successful matches
                - avg_duration: average conversation duration in seconds
                - confidence: 'high' (>50), 'medium' (20-50), or 'low' (<20)

            None if less than 5 matches found (insufficient data)
        """
        from .models import SpeedNetworkingMatch

        try:
            # Get all completed matches
            completed_matches = SpeedNetworkingMatch.objects.filter(
                session=session,
                status='COMPLETED',
                ended_at__isnull=False
            )

            if not completed_matches.exists():
                logger.warning(f"[ML] No completed matches in session {session.id}")
                return None

            # Extract match data
            matches_data = []
            for match in completed_matches:
                # Calculate match duration
                duration_seconds = (match.ended_at - match.created_at).total_seconds()

                # Define success: match lasted >5 minutes (300 seconds) = good conversation
                is_successful = 1 if duration_seconds >= 300 else 0

                # Extract criterion scores from breakdown
                breakdown = match.match_breakdown or {}
                matches_data.append({
                    'score': match.match_score or 0,
                    'probability': match.match_probability or 0,
                    'skill': breakdown.get('skill', 0),
                    'experience': breakdown.get('experience', 0),
                    'location': breakdown.get('location', 0),
                    'education': breakdown.get('education', 0),
                    'success': is_successful,
                    'duration': duration_seconds
                })

            # Need minimum data for meaningful analysis
            if len(matches_data) < 5:
                logger.warning(
                    f"[ML] Insufficient matches ({len(matches_data)}) "
                    f"in session {session.id}. Need at least 5."
                )
                return None

            logger.info(f"[ML] Analyzing {len(matches_data)} completed matches in session {session.id}")

            # Calculate correlations using numpy
            try:
                import numpy as np
            except ImportError:
                logger.error(
                    "[ML] NumPy not installed. Install with: pip install numpy"
                )
                return None

            criteria = ['skill', 'experience', 'location', 'education']
            correlations = {}

            # Calculate correlation between each criterion and success
            for criterion in criteria:
                criterion_scores = np.array([m[criterion] for m in matches_data])
                success_scores = np.array([m['success'] for m in matches_data])

                # Handle edge cases
                if criterion_scores.std() == 0 or success_scores.std() == 0:
                    # No variation in data - correlation undefined
                    correlations[criterion] = 0
                    continue

                # Calculate Pearson correlation coefficient
                correlation = np.corrcoef(criterion_scores, success_scores)[0][1]

                # Only use positive correlations (negative = bad indicator)
                correlations[criterion] = max(0, correlation) if not np.isnan(correlation) else 0

            # Normalize correlations to weights (sum to 1.0)
            total_correlation = sum(correlations.values())
            if total_correlation == 0:
                # If no criterion correlates, use equal weights
                suggested_weights = {c: 0.25 for c in criteria}
                logger.info("[ML] No positive correlations found - using equal weights")
            else:
                suggested_weights = {
                    c: round(v / total_correlation, 3)
                    for c, v in correlations.items()
                }

            # Calculate success metrics
            successful_matches = sum(m['success'] for m in matches_data)
            success_rate = (successful_matches / len(matches_data)) * 100
            avg_score = sum(m['score'] for m in matches_data) / len(matches_data)
            avg_duration = sum(m['duration'] for m in matches_data) / len(matches_data)

            # Determine confidence level
            num_matches = len(matches_data)
            if num_matches > 50:
                confidence = 'high'
            elif num_matches > 20:
                confidence = 'medium'
            else:
                confidence = 'low'

            result = {
                'suggested_weights': suggested_weights,
                'correlations': {c: round(v, 3) for c, v in correlations.items()},
                'matches_analyzed': num_matches,
                'success_rate': round(success_rate, 1),
                'avg_score': round(avg_score, 1),
                'avg_duration': round(avg_duration, 1),
                'confidence': confidence
            }

            logger.info(
                f"[ML] Analysis complete: {num_matches} matches, "
                f"{success_rate:.1f}% success, confidence={confidence}"
            )

            return result

        except Exception as e:
            logger.error(f"[ML] Failed to analyze session {session.id}: {e}", exc_info=True)
            return None

    @staticmethod
    def get_weight_recommendations(correlations, min_sample_size=20):
        """
        Get weight recommendations with confidence levels.

        Args:
            correlations: dict of {criterion: correlation_value}
            min_sample_size: minimum matches required for each confidence level

        Returns:
            dict with recommendations and confidence flags
        """
        criteria = ['skill', 'experience', 'location', 'education']

        # Normalize
        total = sum(correlations.values())
        if total == 0:
            return {c: 0.25 for c in criteria}

        return {c: correlations.get(c, 0) / total for c in criteria}

    @staticmethod
    def suggest_weights_diff(current_weights, suggested_weights, threshold=0.05):
        """
        Compare current weights to suggested weights and highlight changes.

        Args:
            current_weights: dict of current {criterion: weight}
            suggested_weights: dict of suggested {criterion: weight}
            threshold: minimum change to report (default 5%)

        Returns:
            dict with 'changes' and 'explanation'
        """
        changes = {}

        for criterion in current_weights:
            current = current_weights.get(criterion, 0)
            suggested = suggested_weights.get(criterion, 0)
            diff = suggested - current

            if abs(diff) >= threshold:
                changes[criterion] = {
                    'current': round(current, 3),
                    'suggested': round(suggested, 3),
                    'change': round(diff, 3),
                    'direction': 'increase' if diff > 0 else 'decrease'
                }

        return {
            'changes': changes,
            'has_significant_changes': len(changes) > 0,
            'explanation': (
                f"Found {len(changes)} significant weight changes (>{threshold*100}%)"
            )
        }
