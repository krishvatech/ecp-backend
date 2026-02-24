"""
Criteria-Based Speed Networking Matching Engine

Implements skill, experience, location, and education-based matching
with advanced scoring algorithms and fallback strategies.

Features:
- Skill overlap and complementarity detection (Jaccard similarity)
- Experience level proximity matching
- Geographic distance calculation (Haversine)
- Education qualification matching
- Weighted multi-criteria scoring
- Required/optional criterion handling
- Intelligent fallback strategies
- Missing data handling
"""

from math import radians, cos, sin, asin, sqrt
from copy import deepcopy
import logging
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)
CRITERIA_KEYS = ('skill', 'experience', 'location', 'education')


# ============================================================================
# SKILL-BASED MATCHING
# ============================================================================

def calculate_skill_match_score(user_a_skills: List[Dict],
                                user_b_skills: List[Dict],
                                match_mode: str = 'complementary') -> float:
    """
    Calculate skill match score using Jaccard similarity.

    Args:
        user_a_skills: [{'name': 'Python', 'level': 3, 'years': 5}, ...]
        user_b_skills: Same format
        match_mode: 'complementary' or 'similar'

    Returns:
        Score 0-100: Match quality percentage
    """
    if not user_a_skills or not user_b_skills:
        logger.debug(f"[SKILL] Missing skills: A={bool(user_a_skills)}, B={bool(user_b_skills)}")
        return 0

    # Extract skill names
    skill_names_a = {s.get('name', '').lower() for s in user_a_skills if s.get('name')}
    skill_names_b = {s.get('name', '').lower() for s in user_b_skills if s.get('name')}

    if not skill_names_a or not skill_names_b:
        return 0

    # Jaccard similarity: |intersection| / |union|
    intersection = skill_names_a & skill_names_b
    union = skill_names_a | skill_names_b

    jaccard_score = len(intersection) / len(union) * 100 if union else 0

    logger.debug(
        f"[SKILL] Jaccard: {len(intersection)}/{len(union)} = {jaccard_score:.1f}%"
    )

    # Mode-specific scoring
    if match_mode == 'complementary':
        # For complementary: Some overlap is good (40-80), too much less so
        if jaccard_score < 30:
            base_score = 40  # Some common ground
        elif jaccard_score < 70:
            base_score = 80  # Good complementarity
        else:
            base_score = 60  # Too similar, less complementary
    else:  # similar mode
        base_score = jaccard_score

    # Apply proficiency level weighting
    proficiency_bonus = 0
    for skill_a in user_a_skills:
        for skill_b in user_b_skills:
            if skill_a.get('name', '').lower() == skill_b.get('name', '').lower():
                level_a = skill_a.get('level', 2)
                level_b = skill_b.get('level', 2)
                # Bonus if both are advanced (level >= 3)
                if level_a >= 3 and level_b >= 3:
                    proficiency_bonus += 5

    final_score = min(100, base_score + proficiency_bonus)

    logger.debug(
        f"[SKILL] Mode={match_mode}, Base={base_score}, Bonus={proficiency_bonus}, "
        f"Final={final_score}"
    )

    return final_score


# ============================================================================
# EXPERIENCE-BASED MATCHING
# ============================================================================

def get_experience_level(years_of_experience: int) -> int:
    """Convert years to experience level (0-4)."""
    if years_of_experience == 0:
        return 0  # Student
    elif years_of_experience < 2:
        return 1  # Junior
    elif years_of_experience < 5:
        return 2  # Mid-level
    elif years_of_experience < 10:
        return 3  # Senior
    else:
        return 4  # Expert


def calculate_experience_match_score(user_a_years: float,
                                      user_b_years: float,
                                      user_a_level: int = None,
                                      user_b_level: int = None,
                                      match_type: str = 'mentorship') -> float:
    """
    Calculate experience match score.

    Args:
        user_a_years: Years of experience
        user_b_years: Years of experience
        user_a_level: Experience level (0-4), computed if None
        user_b_level: Experience level (0-4), computed if None
        match_type: 'peer', 'mentorship', or 'mixed'

    Returns:
        Score 0-100
    """
    # Compute levels if not provided
    if user_a_level is None:
        user_a_level = get_experience_level(user_a_years)
    if user_b_level is None:
        user_b_level = get_experience_level(user_b_years)

    experience_gap = abs(user_a_years - user_b_years)
    level_gap = abs(user_a_level - user_b_level)

    logger.debug(
        f"[EXPERIENCE] Type={match_type}, Gap={experience_gap}y, LevelGap={level_gap}"
    )

    if match_type == 'peer':
        # Peer matching: Same experience level is ideal (same level, small gap)
        # Require EXACT level match (level_gap = 0) or very close (< 0.5 year gap within same level)
        if level_gap == 0:
            # Same experience level
            if experience_gap <= 0.5:
                base_score = 95  # Perfect peer match
            elif experience_gap <= 1:
                base_score = 85  # Close peer match
            elif experience_gap <= 2:
                base_score = 70  # Similar peers
            else:
                base_score = 50  # Same level but different experience
        else:
            # Different experience levels: penalize accordingly
            base_score = 30  # Different levels shouldn't match well for peer mode

    elif match_type == 'mentorship':
        # Mentorship: 2-5 year gap is ideal
        if experience_gap < 2:
            base_score = 40  # Not enough gap
        elif 2 <= experience_gap <= 5:
            base_score = 95  # IDEAL mentorship gap
        elif 5 < experience_gap <= 10:
            base_score = 75
        else:
            base_score = 50

    else:  # mixed
        if experience_gap <= 2:
            base_score = 85
        elif experience_gap <= 5:
            base_score = 75
        else:
            base_score = 50

    # Penalty for extreme level mismatch
    if level_gap >= 3:
        base_score *= 0.7

    final_score = min(100, base_score)

    logger.debug(f"[EXPERIENCE] Score={final_score}")

    return final_score


# ============================================================================
# LOCATION-BASED MATCHING
# ============================================================================

def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate distance between two lat/lon points in kilometers.

    Uses Haversine formula for great-circle distance.
    """
    try:
        # Convert to radians
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])

        # Haversine formula
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))
        r = 6371  # Earth radius in km

        distance = c * r
        return distance
    except (TypeError, ValueError):
        logger.warning(f"[LOCATION] Invalid coordinates: ({lat1}, {lon1}) or ({lat2}, {lon2})")
        return float('inf')


def get_timezone_offset(timezone_name: str) -> int:
    """Get UTC offset for timezone in hours."""
    try:
        from datetime import datetime
        import pytz

        tz = pytz.timezone(timezone_name)
        now = datetime.now(tz)
        offset = now.utcoffset().total_seconds() / 3600
        return int(offset)
    except Exception as e:
        logger.warning(f"[LOCATION] Timezone lookup failed for {timezone_name}: {e}")
        return 0


def calculate_location_match_score(user_a_location: Dict,
                                   user_b_location: Dict,
                                   match_strategy: str = 'radius') -> float:
    """
    Calculate location match score.

    Args:
        user_a_location: {city, country, lat, lon, timezone}
        user_b_location: Same format
        match_strategy: 'exact_city', 'radius', or 'timezone'

    Returns:
        Score 0-100
    """
    if not user_a_location or not user_b_location:
        return 0

    if match_strategy == 'exact_city':
        # Strict city matching
        city_match = (
            user_a_location.get('city', '').lower() ==
            user_b_location.get('city', '').lower()
        )
        country_match = (
            user_a_location.get('country', '').lower() ==
            user_b_location.get('country', '').lower()
        )

        if city_match and country_match:
            logger.debug("[LOCATION] Exact city match")
            return 100
        else:
            logger.debug("[LOCATION] City mismatch")
            return 0

    elif match_strategy == 'radius':
        # Distance-based with falloff
        lat_a = user_a_location.get('lat')
        lon_a = user_a_location.get('lon')
        lat_b = user_b_location.get('lat')
        lon_b = user_b_location.get('lon')

        if lat_a is None or lon_a is None or lat_b is None or lon_b is None:
            logger.debug("[LOCATION] Missing coordinates, fallback to city match")
            # Fallback to city matching if coordinates missing
            if (user_a_location.get('city') and user_b_location.get('city') and
                user_a_location.get('city').lower() == user_b_location.get('city').lower()):
                return 75
            return 0

        distance = haversine_distance(lat_a, lon_a, lat_b, lon_b)

        logger.debug(f"[LOCATION] Distance: {distance:.1f} km")

        # Scoring function
        if distance < 10:
            score = 100
        elif distance < 50:
            score = 80
        elif distance < 100:
            score = 50
        elif distance < 200:
            score = 20
        else:
            score = 0

        return score

    elif match_strategy == 'timezone':
        # Timezone-based for remote participants
        tz_a = user_a_location.get('timezone', 'UTC')
        tz_b = user_b_location.get('timezone', 'UTC')

        offset_a = get_timezone_offset(tz_a)
        offset_b = get_timezone_offset(tz_b)

        offset_diff = abs(offset_a - offset_b)

        logger.debug(
            f"[LOCATION] Timezone: {tz_a} (UTC+{offset_a}) vs "
            f"{tz_b} (UTC+{offset_b}), diff={offset_diff}h"
        )

        if offset_diff == 0:
            return 100
        elif offset_diff <= 1:
            return 80
        elif offset_diff <= 3:
            return 50
        else:
            return 0

    return 0


def find_closest_candidate_by_distance(user_location: Dict,
                                       candidate_profiles: List[Dict]) -> Optional[Tuple[Dict, float]]:
    """
    Find the closest candidate by geographic distance.

    This is a fallback when criteria-based matching fails - picks whoever is
    geographically closest, even if very far apart.

    Args:
        user_location: {city, country, lat, lon, timezone} of the user
        candidate_profiles: List of candidate profile dicts

    Returns:
        Tuple of (candidate_profile, distance_km) or None if no valid locations
    """
    if not user_location or not candidate_profiles:
        return None

    user_lat = user_location.get('lat')
    user_lon = user_location.get('lon')

    # If user has no coordinates, can't calculate distance
    if user_lat is None or user_lon is None:
        logger.debug("[PROXIMITY] User missing coordinates for distance calculation")
        return None

    closest_candidate = None
    min_distance = float('inf')

    for candidate in candidate_profiles:
        candidate_location = candidate.get('location', {})
        cand_lat = candidate_location.get('lat')
        cand_lon = candidate_location.get('lon')

        # Skip candidates without coordinates
        if cand_lat is None or cand_lon is None:
            logger.debug(f"[PROXIMITY] Candidate {candidate.get('user_id')} missing coordinates")
            continue

        distance = haversine_distance(user_lat, user_lon, cand_lat, cand_lon)

        if distance < min_distance:
            min_distance = distance
            closest_candidate = candidate

    if closest_candidate:
        logger.info(f"[PROXIMITY] Found closest candidate at {min_distance:.1f} km away")
        return (closest_candidate, min_distance)

    logger.warning("[PROXIMITY] No candidates with valid coordinates found")
    return None


# ============================================================================
# EDUCATION-BASED MATCHING
# ============================================================================

def calculate_education_match_score(user_a_education: Dict,
                                   user_b_education: Dict,
                                   match_type: str = 'same_level') -> float:
    """
    Calculate education match score.

    Args:
        user_a_education: {degree, field, institution, level}
        user_b_education: Same format
        match_type: 'same_level', 'complementary_fields', or 'hierarchical'

    Returns:
        Score 0-100
    """
    if not user_a_education or not user_b_education:
        return 0

    level_a = user_a_education.get('level', 0)
    level_b = user_b_education.get('level', 0)
    field_a = (user_a_education.get('field') or '').lower()
    field_b = (user_b_education.get('field') or '').lower()

    # Convert levels to integers (in case they come as strings)
    try:
        level_a = int(level_a) if level_a else 0
        level_b = int(level_b) if level_b else 0
    except (ValueError, TypeError):
        level_a = 0
        level_b = 0

    level_diff = abs(level_a - level_b)

    logger.debug(
        f"[EDUCATION] Type={match_type}, LevelDiff={level_diff}, "
        f"Fields={field_a}/{field_b}"
    )

    if match_type == 'same_level':
        # Match users with EXACT same education level only
        if level_diff == 0:
            base_score = 90  # Exact same level
        else:
            base_score = 10  # Different levels - not a good match for "same_level" type

        # Bonus if same field
        if field_a and field_b and field_a == field_b:
            base_score += 10

    elif match_type == 'complementary_fields':
        # Complementary field pairs
        complementary_pairs = [
            ('computer science', 'business'),
            ('computer science', 'marketing'),
            ('computer science', 'finance'),
            ('engineering', 'business'),
            ('engineering', 'marketing'),
            ('data science', 'business'),
            ('data science', 'marketing'),
        ]

        base_score = 50  # Default for different fields

        # Check complementary
        for field1, field2 in complementary_pairs:
            if (field_a == field1 and field_b == field2) or \
               (field_a == field2 and field_b == field1):
                base_score = 85
                break

        # Same field also good
        if field_a and field_b and field_a == field_b:
            base_score = 90

    elif match_type == 'hierarchical':
        # Mentor/mentee matching
        if level_diff == 0:
            base_score = 70  # Peer learning
        elif level_diff == 1:
            base_score = 90  # Ideal mentor/mentee
        elif level_diff == 2:
            base_score = 75
        else:
            base_score = 40

    final_score = min(100, base_score)

    logger.debug(f"[EDUCATION] Score={final_score}")

    return final_score


# ============================================================================
# COMBINED MATCHING ENGINE
# ============================================================================

class CriteriaBasedMatchingEngine:
    """
    Multi-criteria speed networking matching engine.

    Combines skill, experience, location, and education matching
    with weighted scoring and fallback strategies.
    """

    def __init__(self, session=None, criteria_config: Dict = None):
        """
        Initialize matching engine.

        Args:
            session: SpeedNetworkingSession instance (optional)
            criteria_config: Custom criteria configuration
        """
        self.session = session
        self.criteria_config = criteria_config or self._default_config()

    def _default_config(self) -> Dict:
        """Default criteria configuration."""
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

    def calculate_combined_score(self, user_a: Dict, user_b: Dict) -> Tuple[float, Dict, bool]:
        """
        Calculate combined match score across all criteria.

        FIXED: Properly normalizes weights and includes probability calculation.

        Args:
            user_a: User profile dict
            user_b: User profile dict

        Returns:
            (final_score, breakdown_dict, is_valid)
        """
        logger.info(f"[MATCH] Calculating score for user_a={user_a.get('user_id')} "
                   f"vs user_b={user_b.get('user_id')}")

        scores = {}
        weights = {}
        required_criteria = []
        failed_required = None

        # ===== STEP 1: Calculate all enabled criterion scores =====
        if self.criteria_config['skill'].get('enabled', True):
            scores['skill'] = calculate_skill_match_score(
                user_a.get('skills', []),
                user_b.get('skills', []),
                self.criteria_config['skill'].get('match_mode', 'complementary')
            )
            weights['skill'] = self.criteria_config['skill'].get('weight', 0.35)
            if self.criteria_config['skill'].get('required', True):
                required_criteria.append('skill')

        if self.criteria_config['experience'].get('enabled', True):
            scores['experience'] = calculate_experience_match_score(
                user_a.get('experience_years', 0),
                user_b.get('experience_years', 0),
                user_a.get('experience_level'),
                user_b.get('experience_level'),
                self.criteria_config['experience'].get('match_type', 'mentorship')
            )
            weights['experience'] = self.criteria_config['experience'].get('weight', 0.30)
            if self.criteria_config['experience'].get('required', True):
                required_criteria.append('experience')

        if self.criteria_config['location'].get('enabled', True):
            scores['location'] = calculate_location_match_score(
                user_a.get('location', {}),
                user_b.get('location', {}),
                self.criteria_config['location'].get('match_strategy', 'radius')
            )
            weights['location'] = self.criteria_config['location'].get('weight', 0.20)
            if self.criteria_config['location'].get('required', False):
                required_criteria.append('location')

        if self.criteria_config['education'].get('enabled', True):
            scores['education'] = calculate_education_match_score(
                user_a.get('education', {}),
                user_b.get('education', {}),
                self.criteria_config['education'].get('match_type', 'same_level')
            )
            weights['education'] = self.criteria_config['education'].get('weight', 0.15)
            if self.criteria_config['education'].get('required', False):
                required_criteria.append('education')

        logger.debug(f"[MATCH] Calculated scores: {scores}, Required: {required_criteria}")

        # ===== STEP 2: Validate required criteria =====
        for criterion in required_criteria:
            threshold = self.criteria_config[criterion].get('threshold', 50)
            if scores.get(criterion, 0) < threshold:
                logger.debug(f"[MATCH] Required criterion '{criterion}' score "
                           f"{scores.get(criterion, 0):.0f} < threshold {threshold}")
                failed_required = criterion
                return 0, scores, False

        # ===== STEP 3: Normalize weights to sum to 1.0 =====
        total_weight = sum(weights.values())
        if total_weight == 0:
            logger.warning("[MATCH] No weights configured, cannot calculate score")
            return 0, scores, False

        normalized_weights = {k: v / total_weight for k, v in weights.items()}
        logger.debug(f"[MATCH] Normalized weights: {normalized_weights}")

        # ===== STEP 4: Calculate weighted final score =====
        weighted_score = 0
        for criterion, weight in normalized_weights.items():
            score = scores.get(criterion, 0)
            weighted_score += score * weight
            logger.debug(f"[MATCH] {criterion}: {score:.0f} * {weight:.2f} = {score * weight:.0f}")

        final_score = min(100, max(0, weighted_score))  # Clamp to 0-100

        # ===== STEP 5: Calculate match probability =====
        probability = self._score_to_probability(final_score, scores, required_criteria)

        logger.info(f"[MATCH] Final score: {final_score:.1f} | Probability: {probability:.0f}% | Breakdown: {scores}")

        return final_score, scores, True

    def _score_to_probability(self, score: float, breakdown: Dict, required_criteria: List[str]) -> float:
        """
        Convert raw score (0-100) to match probability (0-100).

        Logic:
        - 0-50: Linear (0% to 50%)
        - 50-75: Steep gradient (50% to 75%) - threshold crossing boost
        - 75-100: Linear (75% to 100%)

        Args:
            score: Raw score 0-100
            breakdown: Scores for each criterion
            required_criteria: List of required criteria that passed

        Returns:
            Probability 0-100
        """
        if score < 50:
            # Below threshold: linear probability
            probability = score / 100
        elif score < 75:
            # Threshold crossing: steeper gradient
            # 50→75 score maps to 50%→75% probability
            probability = 0.5 + (score - 50) / 100
        else:
            # Above 75: linear to 100%
            probability = 0.75 + (score - 75) / 100

        return min(100, probability * 100)

    def find_best_matches(self, user: Dict, candidate_pool: List[Dict],
                         top_n: int = 5) -> List[Tuple[float, Dict, Dict]]:
        """
        Find top N best matches for a user.

        Args:
            user: Target user profile
            candidate_pool: List of candidate profiles
            top_n: Number of best matches to return

        Returns:
            List of (score, candidate, breakdown) tuples
        """
        logger.info(f"[MATCH] Finding top {top_n} matches for user_id={user.get('user_id')} "
                   f"from {len(candidate_pool)} candidates")

        matches = []

        for candidate in candidate_pool:
            score, breakdown, is_valid = self.calculate_combined_score(user, candidate)

            if is_valid:
                matches.append((score, candidate, breakdown))

        # Sort by score (highest first)
        matches.sort(key=lambda x: x[0], reverse=True)

        result = matches[:top_n]
        logger.info(f"[MATCH] Found {len(result)} valid matches")

        return result

    def find_match_with_fallback(self, user: Dict, candidates: List[Dict],
                                max_fallback_steps: int = 5) -> Tuple[Optional[Tuple], int]:
        """
        Find match with progressive fallback strategy.

        Steps:
        1. Strict matching (as configured)
        2. Relax thresholds by 10% (SKIPPED if only one criterion enabled)
        3. Make location optional
        4. Make education optional
        5. Make experience optional (skill-only)

        Args:
            user: User profile
            candidates: Candidate pool
            max_fallback_steps: Max fallback attempts

        Returns:
            ((score, candidate, breakdown), step) or (None, -1)
        """
        logger.info(f"[FALLBACK] Starting fallback matching (max {max_fallback_steps} steps)")

        original_config = deepcopy(self.criteria_config)

        # Count how many criteria are enabled
        enabled_criteria = sum(
            1 for criterion in CRITERIA_KEYS
            if self.criteria_config.get(criterion, {}).get('enabled', True)
        )
        is_single_criterion = enabled_criteria == 1
        logger.debug(f"[FALLBACK] Single criterion mode: {is_single_criterion}")

        for step in range(max_fallback_steps):
            logger.debug(f"[FALLBACK] Step {step}")

            if step == 0:
                # Step 0: Initial strict matching (use original config)
                pass

            elif step == 1:
                # Step 1: Relax thresholds by 10% (SKIP for single criterion)
                if is_single_criterion:
                    logger.debug("[FALLBACK] Skipping threshold relaxation for single criterion mode")
                    continue
                logger.debug("[FALLBACK] Relaxing thresholds by 10%")
                for criterion in CRITERIA_KEYS:
                    if criterion in self.criteria_config and 'threshold' in self.criteria_config[criterion]:
                        old_threshold = self.criteria_config[criterion]['threshold']
                        new_threshold = old_threshold * 0.9
                        self.criteria_config[criterion]['threshold'] = new_threshold
                        logger.debug(f"[FALLBACK] {criterion}: {old_threshold} → {new_threshold}")

            elif step == 2:
                # Step 2: Make location optional
                logger.debug("[FALLBACK] Making location optional")
                self.criteria_config['location']['required'] = False

            elif step == 3:
                # Step 3: Make education optional
                logger.debug("[FALLBACK] Making education optional")
                self.criteria_config['education']['required'] = False

            elif step == 4:
                # Step 4: Make experience optional (skills-only)
                logger.debug("[FALLBACK] Making experience optional")
                self.criteria_config['experience']['required'] = False

            # For single criterion mode, only try strict matching (step 0)
            if is_single_criterion and step > 0:
                logger.debug("[FALLBACK] Single criterion mode: no further fallback steps")
                break

            # Try to find match with current config
            matches = self.find_best_matches(user, candidates, top_n=1)

            if matches:
                score, candidate, breakdown = matches[0]
                logger.info(f"[FALLBACK] Found match at step {step} with score {score:.1f}")
                self.criteria_config = original_config  # Restore
                return (score, candidate, breakdown), step

        logger.warning("[FALLBACK] No match found after all fallback steps")
        self.criteria_config = original_config  # Restore
        return None, -1

    def handle_missing_data(self, user: Dict, criterion: str) -> Tuple[bool, float]:
        """
        Check if user has data for a criterion.

        Args:
            user: User profile
            criterion: 'skill', 'experience', 'location', 'education'

        Returns:
            (has_data, default_score)
        """
        if criterion == 'skill':
            if not user.get('skills') or len(user.get('skills', [])) == 0:
                return False, 50

        elif criterion == 'experience':
            if user.get('experience_years') is None:
                return False, 50

        elif criterion == 'location':
            if not user.get('location'):
                return False, 50
            loc = user['location']
            if not loc.get('lat') and not loc.get('city'):
                return False, 50

        elif criterion == 'education':
            if not user.get('education'):
                return False, 50

        return True, 100

    def validate_profiles(self, user_a: Dict, user_b: Dict,
                         mode: str = 'lenient') -> Tuple[Dict, Dict]:
        """
        Validate and clean user profiles.

        Modes:
        - 'strict': Require all fields
        - 'lenient': Fill missing with defaults
        - 'partial': Only use available fields

        Args:
            user_a, user_b: User profiles
            mode: Validation mode

        Returns:
            (cleaned_user_a, cleaned_user_b)
        """
        if mode == 'lenient':
            # Fill missing fields with defaults
            user_a = self._fill_defaults(user_a)
            user_b = self._fill_defaults(user_b)

        return user_a, user_b

    @staticmethod
    def _fill_defaults(user: Dict) -> Dict:
        """Fill missing user fields with defaults."""
        if not user.get('skills'):
            user['skills'] = [{'name': 'Unknown', 'level': 2}]
        if user.get('experience_years') is None:
            user['experience_years'] = 2
        if not user.get('location'):
            user['location'] = {'city': 'Unknown'}
        if not user.get('education'):
            user['education'] = {'field': 'Unknown', 'level': 1}
        return user

    def find_match_by_proximity(self, user: Dict, candidates: List[Dict]) -> Optional[Tuple[float, Dict, Dict]]:
        """
        Find match by geographic proximity - final fallback when criteria fail.

        Picks the candidate closest to the user geographically, even if very far.
        Used when all other matching strategies (criteria-based, fallback thresholds) fail.

        Args:
            user: User profile dict
            candidates: List of candidate profile dicts

        Returns:
            Tuple of (score, candidate, breakdown) or None
            - score: Based on distance (0-100)
            - candidate: Selected candidate profile
            - breakdown: {'proximity': score, 'distance_km': distance}
        """
        user_location = user.get('location', {})

        result = find_closest_candidate_by_distance(user_location, candidates)

        if not result:
            logger.warning("[PROXIMITY_FALLBACK] No candidates with valid coordinates")
            return None

        closest_candidate, distance_km = result

        # Convert distance to score using same logic as location matching
        if distance_km < 10:
            score = 100
        elif distance_km < 50:
            score = 80
        elif distance_km < 100:
            score = 60
        elif distance_km < 200:
            score = 40
        elif distance_km < 500:
            score = 20
        else:
            score = 10  # Always give a score if we found someone

        breakdown = {
            'proximity': score,
            'distance_km': round(distance_km, 2)
        }

        logger.info(
            f"[PROXIMITY_FALLBACK] Matched by proximity: "
            f"distance={distance_km:.1f}km, score={score:.1f}, "
            f"candidate_id={closest_candidate.get('user_id')}"
        )

        return (score, closest_candidate, breakdown)

    def get_score_explanation(self, scores: Dict) -> str:
        """
        Generate human-readable explanation of match scores.

        Args:
            scores: Score breakdown dict

        Returns:
            Formatted string explanation
        """
        lines = ["Match Score Breakdown:"]
        for criterion, score in scores.items():
            lines.append(f"  {criterion.capitalize()}: {score:.1f}/100")
        return "\n".join(lines)
