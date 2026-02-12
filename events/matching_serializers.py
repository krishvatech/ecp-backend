"""
Serializers for Speed Networking Matching Rules and Profiles.
"""

from rest_framework import serializers
from .models import SpeedNetworkingRule, UserMatchingProfile, MatchHistory


class SpeedNetworkingRuleSerializer(serializers.ModelSerializer):
    """
    Serializer for SpeedNetworkingRule.
    Handles creation and update of matching rules.
    """

    class Meta:
        model = SpeedNetworkingRule
        fields = [
            'id',
            'name',
            'rule_type',
            'category',
            'segment_a_type',
            'segment_a_values',
            'segment_b_type',
            'segment_b_values',
            'is_active',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate(self, data):
        """
        Validate rule configuration.
        """
        rule_type = data.get('rule_type')
        segment_a = data.get('segment_a_type', '')
        segment_b = data.get('segment_b_type', '')

        # Negative rules should not have segment_b
        if rule_type == 'NEGATIVE' and segment_b:
            raise serializers.ValidationError(
                "Negative rules should not define segment B"
            )

        # Positive rules must have segment_b
        if rule_type == 'POSITIVE' and not segment_b:
            raise serializers.ValidationError(
                "Positive rules must define both segment A and segment B"
            )

        # Check for cross-category mixing (simplified check)
        category_a = self._extract_category(segment_a)
        category_b = self._extract_category(segment_b)

        if category_b and category_a != category_b:
            raise serializers.ValidationError(
                "Mixing segment categories (e.g., 'ticket_tier' with 'user_type') "
                "is not allowed"
            )

        return data

    @staticmethod
    def _extract_category(segment_type):
        """Extract category from segment type."""
        if ':' in segment_type:
            return segment_type.split(':')[0]
        return segment_type

    def to_representation(self, instance):
        """
        Add rule description for frontend display.
        """
        data = super().to_representation(instance)
        data['description'] = self._generate_description(instance)
        return data

    @staticmethod
    def _generate_description(rule):
        """Generate human-readable description of rule."""
        if rule.rule_type == 'POSITIVE':
            return (
                f"{rule.segment_a_type} {rule.segment_a_values} "
                f"↔ {rule.segment_b_type} {rule.segment_b_values}"
            )
        else:  # NEGATIVE
            return f"Block {rule.segment_a_type} {rule.segment_a_values}"


class UserMatchingProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for UserMatchingProfile.
    Read-only - profiles are computed, not user-created.
    """

    user_id = serializers.IntegerField(source='user.id', read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = UserMatchingProfile
        fields = [
            'id',
            'user_id',
            'username',
            'full_name',
            'user_type',
            'ticket_tier',
            'custom_fields',
            'can_match',
            'computed_at',
        ]
        read_only_fields = fields

    def get_full_name(self, obj):
        """Get user's full name."""
        return obj.user.get_full_name() or obj.user.username


class MatchHistorySerializer(serializers.ModelSerializer):
    """
    Serializer for MatchHistory.
    Shows all past matches for a user.
    """

    matched_with_id = serializers.IntegerField(source='matched_with.id', read_only=True)
    matched_with_username = serializers.CharField(
        source='matched_with.username', read_only=True
    )
    matched_with_name = serializers.SerializerMethodField()
    match_duration_seconds = serializers.SerializerMethodField()

    class Meta:
        model = MatchHistory
        fields = [
            'id',
            'matched_with_id',
            'matched_with_username',
            'matched_with_name',
            'matched_at',
            'match_duration_seconds',
        ]
        read_only_fields = fields

    def get_matched_with_name(self, obj):
        """Get matched user's full name."""
        return obj.matched_with.get_full_name() or obj.matched_with.username

    def get_match_duration_seconds(self, obj):
        """Get match duration if available."""
        return obj.duration_seconds


class RuleDebugInfoSerializer(serializers.Serializer):
    """
    Provides debug information for rule matching.
    """

    rule_id = serializers.IntegerField()
    rule_name = serializers.CharField()
    rule_type = serializers.CharField()
    user_matches_segment_a = serializers.BooleanField()
    user_matches_segment_b = serializers.BooleanField()
    eligible_candidates_count = serializers.IntegerField()
    eligible_candidates_ids = serializers.ListField(child=serializers.IntegerField())


class CandidateFilteringDebugSerializer(serializers.Serializer):
    """
    Debug output showing how candidates were filtered.
    """

    user_id = serializers.IntegerField()
    available_candidates = serializers.IntegerField()
    after_rule_filtering = serializers.IntegerField()
    after_history_filtering = serializers.IntegerField()
    eligible_candidates = serializers.ListField(child=serializers.IntegerField())
    matching_rules_applied = RuleDebugInfoSerializer(many=True)


class BulkRuleCreateSerializer(serializers.Serializer):
    """
    Allows creating multiple rules in a single request.
    """

    rules = SpeedNetworkingRuleSerializer(many=True)

    def validate_rules(self, rules):
        """Validate each rule."""
        if not rules:
            raise serializers.ValidationError("At least one rule must be provided")
        return rules

    def create(self, validated_data):
        """Create multiple rules."""
        from .models import SpeedNetworkingRule

        session = self.context['session']
        rules_data = validated_data['rules']

        created_rules = []
        for rule_data in rules_data:
            rule = SpeedNetworkingRule.objects.create(
                session=session,
                **rule_data
            )
            created_rules.append(rule)

        return {'rules': created_rules}


class SessionMatchingStatsSerializer(serializers.Serializer):
    """
    Statistics about matching in a session.
    """

    total_matches = serializers.IntegerField()
    active_matches = serializers.IntegerField()
    completed_matches = serializers.IntegerField()
    skipped_matches = serializers.IntegerField()
    avg_match_duration_seconds = serializers.FloatField()
    rule_count = serializers.IntegerField()
    rule_compliance_rate = serializers.FloatField()
    queue_size = serializers.IntegerField()
    avg_wait_time_seconds = serializers.FloatField()
