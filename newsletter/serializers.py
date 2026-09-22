from rest_framework import serializers


class NewsletterPreferenceSerializer(serializers.Serializer):
    slug = serializers.SlugField()
    name = serializers.CharField()
    description = serializers.CharField(allow_blank=True)
    # Effective state: the member's choice AND no Mautic email suppression.
    subscribed = serializers.BooleanField()
    # The member's own stored choice, unaffected by Mautic suppression.
    locally_subscribed = serializers.BooleanField()
    # True when this choice is currently overridden by a Mautic block.
    suppressed = serializers.BooleanField()


class NewsletterPreferenceUpdateItemSerializer(serializers.Serializer):
    slug = serializers.SlugField()
    subscribed = serializers.BooleanField()


class NewsletterPreferencesUpdateSerializer(serializers.Serializer):
    preferences = NewsletterPreferenceUpdateItemSerializer(many=True)

    def validate_preferences(self, value):
        slugs = [item["slug"] for item in value]
        if len(slugs) != len(set(slugs)):
            raise serializers.ValidationError(
                "Each newsletter category may appear only once."
            )
        return value


class NewsletterEmailSuppressionSerializer(serializers.Serializer):
    """Why Mautic is currently withholding email from this member, if it is."""

    suppressed = serializers.BooleanField()
    reason = serializers.CharField(allow_blank=True)
    # True only for a voluntary opt-out an explicit re-subscribe can lift.
    reversible = serializers.BooleanField()
    suppressed_at = serializers.DateTimeField(allow_null=True)


class NewsletterPreferencesResponseSerializer(serializers.Serializer):
    preferences = NewsletterPreferenceSerializer(many=True)
    email_suppression = NewsletterEmailSuppressionSerializer()
