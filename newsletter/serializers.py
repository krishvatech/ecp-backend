from rest_framework import serializers


class NewsletterPreferenceSerializer(serializers.Serializer):
    slug = serializers.SlugField()
    name = serializers.CharField()
    description = serializers.CharField(allow_blank=True)
    subscribed = serializers.BooleanField()


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


class NewsletterPreferencesResponseSerializer(serializers.Serializer):
    preferences = NewsletterPreferenceSerializer(many=True)
