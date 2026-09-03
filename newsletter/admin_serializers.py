from rest_framework import serializers

from .models import NewsletterAudience, NewsletterCampaign, NewsletterCategory


class NewsletterAdminCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = NewsletterCategory
        fields = ["slug", "name", "description", "is_active"]
        read_only_fields = fields


class NewsletterAudienceAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewsletterAudience
        fields = [
            "uuid",
            "name",
            "description",
            "audience_type",
            "status",
            "estimated_count",
            "is_active",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "uuid",
            "estimated_count",
            "created_at",
            "updated_at",
        ]

    def validate_name(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Audience name is required.")
        return value.strip()


class NewsletterCampaignSerializer(serializers.ModelSerializer):
    audiences = NewsletterAdminCategorySerializer(many=True, read_only=True)
    mautic_email_id = serializers.SerializerMethodField()
    audience_slugs = serializers.ListField(
        child=serializers.SlugField(),
        write_only=True,
        required=False,
        allow_empty=True,
    )

    class Meta:
        model = NewsletterCampaign
        fields = [
            "uuid",
            "name",
            "subject",
            "preview_text",
            "from_name",
            "from_email",
            "html_content",
            "plain_text",
            "status",
            "audiences",
            "audience_slugs",
            "scheduled_at",
            "send_started_at",
            "sent_at",
            "mautic_email_id",
            "last_synced_to_mautic_at",
            "last_error",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "uuid",
            "status",
            "scheduled_at",
            "send_started_at",
            "sent_at",
            "mautic_email_id",
            "last_synced_to_mautic_at",
            "last_error",
            "created_at",
            "updated_at",
        ]

    def validate_audience_slugs(self, value):
        slugs = list(dict.fromkeys(value))
        categories = {
            category.slug: category
            for category in NewsletterCategory.objects.filter(slug__in=slugs)
        }
        missing = sorted(set(slugs) - set(categories))
        if missing:
            raise serializers.ValidationError(
                f"Unknown newsletter category: {', '.join(missing)}"
            )

        inactive = sorted(
            slug for slug, category in categories.items() if not category.is_active
        )
        if inactive:
            raise serializers.ValidationError(
                f"Inactive newsletter category: {', '.join(inactive)}"
            )
        return slugs

    def validate_name(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Campaign name is required.")
        return value.strip()

    def get_mautic_email_id(self, obj):
        return obj.mautic_email_id or None


class NewsletterCampaignTestEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()


class NewsletterCampaignScheduleSerializer(serializers.Serializer):
    scheduled_at = serializers.DateTimeField(required=True)
