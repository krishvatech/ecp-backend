from django.db import transaction
from rest_framework import serializers

from .models import NewsletterCampaign, NewsletterCategory


class CampaignNotEditable(serializers.ValidationError):
    pass


def list_campaigns():
    return (
        NewsletterCampaign.objects.select_related("created_by", "updated_by")
        .prefetch_related("audiences")
        .order_by("-created_at", "-id")
    )


def list_active_categories():
    return NewsletterCategory.objects.filter(is_active=True).order_by("name")


def get_campaign(uuid):
    return (
        NewsletterCampaign.objects.select_related("created_by", "updated_by")
        .prefetch_related("audiences")
        .get(uuid=uuid)
    )


def _categories_from_slugs(slugs):
    if slugs is None:
        return None
    unique_slugs = list(dict.fromkeys(slugs))
    return list(
        NewsletterCategory.objects.filter(slug__in=unique_slugs, is_active=True)
    )


@transaction.atomic
def create_campaign(validated_data, *, user):
    audience_slugs = validated_data.pop("audience_slugs", [])
    campaign = NewsletterCampaign.objects.create(
        **validated_data,
        status=NewsletterCampaign.Status.DRAFT,
        created_by=user,
        updated_by=user,
    )
    campaign.audiences.set(_categories_from_slugs(audience_slugs))
    return campaign


@transaction.atomic
def update_campaign(campaign, validated_data, *, user):
    if campaign.status != NewsletterCampaign.Status.DRAFT:
        raise CampaignNotEditable("Only draft newsletter campaigns can be edited.")

    audience_slugs = validated_data.pop("audience_slugs", None)
    for field, value in validated_data.items():
        setattr(campaign, field, value)
    campaign.updated_by = user
    campaign.save()

    categories = _categories_from_slugs(audience_slugs)
    if categories is not None:
        campaign.audiences.set(categories)
    return campaign


@transaction.atomic
def delete_draft_campaign(campaign):
    if campaign.status != NewsletterCampaign.Status.DRAFT:
        raise CampaignNotEditable("Only draft newsletter campaigns can be deleted.")
    campaign.delete()
