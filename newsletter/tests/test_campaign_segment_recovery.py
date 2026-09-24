"""Stale Subscription List -> Mautic segment mapping recovery.

A Subscription List stores the id of its Mautic segment. When that segment is
deleted in Mautic the stored id goes stale, and every broadcast targeting the
list is rejected by the provider. Broadcast synchronization therefore validates
the mapping first and repairs it only when Mautic definitively proves the
segment is gone.
"""

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from newsletter.campaign_services import (
    CampaignMauticSyncFailed,
    CampaignMauticUnavailable,
    sync_campaign_for_worker_delivery,
    sync_campaign_to_mautic,
)
from newsletter.category_segment_services import (
    ensure_category_segment,
    repair_campaign_audience_segments,
)
from newsletter.mautic.exceptions import PermanentMauticError, TemporaryMauticError
from newsletter.models import (
    NewsletterCampaign,
    NewsletterCategory,
    NewsletterSubscription,
    NewsletterSyncEvent,
)


User = get_user_model()

MISSING = PermanentMauticError("Mautic API request failed (HTTP 404): not found")
FORBIDDEN = PermanentMauticError("Mautic API request failed (HTTP 403): denied")
UNAVAILABLE = TemporaryMauticError("Mautic API request failed (HTTP 503)")


def static_segment(segment_id, alias="news"):
    return {"id": segment_id, "alias": alias, "filters": []}


def dynamic_segment(segment_id, alias="news"):
    return {
        "id": segment_id,
        "alias": alias,
        "filters": [{"glue": "and", "field": "email", "operator": "!empty"}],
    }


class SegmentRecoveryBase(TestCase):
    def build_category(self, *, slug="news", segment_id="1"):
        return NewsletterCategory.objects.create(
            name="Test News",
            slug=slug,
            mautic_segment_id=segment_id,
        )

    def build_campaign(self, category):
        campaign = NewsletterCampaign.objects.create(
            name="Recovery Broadcast",
            subject="Subject",
            from_name="ECP",
            from_email="news@example.test",
            html_content="<p>Hello</p>",
        )
        campaign.audiences.set([category])
        return campaign

    def client_with(self, **behaviour):
        client = Mock()
        for name, value in behaviour.items():
            attr = getattr(client, name)
            if isinstance(value, Exception):
                attr.side_effect = value
            elif callable(value) and not isinstance(value, Mock):
                attr.side_effect = value
            else:
                attr.return_value = value
        return client


class EnsureCategorySegmentTests(SegmentRecoveryBase):
    # A — a valid mapping is left alone
    def test_valid_mapping_is_kept_and_creates_nothing(self):
        category = self.build_category(segment_id="5")
        client = self.client_with(get_segment=static_segment("5"))

        segment_id, changed = ensure_category_segment(category, client=client)

        self.assertEqual(segment_id, "5")
        self.assertFalse(changed)
        client.create_segment.assert_not_called()
        client.list_segments.assert_not_called()

    # B — stale mapping, no alias match, new segment created
    def test_missing_segment_is_replaced_with_a_new_static_segment(self):
        category = self.build_category(segment_id="1")
        client = self.client_with(
            get_segment=MISSING,
            list_segments={"lists": []},
            create_segment={"id": 2},
        )

        segment_id, changed = ensure_category_segment(category, client=client)

        self.assertEqual(segment_id, "2")
        self.assertTrue(changed)
        client.create_segment.assert_called_once()
        payload = client.create_segment.call_args.args[0]
        self.assertEqual(payload["alias"], "news")
        self.assertEqual(payload["filters"], [])
        category.refresh_from_db()
        self.assertEqual(category.mautic_segment_id, "2")

    # C — stale mapping, exact static alias reused
    def test_exact_static_alias_is_reused_instead_of_creating_a_duplicate(self):
        category = self.build_category(segment_id="1")
        client = self.client_with(
            get_segment=MISSING,
            list_segments={"lists": [static_segment(9, alias="news")]},
        )

        segment_id, changed = ensure_category_segment(category, client=client)

        self.assertEqual(segment_id, "9")
        self.assertTrue(changed)
        client.create_segment.assert_not_called()
        category.refresh_from_db()
        self.assertEqual(category.mautic_segment_id, "9")

    def test_alias_match_must_be_exact(self):
        category = self.build_category(segment_id="1")
        # Provider search is fuzzy; a near-miss must not be adopted.
        client = self.client_with(
            get_segment=MISSING,
            list_segments={"lists": [static_segment(9, alias="news-archive")]},
            create_segment={"id": 3},
        )

        segment_id, _ = ensure_category_segment(category, client=client)

        self.assertEqual(segment_id, "3")
        client.create_segment.assert_called_once()

    # D — dynamic alias conflict refused
    def test_dynamic_alias_conflict_is_refused(self):
        category = self.build_category(segment_id="1")
        client = self.client_with(
            get_segment=MISSING,
            list_segments={"lists": [dynamic_segment(9, alias="news")]},
        )

        with self.assertRaisesRegex(PermanentMauticError, "dynamic"):
            ensure_category_segment(category, client=client)

        client.create_segment.assert_not_called()
        category.refresh_from_db()
        self.assertEqual(category.mautic_segment_id, "1")

    def test_mapped_segment_that_became_dynamic_is_refused(self):
        category = self.build_category(segment_id="5")
        client = self.client_with(get_segment=dynamic_segment("5"))

        with self.assertRaisesRegex(PermanentMauticError, "dynamic"):
            ensure_category_segment(category, client=client)

    # E — alias already owned by another category
    def test_alias_owned_by_another_category_is_refused(self):
        other = NewsletterCategory.objects.create(
            name="Other",
            slug="other",
            mautic_segment_id="9",
        )
        category = self.build_category(segment_id="1")
        client = self.client_with(
            get_segment=MISSING,
            list_segments={"lists": [static_segment(9, alias="news")]},
        )

        with self.assertRaisesRegex(PermanentMauticError, "already mapped"):
            ensure_category_segment(category, client=client)

        client.create_segment.assert_not_called()
        category.refresh_from_db()
        self.assertEqual(category.mautic_segment_id, "1")
        self.assertEqual(other.mautic_segment_id, "9")

    # F — temporary errors never trigger creation
    def test_temporary_provider_error_never_creates_a_replacement(self):
        category = self.build_category(segment_id="1")
        client = self.client_with(get_segment=UNAVAILABLE)

        with self.assertRaises(TemporaryMauticError):
            ensure_category_segment(category, client=client)

        client.create_segment.assert_not_called()
        category.refresh_from_db()
        self.assertEqual(category.mautic_segment_id, "1")

    # G — non-404 permanent errors propagate untouched
    def test_permission_error_propagates_without_repair(self):
        category = self.build_category(segment_id="1")
        client = self.client_with(get_segment=FORBIDDEN)

        with self.assertRaises(PermanentMauticError):
            ensure_category_segment(category, client=client)

        client.create_segment.assert_not_called()
        category.refresh_from_db()
        self.assertEqual(category.mautic_segment_id, "1")


@override_settings(MAUTIC_SYNC_ENABLED=True)
class RepairCampaignAudienceSegmentsTests(SegmentRecoveryBase):
    def test_repair_queues_reconciliation_for_every_subscription_state(self):
        category = self.build_category(segment_id="1")
        subscribed = User.objects.create_user(
            username="sub", email="sub@example.test", password="pw"
        )
        unsubscribed = User.objects.create_user(
            username="unsub", email="unsub@example.test", password="pw"
        )
        NewsletterSubscription.objects.create(
            user=subscribed,
            category=category,
            is_subscribed=True,
            subscribed_at=timezone.now(),
        )
        NewsletterSubscription.objects.create(
            user=unsubscribed,
            category=category,
            is_subscribed=False,
            unsubscribed_at=timezone.now(),
        )
        campaign = self.build_campaign(category)
        client = self.client_with(
            get_segment=MISSING,
            list_segments={"lists": []},
            create_segment={"id": 2},
        )

        repaired = repair_campaign_audience_segments(campaign, client=client)

        self.assertEqual(repaired, 1)
        # Both states are reconciled: the new segment must learn who belongs in
        # it and who must stay out of it.
        events = NewsletterSyncEvent.objects.filter(category=category)
        self.assertEqual(events.count(), 2)
        self.assertEqual(
            sorted(events.values_list("desired_subscribed", flat=True)),
            [False, True],
        )

    def test_valid_mapping_queues_no_reconciliation(self):
        category = self.build_category(segment_id="5")
        campaign = self.build_campaign(category)
        client = self.client_with(get_segment=static_segment("5"))

        repaired = repair_campaign_audience_segments(campaign, client=client)

        self.assertEqual(repaired, 0)
        self.assertEqual(NewsletterSyncEvent.objects.count(), 0)

    # H — repeated repair is idempotent
    def test_second_repair_reuses_the_valid_mapping(self):
        category = self.build_category(segment_id="1")
        campaign = self.build_campaign(category)
        first = self.client_with(
            get_segment=MISSING,
            list_segments={"lists": []},
            create_segment={"id": 2},
        )
        repair_campaign_audience_segments(campaign, client=first)

        second = self.client_with(get_segment=static_segment("2"))
        repaired = repair_campaign_audience_segments(campaign, client=second)

        self.assertEqual(repaired, 0)
        second.create_segment.assert_not_called()
        category.refresh_from_db()
        self.assertEqual(category.mautic_segment_id, "2")

    # J — the same request must use the repaired id
    def test_prefetched_audiences_are_refreshed_after_repair(self):
        category = self.build_category(segment_id="1")
        created = self.build_campaign(category)

        # Reload exactly the way the sync paths do, so the audience objects are
        # prefetched while still holding the stale id.
        campaign = NewsletterCampaign.objects.prefetch_related("audiences").get(
            pk=created.pk
        )
        self.assertEqual(
            [c.mautic_segment_id for c in campaign.audiences.all()],
            ["1"],
        )

        client = self.client_with(
            get_segment=MISSING,
            list_segments={"lists": []},
            create_segment={"id": 2},
        )
        repair_campaign_audience_segments(campaign, client=client)

        self.assertEqual(
            [c.mautic_segment_id for c in campaign.audiences.all()],
            ["2"],
            "the prefetch cache must not keep serving the stale segment id",
        )


@override_settings(MAUTIC_SYNC_ENABLED=True)
class BroadcastSyncUsesRepairedSegmentTests(SegmentRecoveryBase):
    """The mandatory same-request regression: payload must carry the new id."""

    def run_sync(self, sync_fn, campaign, provider):
        # The repair helper builds its own service-account client; the email
        # mutation uses the sync client. Both are stubbed with `provider`.
        with patch(
            "newsletter.category_segment_services.MauticClient",
            return_value=provider,
        ), patch(
            "newsletter.campaign_services.MauticClient",
            return_value=provider,
        ):
            return sync_fn(campaign)

    def stale_provider(self):
        return self.client_with(
            get_segment=MISSING,
            list_segments={"lists": []},
            create_segment={"id": 2},
            create_email={"id": "77"},
        )

    def test_interactive_sync_sends_the_repaired_segment_id(self):
        category = self.build_category(segment_id="1")
        campaign = NewsletterCampaign.objects.prefetch_related("audiences").get(
            pk=self.build_campaign(category).pk
        )
        provider = self.stale_provider()

        self.run_sync(sync_campaign_to_mautic, campaign, provider)

        payload = provider.create_email.call_args.args[0]
        self.assertEqual(payload["lists"], [2], "must not send the stale id 1")
        self.assertEqual(payload["emailType"], "list")

    def test_worker_sync_sends_the_repaired_segment_id(self):
        category = self.build_category(segment_id="1")
        campaign = NewsletterCampaign.objects.prefetch_related("audiences").get(
            pk=self.build_campaign(category).pk
        )
        provider = self.stale_provider()

        self.run_sync(sync_campaign_for_worker_delivery, campaign, provider)

        payload = provider.create_email.call_args.args[0]
        self.assertEqual(payload["lists"], [2])

    def test_valid_mapping_sends_the_existing_segment_id(self):
        category = self.build_category(segment_id="5")
        campaign = NewsletterCampaign.objects.prefetch_related("audiences").get(
            pk=self.build_campaign(category).pk
        )
        provider = self.client_with(
            get_segment=static_segment("5"),
            create_email={"id": "77"},
        )

        self.run_sync(sync_campaign_to_mautic, campaign, provider)

        payload = provider.create_email.call_args.args[0]
        self.assertEqual(payload["lists"], [5])
        provider.create_segment.assert_not_called()

    def test_temporary_segment_error_surfaces_as_unavailable_without_sending(self):
        category = self.build_category(segment_id="1")
        campaign = NewsletterCampaign.objects.prefetch_related("audiences").get(
            pk=self.build_campaign(category).pk
        )
        provider = self.client_with(get_segment=UNAVAILABLE, create_email={"id": "77"})

        with self.assertRaises(CampaignMauticUnavailable):
            self.run_sync(sync_campaign_to_mautic, campaign, provider)

        provider.create_email.assert_not_called()
        provider.create_segment.assert_not_called()

    def test_permanent_segment_error_surfaces_as_sync_failed_without_sending(self):
        category = self.build_category(segment_id="1")
        campaign = NewsletterCampaign.objects.prefetch_related("audiences").get(
            pk=self.build_campaign(category).pk
        )
        provider = self.client_with(get_segment=FORBIDDEN, create_email={"id": "77"})

        with self.assertRaises(CampaignMauticSyncFailed):
            self.run_sync(sync_campaign_to_mautic, campaign, provider)

        provider.create_email.assert_not_called()

    def test_segment_repair_never_receives_an_asserted_client(self):
        """Infrastructure repair stays on the service account."""
        category = self.build_category(segment_id="1")
        campaign = NewsletterCampaign.objects.prefetch_related("audiences").get(
            pk=self.build_campaign(category).pk
        )
        provider = self.stale_provider()
        asserted = self.client_with(create_email={"id": "77"})
        asserted._uses_asserted_user = Mock(return_value=True)

        # campaign_services builds the service-account client used for segment
        # work; the asserted client is only ever used for the email mutation.
        with patch(
            "newsletter.campaign_services.MauticClient",
            return_value=provider,
        ):
            sync_campaign_to_mautic(campaign, client=asserted)

        # Segment work went to the service-account client only.
        provider.create_segment.assert_called_once()
        asserted.create_segment.assert_not_called()
        # The email mutation went to the asserted client only.
        asserted.create_email.assert_called_once()
        provider.create_email.assert_not_called()
