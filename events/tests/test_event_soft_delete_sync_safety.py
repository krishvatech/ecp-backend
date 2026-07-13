from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from community.models import Community
from orders.models import Order, OrderItem
from events.models import (
    Event,
    EventParticipant,
    EventPlatform,
    EventPublication,
    EventRegistration,
    ExternalEventMapping,
    PlatformSyncJob,
)
from events.views import EventViewSet


@override_settings(
    SALEOR_ENABLED=False,
    EVENT_PLATFORM_SYNC_TRIGGER_ON_COMMIT=False,
)
class EventSoftDeleteSyncSafetyTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.owner = User.objects.create_superuser(
            username="event-owner",
            email="owner@example.com",
            password="test-pass",
        )
        self.attendee = User.objects.create_user(
            username="attendee",
            email="attendee@example.com",
            password="test-pass",
        )
        self.community = Community.objects.create(
            name="Lifecycle Test Community",
            owner=self.owner,
        )
        self.imma, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect",
            defaults={
                "name": "IMAA Connect",
                "is_active": True,
                "display_order": 10,
            },
        )
        self.manda, _ = EventPlatform.objects.update_or_create(
            slug="manda",
            defaults={
                "name": "MANDA",
                "is_active": True,
                "display_order": 20,
            },
        )

    def make_event(self, **overrides):
        defaults = {
            "community": self.community,
            "created_by": self.owner,
            "title": "Lifecycle Test Event",
            "description": "Test event",
            "status": "published",
            "start_time": timezone.now() + timezone.timedelta(days=1),
            "end_time": timezone.now() + timezone.timedelta(days=1, hours=2),
            "is_free": False,
            "price": Decimal("100.00"),
        }
        defaults.update(overrides)
        event = Event(**defaults)
        # Avoid unrelated Saleor post-save work while building test fixtures.
        event.skip_saleor_sync = True
        event.save()
        EventPublication.objects.get_or_create(
            event=event,
            platform=self.imma,
            defaults={"is_enabled": True},
        )
        return event

    def call_action(self, event, action, method="post", data=None):
        view = EventViewSet.as_view({method: action})
        request_method = getattr(self.factory, method)
        request = request_method(
            f"/api/events/{event.pk}/{action}/",
            data or {},
            format="json",
        )
        force_authenticate(request, user=self.owner)
        return view(request, pk=str(event.pk))

    def test_cancel_preserves_orders_participants_registrations_and_enqueues_only_event_disable(self):
        event = self.make_event(
            saleor_product_id="UHJvZHVjdDox",
            saleor_variant_id="UHJvZHVjdFZhcmlhbnQ6MQ==",
        )
        EventPublication.objects.create(event=event, platform=self.manda, is_enabled=True)
        registration = EventRegistration.objects.create(event=event, user=self.attendee)
        participant = EventParticipant.objects.create(
            event=event,
            participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
            role=EventParticipant.ROLE_SPEAKER,
            user=self.attendee,
        )
        order = Order.objects.create(
            user=self.attendee,
            status="paid",
            currency="usd",
            subtotal=Decimal("100.00"),
            total=Decimal("100.00"),
        )
        order_item = OrderItem.objects.create(
            order=order,
            event=event,
            quantity=1,
            unit_price=Decimal("100.00"),
            line_total=Decimal("100.00"),
        )
        canonical_id = event.canonical_event_id

        with self.captureOnCommitCallbacks(execute=True):
            response = self.call_action(
                event,
                "cancel",
                data={
                    "cancellation_message": "Cancelled for testing",
                    "notify_participants": False,
                },
            )

        self.assertEqual(response.status_code, 200)
        event.refresh_from_db()
        self.assertEqual(event.status, "cancelled")
        self.assertEqual(event.canonical_event_id, canonical_id)
        self.assertEqual(event.saleor_product_id, "UHJvZHVjdDox")
        self.assertEqual(event.saleor_variant_id, "UHJvZHVjdFZhcmlhbnQ6MQ==")
        self.assertTrue(EventRegistration.objects.filter(pk=registration.pk).exists())
        self.assertTrue(EventParticipant.objects.filter(pk=participant.pk).exists())
        self.assertTrue(Order.objects.filter(pk=order.pk).exists())
        self.assertTrue(OrderItem.objects.filter(pk=order_item.pk).exists())

        self.assertTrue(
            PlatformSyncJob.objects.filter(
                event=event,
                platform=self.manda,
                job_type=PlatformSyncJob.JobType.EVENT_DISABLE,
            ).exists()
        )
        self.assertFalse(
            PlatformSyncJob.objects.filter(
                event=event,
                job_type=PlatformSyncJob.JobType.PARTICIPANT_CANCEL,
            ).exists()
        )


    def test_future_published_event_can_soft_delete_without_data_loss(self):
        event = self.make_event(
            saleor_product_id="UHJvZHVjdDoz",
            saleor_variant_id="UHJvZHVjdFZhcmlhbnQ6Mw==",
        )
        EventPublication.objects.create(event=event, platform=self.manda, is_enabled=True)
        registration = EventRegistration.objects.create(event=event, user=self.attendee)
        participant = EventParticipant.objects.create(
            event=event,
            participant_type=EventParticipant.PARTICIPANT_TYPE_STAFF,
            role=EventParticipant.ROLE_SPEAKER,
            user=self.attendee,
        )
        order = Order.objects.create(
            user=self.attendee,
            status="paid",
            currency="usd",
            subtotal=Decimal("100.00"),
            total=Decimal("100.00"),
        )
        order_item = OrderItem.objects.create(
            order=order,
            event=event,
            quantity=1,
            unit_price=Decimal("100.00"),
            line_total=Decimal("100.00"),
        )
        canonical_id = event.canonical_event_id

        with self.captureOnCommitCallbacks(execute=True):
            archive_response = self.call_action(
                event,
                "soft_delete",
                data={"deletion_reason": "Removed from the platform"},
            )

        self.assertEqual(archive_response.status_code, 200)
        self.assertEqual(archive_response.data["display_status"], "deleted")
        self.assertTrue(archive_response.data["database_record_preserved"])
        self.assertFalse(archive_response.data["visible_in_event_lists"])
        self.assertFalse(archive_response.data["cancellation_email_sent"])
        event.refresh_from_db()
        self.assertEqual(event.status, "archived")
        self.assertEqual(event.archived_from_status, "published")
        self.assertTrue(event.is_hidden)
        self.assertIsNone(event.cancelled_at)
        self.assertEqual(event.cancellation_message, "")
        self.assertEqual(event.canonical_event_id, canonical_id)
        self.assertEqual(event.saleor_product_id, "UHJvZHVjdDoz")
        self.assertEqual(event.saleor_variant_id, "UHJvZHVjdFZhcmlhbnQ6Mw==")
        self.assertTrue(EventRegistration.objects.filter(pk=registration.pk).exists())
        self.assertTrue(EventParticipant.objects.filter(pk=participant.pk).exists())
        self.assertTrue(Order.objects.filter(pk=order.pk).exists())
        self.assertTrue(OrderItem.objects.filter(pk=order_item.pk).exists())
        self.assertTrue(
            PlatformSyncJob.objects.filter(
                event=event,
                platform=self.manda,
                job_type=PlatformSyncJob.JobType.EVENT_DISABLE,
            ).exists()
        )
        self.assertFalse(
            PlatformSyncJob.objects.filter(
                event=event,
                job_type=PlatformSyncJob.JobType.PARTICIPANT_CANCEL,
            ).exists()
        )

        with self.captureOnCommitCallbacks(execute=True):
            restore_response = self.call_action(event, "restore")

        self.assertEqual(restore_response.status_code, 200)
        event.refresh_from_db()
        self.assertEqual(event.status, "published")
        self.assertFalse(event.is_hidden)
        self.assertEqual(event.canonical_event_id, canonical_id)
        self.assertTrue(EventRegistration.objects.filter(pk=registration.pk).exists())
        self.assertTrue(EventParticipant.objects.filter(pk=participant.pk).exists())
        self.assertTrue(OrderItem.objects.filter(pk=order_item.pk).exists())


    def test_lifecycle_options_allow_soft_delete_but_not_hard_delete(self):
        event = self.make_event(status="published")

        response = self.call_action(event, "lifecycle_options", method="get")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["can_archive"])
        self.assertTrue(response.data["can_soft_delete"])
        self.assertFalse(response.data["can_hard_delete"])
        self.assertTrue(response.data["can_cancel"])
        self.assertFalse(response.data["can_restore"])

    def test_soft_deleted_events_are_excluded_from_normal_and_hidden_lists(self):
        active_event = self.make_event(title="Active Owner Event", status="published")
        deleted_event = self.make_event(
            title="Soft Deleted Owner Event",
            status="archived",
            archived_at=timezone.now(),
            archived_from_status="published",
            is_hidden=True,
        )
        view = EventViewSet.as_view({"get": "mine"})

        all_request = self.factory.get("/api/events/mine/?view=card")
        force_authenticate(all_request, user=self.owner)
        all_response = view(all_request)
        self.assertEqual(all_response.status_code, 200)
        all_rows = (
            all_response.data.get("results", [])
            if isinstance(all_response.data, dict)
            else all_response.data
        )
        all_ids = {row["id"] for row in all_rows}
        self.assertIn(active_event.id, all_ids)
        self.assertNotIn(deleted_event.id, all_ids)

        hidden_request = self.factory.get(
            "/api/events/mine/?view=card&is_hidden=true"
        )
        force_authenticate(hidden_request, user=self.owner)
        hidden_response = view(hidden_request)
        self.assertEqual(hidden_response.status_code, 200)
        hidden_rows = (
            hidden_response.data.get("results", [])
            if isinstance(hidden_response.data, dict)
            else hidden_response.data
        )
        hidden_ids = {row["id"] for row in hidden_rows}
        self.assertNotIn(deleted_event.id, hidden_ids)


    def test_soft_deleted_event_detail_is_not_displayed(self):
        event = self.make_event(status="published")
        delete_response = self.call_action(event, "soft_delete")
        self.assertEqual(delete_response.status_code, 200)

        view = EventViewSet.as_view({"get": "retrieve"})
        request = self.factory.get(f"/api/events/{event.pk}/")
        force_authenticate(request, user=self.owner)
        response = view(request, pk=str(event.pk))

        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.data["error"], "event_soft_deleted")
        self.assertTrue(response.data["database_record_preserved"])
        self.assertTrue(Event.objects.filter(pk=event.pk).exists())

    def test_currently_live_event_must_end_before_soft_delete(self):
        event = self.make_event(status="live", is_live=True)

        response = self.call_action(event, "soft_delete")

        self.assertEqual(response.status_code, 409)
        self.assertIn("End the live meeting", response.data["detail"])
        event.refresh_from_db()
        self.assertEqual(event.status, "live")
        self.assertTrue(event.is_live)

    def test_archive_and_restore_preserve_history_and_previous_status(self):
        event = self.make_event(
            status="ended",
            start_time=timezone.now() - timezone.timedelta(days=2),
            end_time=timezone.now() - timezone.timedelta(days=1),
        )
        EventPublication.objects.create(event=event, platform=self.manda, is_enabled=True)
        registration = EventRegistration.objects.create(event=event, user=self.attendee)
        canonical_id = event.canonical_event_id

        with self.captureOnCommitCallbacks(execute=True):
            archive_response = self.call_action(
                event,
                "archive",
                data={"archive_reason": "Retention-safe cleanup"},
            )

        self.assertEqual(archive_response.status_code, 200)
        event.refresh_from_db()
        self.assertEqual(event.status, "archived")
        self.assertEqual(event.archived_from_status, "ended")
        self.assertTrue(event.is_hidden)
        self.assertEqual(event.canonical_event_id, canonical_id)
        self.assertTrue(EventRegistration.objects.filter(pk=registration.pk).exists())

        with self.captureOnCommitCallbacks(execute=True):
            restore_response = self.call_action(event, "restore")

        self.assertEqual(restore_response.status_code, 200)
        event.refresh_from_db()
        self.assertEqual(event.status, "ended")
        self.assertFalse(event.is_hidden)
        self.assertIsNotNone(event.restored_at)
        self.assertTrue(EventRegistration.objects.filter(pk=registration.pk).exists())

    def test_past_published_event_archives_as_ended(self):
        event = self.make_event(
            status="published",
            start_time=timezone.now() - timezone.timedelta(days=2),
            end_time=timezone.now() - timezone.timedelta(hours=1),
        )

        with self.captureOnCommitCallbacks(execute=True):
            response = self.call_action(event, "archive")

        self.assertEqual(response.status_code, 200)
        event.refresh_from_db()
        self.assertEqual(event.status, "archived")
        self.assertEqual(event.archived_from_status, "ended")

    def test_wordpress_owned_event_cannot_be_cancelled_or_soft_deleted_locally(self):
        event = self.make_event(wordpress_event_id=9876)

        cancel_response = self.call_action(event, "cancel")
        archive_response = self.call_action(event, "soft_delete")

        self.assertEqual(cancel_response.status_code, 409)
        self.assertEqual(archive_response.status_code, 409)
        event.refresh_from_db()
        self.assertEqual(event.status, "published")
        self.assertEqual(event.wordpress_event_id, 9876)

    def test_manda_owned_event_cannot_be_soft_deleted_locally(self):
        event = self.make_event(status="ended")
        ExternalEventMapping.objects.create(
            source_platform=ExternalEventMapping.SOURCE_MANDA,
            source_event_id="manda-123",
            canonical_event_id=event.canonical_event_id,
            local_event=event,
            is_active=True,
        )

        response = self.call_action(event, "soft_delete")

        self.assertEqual(response.status_code, 409)
        event.refresh_from_db()
        self.assertEqual(event.status, "ended")

    def test_delete_endpoint_soft_deletes_even_clean_drafts_and_preserves_history(self):
        clean_draft = self.make_event(
            title="Clean Draft",
            status="draft",
            price=None,
            is_free=True,
        )
        clean_id = clean_draft.pk
        response = self.call_action(clean_draft, "destroy", method="delete")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["database_record_preserved"])
        clean_draft.refresh_from_db()
        self.assertEqual(clean_draft.pk, clean_id)
        self.assertEqual(clean_draft.status, "archived")

        protected_draft = self.make_event(
            title="Protected Draft",
            status="draft",
            price=None,
            is_free=True,
        )
        registration = EventRegistration.objects.create(
            event=protected_draft,
            user=self.attendee,
        )
        response = self.call_action(protected_draft, "destroy", method="delete")
        self.assertEqual(response.status_code, 200)
        protected_draft.refresh_from_db()
        self.assertEqual(protected_draft.status, "archived")
        self.assertTrue(EventRegistration.objects.filter(pk=registration.pk).exists())


@override_settings(
    SALEOR_ENABLED=True,
    EVENT_PLATFORM_SYNC_TRIGGER_ON_COMMIT=False,
)
class EventSaleorLifecycleTests(TestCase):
    """Lifecycle uses Saleor unpublish, never product deletion."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.owner = User.objects.create_superuser(
            username="saleor-owner",
            email="saleor-owner@example.com",
            password="test-pass",
        )
        self.community = Community.objects.create(
            name="Saleor Lifecycle Community",
            owner=self.owner,
        )
        self.imma, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect",
            defaults={
                "name": "IMAA Connect",
                "is_active": True,
            },
        )

    def test_cancel_queues_saleor_unpublish_and_keeps_ids(self):
        event = Event(
            community=self.community,
            created_by=self.owner,
            title="Saleor Lifecycle Event",
            status="published",
            start_time=timezone.now() + timezone.timedelta(days=1),
            end_time=timezone.now() + timezone.timedelta(days=1, hours=1),
            is_free=False,
            price=Decimal("50.00"),
            saleor_product_id="UHJvZHVjdDoy",
            saleor_variant_id="UHJvZHVjdFZhcmlhbnQ6Mg==",
        )
        event.skip_saleor_sync = True
        event.save()
        EventPublication.objects.create(event=event, platform=self.imma, is_enabled=True)

        view = EventViewSet.as_view({"post": "cancel"})
        request = self.factory.post(
            f"/api/events/{event.pk}/cancel/",
            {"notify_participants": False},
            format="json",
        )
        force_authenticate(request, user=self.owner)

        with patch("events.tasks.set_event_saleor_availability_async.delay") as delay:
            with self.captureOnCommitCallbacks(execute=True):
                response = view(request, pk=str(event.pk))

        self.assertEqual(response.status_code, 200)
        delay.assert_called_once_with(event.id, False)
        event.refresh_from_db()
        self.assertEqual(event.saleor_product_id, "UHJvZHVjdDoy")
        self.assertEqual(event.saleor_variant_id, "UHJvZHVjdFZhcmlhbnQ6Mg==")

    def test_direct_archive_queues_saleor_unpublish_and_keeps_ids(self):
        event = Event(
            community=self.community,
            created_by=self.owner,
            title="Saleor Direct Archive Event",
            status="published",
            start_time=timezone.now() + timezone.timedelta(days=2),
            end_time=timezone.now() + timezone.timedelta(days=2, hours=1),
            is_free=False,
            price=Decimal("75.00"),
            saleor_product_id="UHJvZHVjdDo0",
            saleor_variant_id="UHJvZHVjdFZhcmlhbnQ6NA==",
        )
        event.skip_saleor_sync = True
        event.save()
        EventPublication.objects.create(event=event, platform=self.imma, is_enabled=True)

        view = EventViewSet.as_view({"post": "archive"})
        request = self.factory.post(
            f"/api/events/{event.pk}/archive/",
            {"archive_reason": "No longer displayed"},
            format="json",
        )
        force_authenticate(request, user=self.owner)

        with patch("events.tasks.set_event_saleor_availability_async.delay") as delay:
            with self.captureOnCommitCallbacks(execute=True):
                response = view(request, pk=str(event.pk))

        self.assertEqual(response.status_code, 200)
        delay.assert_called_once_with(event.id, False)
        event.refresh_from_db()
        self.assertEqual(event.status, "archived")
        self.assertEqual(event.archived_from_status, "published")
        self.assertEqual(event.saleor_product_id, "UHJvZHVjdDo0")
        self.assertEqual(event.saleor_variant_id, "UHJvZHVjdFZhcmlhbnQ6NA==")
