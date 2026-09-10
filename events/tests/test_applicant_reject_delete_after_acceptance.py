"""
Tests for "Applicants - Reject and/or delete after acceptance".

Covers:
1. Declining an already-accepted track application: status transition +
   rollback of acceptance side effects (attendee origins, registration roles).
2. Soft delete on EventApplicationTrackApplication: field updates, default
   manager hiding deleted rows, all_objects exposing them for audit.
3. Bulk `delete` action on EventViewSet.bulk_action: permission check,
   deleted_by/reason stored, no hard delete.
4. Regression coverage for pending -> accepted / declined / waitlisted.
"""
from decimal import Decimal

from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient

from community.models import Community
from events.models import (
    Event,
    EventApplication,
    EventApplicationTrack,
    EventApplicationTrackApplication,
    EventAttendeeOrigin,
    EventRegistration,
    EventRole,
    TrackPricingTier,
)
from events.services.application_decisions import (
    accept_track_application,
    decline_track_application,
    waitlist_track_application,
)


class BaseApplicantActionTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.community = Community.objects.create(name='Applicant Actions Community')
        self.manager = User.objects.create_user(username='manager', password='pass123', is_staff=True)
        self.applicant = User.objects.create_user(username='applicant', password='pass123')
        self.other_user = User.objects.create_user(username='other', password='pass123')

        self.event = Event.objects.create(
            community=self.community,
            title='Applicant Actions Event',
            created_by=self.manager,
            registration_type='apply',
            waiting_room_enabled=False,
        )

        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            status='open',
            role_mappings_on_acceptance=['speaker'],
            enabled_submission_modes=['self_submission'],
        )

        self.free_tier = TrackPricingTier.objects.create(
            track=self.track,
            key='free',
            label='Free',
            price=Decimal('0.00'),
            is_default=True,
            is_active=True,
        )

        self.application = EventApplication.objects.create(
            event=self.event,
            user=self.applicant,
            first_name='John',
            last_name='Doe',
            email='john@example.com',
        )

        self.track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=self.track,
            submission_mode='self_submission',
            status='pending',
            tier_preference=self.free_tier,
        )


class AcceptedToDeclinedRollbackTests(BaseApplicantActionTestCase):
    """Section 1: accepted -> declined status transition and side-effect rollback."""

    def test_decline_after_accept_changes_status_and_cancels_origin(self):
        accept_track_application(self.track_app, self.manager, accepted_tier=self.free_tier)
        self.track_app.refresh_from_db()
        self.assertEqual(self.track_app.status, EventApplicationTrackApplication.STATUS_ACCEPTED)

        registration = EventRegistration.objects.get(event=self.event, user=self.applicant)
        speaker_role = EventRole.objects.get(event=self.event, key='speaker')
        self.assertIn(speaker_role, registration.roles.all())
        origin = EventAttendeeOrigin.objects.get(registration=registration, track=self.track)
        self.assertEqual(origin.status, 'active')

        decline_track_application(self.track_app, self.manager, send_email=False)
        self.track_app.refresh_from_db()

        # Status changed
        self.assertEqual(self.track_app.status, EventApplicationTrackApplication.STATUS_DECLINED)
        self.assertIsNotNone(self.track_app.declined_at)

        # History preserved: prior acceptance metadata is not wiped
        self.assertEqual(self.track_app.accepted_tier_id, self.free_tier.id)
        self.assertIsNotNone(self.track_app.accepted_at)

        # Attendee origin is cancelled, not deleted (audit trail preserved)
        origin.refresh_from_db()
        self.assertEqual(origin.status, 'cancelled')
        self.assertTrue(EventAttendeeOrigin.objects.filter(pk=origin.pk).exists())

        # Role removed from the registration (no longer active), but the
        # EventRole itself is not deleted (shared/reusable config).
        registration.refresh_from_db()
        self.assertNotIn(speaker_role, registration.roles.all())
        self.assertTrue(EventRole.objects.filter(pk=speaker_role.pk).exists())

        # Registration itself is preserved for audit/history, status recalculated
        self.assertTrue(EventRegistration.objects.filter(pk=registration.pk).exists())
        self.assertEqual(registration.attendee_status, 'cancelled')

    def test_decline_after_accept_keeps_role_if_still_used_by_another_track(self):
        """A role shared by two accepted tracks must survive declining just one of them."""
        second_track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker-2',
            label='Speaker Track 2',
            status='open',
            role_mappings_on_acceptance=['speaker'],
            enabled_submission_modes=['self_submission'],
        )
        second_tier = TrackPricingTier.objects.create(
            track=second_track,
            key='free2',
            label='Free 2',
            price=Decimal('0.00'),
            is_default=True,
            is_active=True,
        )
        second_track_app = EventApplicationTrackApplication.objects.create(
            application=self.application,
            track=second_track,
            submission_mode='self_submission',
            status='pending',
            tier_preference=second_tier,
        )

        accept_track_application(self.track_app, self.manager, accepted_tier=self.free_tier)
        accept_track_application(second_track_app, self.manager, accepted_tier=second_tier)

        registration = EventRegistration.objects.get(event=self.event, user=self.applicant)
        speaker_role = EventRole.objects.get(event=self.event, key='speaker')
        self.assertIn(speaker_role, registration.roles.all())

        decline_track_application(self.track_app, self.manager, send_email=False)

        registration.refresh_from_db()
        # Role still needed by second_track_app (still accepted/active origin)
        self.assertIn(speaker_role, registration.roles.all())
        # Registration remains confirmed because the other origin is still active
        self.assertEqual(registration.attendee_status, 'confirmed')

    def test_decline_endpoint_allows_accepted_to_declined(self):
        self.client.force_authenticate(self.manager)
        accept_resp = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/accept/',
            {'accepted_tier_id': self.free_tier.id},
            format='json',
        )
        self.assertEqual(accept_resp.status_code, 200)

        decline_resp = self.client.post(
            f'/events/{self.event.id}/applications/{self.application.id}/track-applications/{self.track_app.id}/decline/',
            {'send_email': False},
            format='json',
        )
        self.assertEqual(decline_resp.status_code, 200)
        self.track_app.refresh_from_db()
        self.assertEqual(self.track_app.status, EventApplicationTrackApplication.STATUS_DECLINED)


class SoftDeleteTests(BaseApplicantActionTestCase):
    """Section 2: soft delete pattern on EventApplicationTrackApplication."""

    def test_soft_delete_sets_audit_fields(self):
        self.track_app.soft_delete(user=self.manager, reason='Duplicate application')
        self.track_app.refresh_from_db()

        self.assertTrue(self.track_app.is_deleted)
        self.assertIsNotNone(self.track_app.deleted_at)
        self.assertEqual(self.track_app.deleted_by_id, self.manager.id)
        self.assertEqual(self.track_app.deletion_reason, 'Duplicate application')

    def test_default_manager_hides_deleted_record(self):
        self.track_app.soft_delete(user=self.manager, reason='Removed')

        self.assertFalse(
            EventApplicationTrackApplication.objects.filter(pk=self.track_app.pk).exists()
        )
        self.assertTrue(
            EventApplicationTrackApplication.all_objects.filter(pk=self.track_app.pk).exists()
        )

    def test_restore_reverses_soft_delete(self):
        self.track_app.soft_delete(user=self.manager, reason='Removed')
        self.track_app.restore()
        self.track_app.refresh_from_db()

        self.assertFalse(self.track_app.is_deleted)
        self.assertIsNone(self.track_app.deleted_at)
        self.assertIsNone(self.track_app.deleted_by)
        self.assertEqual(self.track_app.deletion_reason, '')
        self.assertTrue(
            EventApplicationTrackApplication.objects.filter(pk=self.track_app.pk).exists()
        )


class BulkDeleteActionTests(BaseApplicantActionTestCase):
    """Section 4: bulk_action 'delete' branch."""

    def test_bulk_delete_requires_event_manager(self):
        self.client.force_authenticate(self.other_user)
        response = self.client.post(
            f'/events/{self.event.id}/bulk-action/',
            {'action': 'delete', 'track_application_ids': [self.track_app.id], 'reason': 'Spam'},
            format='json',
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(
            EventApplicationTrackApplication.objects.get(pk=self.track_app.pk).is_deleted
        )

    def test_bulk_delete_soft_deletes_with_reason_and_actor(self):
        self.client.force_authenticate(self.manager)
        response = self.client.post(
            f'/events/{self.event.id}/bulk-action/',
            {'action': 'delete', 'track_application_ids': [self.track_app.id], 'reason': 'Spam application'},
            format='json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['updated_count'], 1)

        self.track_app.refresh_from_db()
        self.assertTrue(self.track_app.is_deleted)
        self.assertEqual(self.track_app.deleted_by_id, self.manager.id)
        self.assertEqual(self.track_app.deletion_reason, 'Spam application')

        # No hard delete: row still exists via all_objects
        self.assertTrue(
            EventApplicationTrackApplication.all_objects.filter(pk=self.track_app.pk).exists()
        )

    def test_bulk_delete_works_for_accepted_application(self):
        accept_track_application(self.track_app, self.manager, accepted_tier=self.free_tier)
        self.client.force_authenticate(self.manager)

        response = self.client.post(
            f'/events/{self.event.id}/bulk-action/',
            {'action': 'delete', 'track_application_ids': [self.track_app.id]},
            format='json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['updated_count'], 1)

        self.track_app.refresh_from_db()
        self.assertTrue(self.track_app.is_deleted)
        # Underlying acceptance/history fields remain intact (no hard delete of data)
        self.assertEqual(self.track_app.accepted_tier_id, self.free_tier.id)

    def test_bulk_delete_excluded_from_review_queue_after_delete(self):
        self.client.force_authenticate(self.manager)
        self.client.post(
            f'/events/{self.event.id}/bulk-action/',
            {'action': 'delete', 'track_application_ids': [self.track_app.id]},
            format='json',
        )

        list_response = self.client.get(f'/events/{self.event.id}/review-queue/')
        self.assertEqual(list_response.status_code, 200)
        returned_ids = [item['id'] for item in list_response.data.get('results', list_response.data)]
        self.assertNotIn(self.track_app.id, returned_ids)


class RegressionTests(BaseApplicantActionTestCase):
    """Section 4: pending -> accepted / declined / waitlisted must still work."""

    def test_pending_to_accepted(self):
        accept_track_application(self.track_app, self.manager, accepted_tier=self.free_tier)
        self.track_app.refresh_from_db()
        self.assertEqual(self.track_app.status, EventApplicationTrackApplication.STATUS_ACCEPTED)
        self.assertEqual(self.track_app.accepted_tier_id, self.free_tier.id)

    def test_pending_to_declined(self):
        decline_track_application(self.track_app, self.manager, send_email=False)
        self.track_app.refresh_from_db()
        self.assertEqual(self.track_app.status, EventApplicationTrackApplication.STATUS_DECLINED)

    def test_pending_to_waitlisted(self):
        waitlist_track_application(self.track_app, self.manager, send_email=False)
        self.track_app.refresh_from_db()
        self.assertEqual(self.track_app.status, EventApplicationTrackApplication.STATUS_WAITLISTED)

    def test_bulk_action_accept_decline_waitlist_still_supported(self):
        self.client.force_authenticate(self.manager)
        second_app = EventApplication.objects.create(
            event=self.event,
            user=self.other_user,
            first_name='Jane',
            last_name='Roe',
            email='jane@example.com',
        )
        second_track_app = EventApplicationTrackApplication.objects.create(
            application=second_app,
            track=self.track,
            submission_mode='self_submission',
            status='pending',
            tier_preference=self.free_tier,
        )

        response = self.client.post(
            f'/events/{self.event.id}/bulk-action/',
            {
                'action': 'accept',
                'track_application_ids': [self.track_app.id, second_track_app.id],
                'tier_preference_id': self.free_tier.id,
            },
            format='json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['updated_count'], 2)
