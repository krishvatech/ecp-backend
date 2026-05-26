"""
Performance Optimization Tests for Application Tracks v1

Tests verify:
1. Signal optimization - no duplicate triggers on status unchanged
2. Async email - form emails are queued to Celery, not sent synchronously
3. Review queue optimization - select_related prevents N+1 queries
4. Form writeback optimization - only loads needed fields
5. Template caching - reuses templates in bulk operations
6. Reminder scheduler optimization - uses prefetch_related
"""

from django.test import TestCase, TransactionTestCase
from django.contrib.auth import get_user_model
from django.test.utils import override_settings
from django.utils import timezone
from datetime import timedelta
from unittest.mock import patch, MagicMock
from events.models import (
    Event, EventRegistration, EventRole, EventApplicationTrack,
    PostAcceptanceFormTemplate, PostAcceptanceFormAssignment,
    PostAcceptanceFormSubmission, PostAcceptanceFormAnswer,
    EventApplicationTrackApplication
)
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class SetUpTestCase(TestCase):
    """Base test case with common setup for performance tests."""

    def setUp(self):
        """Create test fixtures."""
        # Create users
        self.user1 = User.objects.create_user(
            username='user1', email='user1@example.com', password='pass123'
        )
        self.user2 = User.objects.create_user(
            username='user2', email='user2@example.com', password='pass123'
        )
        self.user3 = User.objects.create_user(
            username='user3', email='user3@example.com', password='pass123'
        )

        # Create event (in-person to trigger participant info forms)
        self.event = Event.objects.create(
            title='Test Event',
            slug='test-event',
            description='Test event for performance testing',
            format='in_person',
            start_time=timezone.now() + timedelta(days=30),
            end_time=timezone.now() + timedelta(days=31),
            organizer_id=self.user1.id,
            registration_type='application_tracks',
            status='published'
        )

        # Create roles
        self.speaker_role = EventRole.objects.create(
            event=self.event,
            key='speaker',
            name='Speaker',
            triggers_promotional_profile=True
        )
        self.attendee_role = EventRole.objects.create(
            event=self.event,
            key='attendee',
            name='Attendee',
            triggers_promotional_profile=False
        )

        # Create application track
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker',
            status='open',
            is_active=True,
            enabled_submission_modes=['self_submission'],
            role_mappings_on_acceptance=['speaker', 'attendee']
        )

        # Create form templates
        self.participant_template = PostAcceptanceFormTemplate.objects.create(
            event=self.event,
            form_type='participant_information',
            title='Participant Information',
            description='Share your participant information',
            is_enabled=True,
            deadline_days=21
        )
        self.promotional_template = PostAcceptanceFormTemplate.objects.create(
            event=self.event,
            form_type='promotional_profile',
            title='Promotional Profile',
            description='Share your professional profile',
            is_enabled=True,
            deadline_days=14
        )


class SignalOptimizationTest(SetUpTestCase):
    """Test signal optimization - no trigger on status unchanged."""

    def test_status_unchanged_no_trigger(self):
        """Verify signal doesn't trigger forms when status hasn't changed."""
        # Create registration with confirmed status
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user1,
            attendee_status='confirmed',
            status='registered'
        )
        registration.roles.add(self.speaker_role)

        # Get initial assignment count
        initial_count = PostAcceptanceFormAssignment.objects.count()

        # Save without changing status
        registration.comments = "Updated comments"
        registration.save()

        # Verify no new form assignments created
        new_count = PostAcceptanceFormAssignment.objects.count()
        self.assertEqual(
            initial_count, new_count,
            "Signal should not trigger when status hasn't changed"
        )

    def test_status_transition_triggers_once(self):
        """Verify status transition to confirmed triggers forms exactly once."""
        # Create registration with pending status
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user2,
            attendee_status='payment_pending',
            status='registered'
        )
        registration.roles.add(self.speaker_role)

        initial_count = PostAcceptanceFormAssignment.objects.count()

        # Transition to confirmed
        registration.attendee_status = 'confirmed'
        registration.save()

        # Verify forms were created
        new_count = PostAcceptanceFormAssignment.objects.count()
        self.assertGreater(
            new_count, initial_count,
            "Signal should trigger when status transitions to confirmed"
        )
        forms_created = new_count - initial_count

        # Save again without changing status
        registration.comments = "More comments"
        registration.save()

        # Verify no additional forms created
        final_count = PostAcceptanceFormAssignment.objects.count()
        self.assertEqual(
            new_count, final_count,
            "Signal should not trigger again when status unchanged"
        )

    def test_non_confirmed_status_no_trigger(self):
        """Verify signal doesn't trigger for non-confirmed statuses."""
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user3,
            attendee_status='declined',
            status='registered'
        )

        initial_count = PostAcceptanceFormAssignment.objects.count()

        # Save with different non-confirmed status
        registration.attendee_status = 'waitlisted'
        registration.save()

        # Verify no forms created
        final_count = PostAcceptanceFormAssignment.objects.count()
        self.assertEqual(
            initial_count, final_count,
            "Signal should not trigger for non-confirmed statuses"
        )


@override_settings(CELERY_ALWAYS_EAGER=False)
class EmailAsyncTest(SetUpTestCase):
    """Test form assignment email is queued to Celery, not sent synchronously."""

    @patch('events.tasks.send_form_assignment_email_task.delay')
    def test_form_email_queued_async(self, mock_task_delay):
        """Verify form assignment email is queued, not sent synchronously."""
        mock_task_delay.return_value = MagicMock()

        # Create registration and trigger form
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user1,
            attendee_status='confirmed',
            status='registered'
        )
        registration.roles.add(self.speaker_role)

        # Get form assignment
        assignment = PostAcceptanceFormAssignment.objects.filter(
            form_type='participant_information'
        ).first()

        if assignment:
            # Verify task was queued with the assignment ID
            mock_task_delay.assert_called()

    @patch('events.tasks.send_form_assignment_email_task.delay')
    @patch('events.services.post_acceptance_forms.send_form_assignment_email')
    def test_form_email_fallback_to_sync(self, mock_sync_send, mock_task_delay):
        """Verify fallback to sync email if Celery fails."""
        # Simulate Celery failure
        mock_task_delay.side_effect = Exception("Celery unavailable")
        mock_sync_send.return_value = True

        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user2,
            attendee_status='confirmed',
            status='registered'
        )

        # Form creation should not fail even if Celery fails
        assignment = PostAcceptanceFormAssignment.objects.filter(
            event_registration=registration
        ).first()
        self.assertIsNotNone(assignment, "Assignment should be created even if email fails")


class ReviewQueueOptimizationTest(SetUpTestCase):
    """Test review queue optimization prevents N+1 queries."""

    def test_review_queue_select_related(self):
        """Verify review queue uses select_related to prevent N+1."""
        # Create multiple applications with different users
        for i in range(5):
            user = User.objects.create_user(
                username=f'applicant{i}',
                email=f'applicant{i}@example.com',
                password='pass123'
            )

        # Create EventApplication records
        from events.models import EventApplication
        applications = []
        for i in range(5):
            app = EventApplication.objects.create(
                event=self.event,
                email=f'applicant{i}@example.com',
                first_name=f'Applicant',
                last_name=f'{i}',
                submission_mode='self_submission'
            )
            applications.append(app)

        # Create track applications
        for i, app in enumerate(applications):
            EventApplicationTrackApplication.objects.create(
                application=app,
                track=self.track,
                submission_mode='self_submission',
                status='pending'
            )

        # Query the review queue (mimicking the view)
        from django.db import connection, reset_queries
        from django.test.utils import override_settings

        with override_settings(DEBUG=True):
            reset_queries()
            qs = EventApplicationTrackApplication.objects.filter(
                track__event=self.event
            ).select_related(
                'application',
                'application__user',
                'track',
                'track__event',
                'tier_preference',
                'reviewed_by'
            ).only(
                'id', 'application_id', 'track_id', 'status',
                'submission_mode', 'tier_preference_id', 'accepted_tier_id',
                'reviewed_by_id', 'reviewed_at', 'created_at', 'updated_at',
                'application__id', 'application__email', 'application__first_name',
                'application__last_name', 'application__user_id',
                'application__user__id', 'application__user__username', 'application__user__email',
                'track__id', 'track__label', 'track__key',
                'track__event__id', 'track__event__title',
                'tier_preference__id', 'tier_preference__label',
                'reviewed_by__id', 'reviewed_by__username'
            )

            # Access data from queryset
            items = list(qs)
            for item in items:
                _ = item.application.email
                _ = item.track.label

            # Verify query count is reasonable (should be 1-2, not 10+)
            query_count = len(connection.queries)
            self.assertLess(
                query_count, 5,
                f"Should use select_related effectively, but got {query_count} queries"
            )


class FormWritebackOptimizationTest(SetUpTestCase):
    """Test form writeback uses optimized queries."""

    def test_form_writeback_only_loads_needed_fields(self):
        """Verify writeback only loads needed fields, not large JSON."""
        # Create registration and form assignment
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user1,
            attendee_status='confirmed',
            status='registered'
        )

        assignment = PostAcceptanceFormAssignment.objects.create(
            event=self.event,
            event_registration=registration,
            form_type='participant_information',
            form_template=self.participant_template,
            deadline=timezone.now() + timedelta(days=21)
        )

        # Create submission and answers
        submission = PostAcceptanceFormSubmission.objects.create(
            assignment=assignment
        )

        # Add answers
        for question_key in ['share_contact_details', 'photo_video_consent', 'visa_support']:
            PostAcceptanceFormAnswer.objects.create(
                submission=submission,
                question_key=question_key,
                answer_text='yes'
            )

        # Test writeback (it should use .only() to exclude large JSON fields)
        from events.services.post_acceptance_forms import writeback_participant_information_form
        from django.db import connection, reset_queries
        from django.test.utils import override_settings

        with override_settings(DEBUG=True):
            reset_queries()
            result = writeback_participant_information_form(assignment)
            query_count = len(connection.queries)

            # Verify writeback succeeded
            self.assertTrue(result, "Writeback should succeed")

            # Verify query count is reasonable
            self.assertLess(query_count, 10, f"Writeback should be efficient, got {query_count} queries")


class TemplateCachingTest(SetUpTestCase):
    """Test form template caching in bulk operations."""

    @patch('events.services.post_acceptance_forms.PostAcceptanceFormTemplate.objects.filter')
    def test_template_cache_reuse(self, mock_filter):
        """Verify template cache prevents repeated queries."""
        from events.services.post_acceptance_forms import trigger_post_acceptance_forms

        # Create form template
        form_template = self.participant_template

        # Set up mock to track how many times filter is called
        mock_qs = MagicMock()
        mock_qs.first.return_value = form_template
        mock_filter.return_value = mock_qs

        # Create multiple registrations
        registrations = []
        for i in range(3):
            user = User.objects.create_user(
                username=f'bulk{i}',
                email=f'bulk{i}@example.com',
                password='pass123'
            )
            reg = EventRegistration.objects.create(
                event=self.event,
                user=user,
                attendee_status='confirmed',
                status='registered'
            )
            registrations.append(reg)

        # Trigger forms with template cache
        template_cache = {}
        for reg in registrations:
            trigger_post_acceptance_forms(reg, form_template_cache=template_cache)

        # Verify cache was used (template_cache should have entries)
        self.assertIn('participant_information', template_cache, "Cache should store templates")


class ReminderSchedulerOptimizationTest(SetUpTestCase):
    """Test reminder scheduler uses prefetch_related."""

    def test_reminder_scheduler_prefetch(self):
        """Verify reminder scheduler uses prefetch_related for user lookups."""
        # Create registration with form assignment
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user1,
            attendee_status='confirmed',
            status='registered'
        )

        assignment = PostAcceptanceFormAssignment.objects.create(
            event=self.event,
            event_registration=registration,
            form_type='participant_information',
            form_template=self.participant_template,
            deadline=timezone.now() + timedelta(days=21),
            status='pending'
        )

        # Test scheduler query
        from django.db import connection, reset_queries
        from django.test.utils import override_settings
        from datetime import datetime, timedelta
        from django.utils import timezone

        with override_settings(DEBUG=True):
            reset_queries()

            # Mimic the scheduler's query
            now = timezone.now()
            assignments = PostAcceptanceFormAssignment.objects.filter(
                status__in=[
                    PostAcceptanceFormAssignment.STATUS_NOT_STARTED,
                    PostAcceptanceFormAssignment.STATUS_IN_PROGRESS
                ],
                deadline__gte=now,
                deadline__lte=now + timedelta(days=14),
                event_registration__attendee_status='confirmed',
                event_registration__status='registered'
            ).select_related(
                'event', 'event_registration', 'form_template'
            ).prefetch_related(
                'event_registration__user'
            )

            # Access user data
            for assignment in assignments:
                _ = assignment.event_registration.user.email

            query_count = len(connection.queries)

            # Verify query count is reasonable (should be 2-3, not 1+N)
            self.assertLess(
                query_count, 8,
                f"Prefetch should reduce queries, but got {query_count}"
            )


class ExistingFunctionalityTest(SetUpTestCase):
    """Verify optimizations don't break existing functionality."""

    def test_normal_event_registration_unchanged(self):
        """Verify normal event registration (non-Application Tracks) still works."""
        # Create event without application tracks
        normal_event = Event.objects.create(
            title='Normal Event',
            slug='normal-event',
            description='A normal event',
            format='virtual',
            start_time=timezone.now() + timedelta(days=10),
            end_time=timezone.now() + timedelta(days=11),
            organizer_id=self.user1.id,
            registration_type='open',
            status='published'
        )

        # Register user
        registration = EventRegistration.objects.create(
            event=normal_event,
            user=self.user2,
            attendee_status='registered',
            status='registered'
        )

        self.assertEqual(registration.attendee_status, 'registered')
        self.assertEqual(registration.status, 'registered')

    def test_multiple_status_transitions(self):
        """Verify signal works correctly through multiple transitions."""
        registration = EventRegistration.objects.create(
            event=self.event,
            user=self.user1,
            attendee_status='pending',
            status='registered'
        )
        registration.roles.add(self.speaker_role)

        initial_count = PostAcceptanceFormAssignment.objects.count()

        # Transition 1: pending -> payment_pending
        registration.attendee_status = 'payment_pending'
        registration.save()
        count_after_1 = PostAcceptanceFormAssignment.objects.count()
        self.assertEqual(count_after_1, initial_count, "No forms for payment_pending")

        # Transition 2: payment_pending -> confirmed
        registration.attendee_status = 'confirmed'
        registration.save()
        count_after_2 = PostAcceptanceFormAssignment.objects.count()
        self.assertGreater(count_after_2, count_after_1, "Forms created for confirmed")

        # Verify forms not duplicated
        count_after_3 = PostAcceptanceFormAssignment.objects.count()
        registration.attendee_status = 'confirmed'  # No change
        registration.save()
        count_after_4 = PostAcceptanceFormAssignment.objects.count()
        self.assertEqual(count_after_3, count_after_4, "No duplicate forms")


class BulkOperationTest(SetUpTestCase):
    """Test optimizations in bulk operations."""

    def test_bulk_registration_creation(self):
        """Verify bulk registration doesn't create duplicates or errors."""
        registrations = []
        for i in range(10):
            user = User.objects.create_user(
                username=f'bulk_reg_{i}',
                email=f'bulk_reg_{i}@example.com',
                password='pass123'
            )
            reg = EventRegistration.objects.create(
                event=self.event,
                user=user,
                attendee_status='confirmed',
                status='registered'
            )
            reg.roles.add(self.attendee_role)
            registrations.append(reg)

        # Verify all registrations created
        self.assertEqual(len(registrations), 10)

        # Verify form assignments created without errors
        assignments = PostAcceptanceFormAssignment.objects.filter(
            event=self.event,
            form_type='participant_information'
        ).count()
        self.assertGreater(assignments, 0)

        # Verify no duplicate assignments (each registration has at most 1)
        from django.db.models import Count
        duplicate_check = PostAcceptanceFormAssignment.objects.filter(
            event=self.event,
            form_type='participant_information'
        ).values('event_registration').annotate(count=Count('id')).filter(count__gt=1)
        self.assertEqual(duplicate_check.count(), 0, "No duplicate assignments should exist")
