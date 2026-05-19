"""
Tests for Participant Information Form integration with all attendee confirmation flows.
Tests automatic form triggering, idempotency, and submission writebacks.
"""
import pytest
from django.contrib.auth.models import User
from django.utils import timezone
from django.test import TestCase
from datetime import timedelta
from io import StringIO

from events.models import (
    Event, EventRegistration, EventApplication,
    PostAcceptanceFormTemplate, PostAcceptanceFormAssignment,
    PostAcceptanceFormSubmission, PostAcceptanceFormAnswer,
    Community, GuestAttendee
)
from events.services import (
    trigger_post_acceptance_forms,
    writeback_participant_information_form,
)
from events.management.commands.seed_participant_information_form import Command


@pytest.fixture
def user():
    """Create a test user."""
    return User.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='testpass123'
    )


@pytest.fixture
def admin_user():
    """Create an admin user."""
    return User.objects.create_user(
        username='admin',
        email='admin@example.com',
        password='admin123',
        is_superuser=True
    )


@pytest.fixture
def community(admin_user):
    """Create a test community."""
    return Community.objects.create(
        name='Test Community',
        created_by=admin_user
    )


@pytest.fixture
def in_person_event(community, admin_user):
    """Create an in-person event."""
    return Event.objects.create(
        community=community,
        title='In-Person Event',
        created_by=admin_user,
        format='in_person',
        start_time=timezone.now() + timedelta(days=1),
        end_time=timezone.now() + timedelta(days=1, hours=2),
    )


@pytest.fixture
def hybrid_event(community, admin_user):
    """Create a hybrid event."""
    return Event.objects.create(
        community=community,
        title='Hybrid Event',
        created_by=admin_user,
        format='hybrid',
        start_time=timezone.now() + timedelta(days=1),
        end_time=timezone.now() + timedelta(days=1, hours=2),
    )


@pytest.fixture
def virtual_event(community, admin_user):
    """Create a virtual event."""
    return Event.objects.create(
        community=community,
        title='Virtual Event',
        created_by=admin_user,
        format='virtual',
        start_time=timezone.now() + timedelta(days=1),
        end_time=timezone.now() + timedelta(days=1, hours=2),
    )


@pytest.mark.django_db
class TestConfirmationPathsTriggering:
    """Tests that post-acceptance forms are triggered in all confirmation paths."""

    def test_approve_application_triggers_form(self, in_person_event, admin_user, user):
        """Test that approving an application triggers Participant Info form."""
        # Create application
        app = EventApplication.objects.create(
            event=in_person_event,
            user=user,
            first_name='John',
            last_name='Doe',
            email='john@example.com',
            status='pending'
        )

        # Create form template
        PostAcceptanceFormTemplate.objects.create(
            event=in_person_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        # Approve application (in real flow, this happens via API)
        app.status = 'approved'
        app.reviewed_by = admin_user
        app.reviewed_at = timezone.now()
        app.save()

        # Manually trigger (API endpoint does this)
        registration = EventRegistration.objects.filter(
            event=in_person_event,
            user=user
        ).first()
        if registration:
            trigger_post_acceptance_forms(registration)

        # Verify form was assigned
        assignment = PostAcceptanceFormAssignment.objects.filter(
            event_registration=registration,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION
        ).first()
        assert assignment is not None, "Participant Information form not assigned"

    def test_preapproved_application_triggers_form(self, in_person_event, user):
        """Test that pre-approved applications trigger forms."""
        # Create pre-approved application
        app = EventApplication.objects.create(
            event=in_person_event,
            user=user,
            first_name='Jane',
            last_name='Smith',
            email='jane@example.com',
            status='approved',
            is_preapproved=True,
            preapproved_at=timezone.now()
        )

        # Create form template
        PostAcceptanceFormTemplate.objects.create(
            event=in_person_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        # Create registration (auto-created in approval flow)
        registration = EventRegistration.objects.create(
            event=in_person_event,
            user=user,
            attendee_status='confirmed'
        )

        # Trigger forms
        trigger_post_acceptance_forms(registration)

        # Verify form was assigned
        assignment = PostAcceptanceFormAssignment.objects.filter(
            event_registration=registration,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION
        ).exists()
        assert assignment, "Form not assigned for pre-approved application"

    def test_no_trigger_virtual_event(self, virtual_event, user):
        """Test that Participant Info form does NOT trigger for virtual events."""
        registration = EventRegistration.objects.create(
            event=virtual_event,
            user=user,
            attendee_status='confirmed'
        )

        PostAcceptanceFormTemplate.objects.create(
            event=virtual_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        trigger_post_acceptance_forms(registration)

        # Verify no Participant Info form
        assignment = PostAcceptanceFormAssignment.objects.filter(
            event_registration=registration,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION
        ).exists()
        assert not assignment, "Participant Info form should not trigger for virtual event"

    def test_hybrid_event_triggers_form(self, hybrid_event, user):
        """Test that Participant Info form triggers for hybrid events."""
        registration = EventRegistration.objects.create(
            event=hybrid_event,
            user=user,
            attendee_status='confirmed'
        )

        PostAcceptanceFormTemplate.objects.create(
            event=hybrid_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        trigger_post_acceptance_forms(registration)

        # Verify form was assigned
        assignment = PostAcceptanceFormAssignment.objects.filter(
            event_registration=registration,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION
        ).exists()
        assert assignment, "Participant Info form should trigger for hybrid event"


@pytest.mark.django_db
class TestIdempotency:
    """Tests that form triggering is idempotent (safe to call multiple times)."""

    def test_multiple_triggers_no_duplicates(self, in_person_event, user):
        """Test that calling trigger multiple times doesn't create duplicates."""
        registration = EventRegistration.objects.create(
            event=in_person_event,
            user=user,
            attendee_status='confirmed'
        )

        PostAcceptanceFormTemplate.objects.create(
            event=in_person_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        # Call trigger multiple times
        trigger_post_acceptance_forms(registration)
        trigger_post_acceptance_forms(registration)
        trigger_post_acceptance_forms(registration)

        # Verify only one assignment exists
        count = PostAcceptanceFormAssignment.objects.filter(
            event_registration=registration,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION
        ).count()
        assert count == 1, f"Expected 1 assignment, got {count}"


@pytest.mark.django_db
class TestWritebacks:
    """Tests that form submissions write back to EventRegistration."""

    def test_writeback_directory_visibility(self, in_person_event, user):
        """Test that directory_visibility is written back."""
        registration = EventRegistration.objects.create(
            event=in_person_event,
            user=user,
            attendee_status='confirmed',
            directory_visibility=False
        )

        template = PostAcceptanceFormTemplate.objects.create(
            event=in_person_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        assignment = PostAcceptanceFormAssignment.objects.create(
            event=in_person_event,
            form_template=template,
            event_registration=registration,
            form_type=template.form_type,
            deadline=timezone.now() + timedelta(days=7),
            status=PostAcceptanceFormAssignment.STATUS_COMPLETED
        )

        # Create submission with answer
        submission = PostAcceptanceFormSubmission.objects.create(assignment=assignment)
        PostAcceptanceFormAnswer.objects.create(
            submission=submission,
            question_key='share_contact_details',
            answer_text='true'
        )

        # Writeback
        writeback_participant_information_form(assignment)

        # Verify writeback
        registration.refresh_from_db()
        assert registration.directory_visibility is True

    def test_writeback_photo_consent(self, in_person_event, user):
        """Test that photo_video_consent is written back."""
        registration = EventRegistration.objects.create(
            event=in_person_event,
            user=user,
            attendee_status='confirmed',
            photo_video_consent='no'
        )

        template = PostAcceptanceFormTemplate.objects.create(
            event=in_person_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        assignment = PostAcceptanceFormAssignment.objects.create(
            event=in_person_event,
            form_template=template,
            event_registration=registration,
            form_type=template.form_type,
            deadline=timezone.now() + timedelta(days=7),
            status=PostAcceptanceFormAssignment.STATUS_COMPLETED
        )

        submission = PostAcceptanceFormSubmission.objects.create(assignment=assignment)
        PostAcceptanceFormAnswer.objects.create(
            submission=submission,
            question_key='photo_video_consent',
            answer_text='full'
        )

        writeback_participant_information_form(assignment)

        registration.refresh_from_db()
        assert registration.photo_video_consent == 'full'

    def test_writeback_visa_support(self, in_person_event, user):
        """Test that visa_support_requested is written back."""
        registration = EventRegistration.objects.create(
            event=in_person_event,
            user=user,
            attendee_status='confirmed',
            visa_support_requested=False
        )

        template = PostAcceptanceFormTemplate.objects.create(
            event=in_person_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        assignment = PostAcceptanceFormAssignment.objects.create(
            event=in_person_event,
            form_template=template,
            event_registration=registration,
            form_type=template.form_type,
            deadline=timezone.now() + timedelta(days=7),
            status=PostAcceptanceFormAssignment.STATUS_COMPLETED
        )

        submission = PostAcceptanceFormSubmission.objects.create(assignment=assignment)
        PostAcceptanceFormAnswer.objects.create(
            submission=submission,
            question_key='visa_support',
            answer_text='true'
        )

        writeback_participant_information_form(assignment)

        registration.refresh_from_db()
        assert registration.visa_support_requested is True
        assert registration.participant_information_completed_at is not None


@pytest.mark.django_db
class TestSeedCommand:
    """Tests for the seed_participant_information_form management command."""

    def test_seed_creates_form_template(self, in_person_event):
        """Test that seed command creates form template."""
        cmd = Command()
        out = StringIO()

        cmd.handle(event_id=in_person_event.id, stdout=out)

        template = PostAcceptanceFormTemplate.objects.filter(
            event=in_person_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION
        ).first()
        assert template is not None
        assert template.is_enabled
        assert 'sections' in template.question_schema

    def test_seed_all_events(self, in_person_event, hybrid_event):
        """Test that seed command can seed all events."""
        cmd = Command()
        out = StringIO()

        cmd.handle(stdout=out)

        # Both events should have templates
        for event in [in_person_event, hybrid_event]:
            template = PostAcceptanceFormTemplate.objects.filter(
                event=event,
                form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION
            ).exists()
            assert template

    def test_seed_respects_existing(self, in_person_event):
        """Test that seed skips existing templates unless --recreate."""
        # Create template manually
        existing = PostAcceptanceFormTemplate.objects.create(
            event=in_person_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=14,
            question_schema={"test": "original"}
        )

        cmd = Command()
        out = StringIO()

        # Run without recreate
        cmd.handle(event_id=in_person_event.id, stdout=out)

        # Should still have original schema
        existing.refresh_from_db()
        assert existing.question_schema == {"test": "original"}
        assert existing.deadline_days == 14

        # Run with recreate
        cmd.handle(event_id=in_person_event.id, recreate=True, stdout=out)

        # Should have new schema
        existing.refresh_from_db()
        assert existing.question_schema != {"test": "original"}
        assert 'sections' in existing.question_schema

    def test_seed_schema_structure(self, in_person_event):
        """Test that seeded schema has expected structure."""
        cmd = Command()
        out = StringIO()

        cmd.handle(event_id=in_person_event.id, stdout=out)

        template = PostAcceptanceFormTemplate.objects.get(
            event=in_person_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION
        )

        schema = template.question_schema
        assert 'sections' in schema
        assert 'metadata' in schema
        assert 'form_title' in schema

        # Check sections exist
        section_ids = {s['id'] for s in schema['sections']}
        expected_sections = {
            'accessibility',
            'emergency_contact',
            'food',
            'privacy',
            'travel'
        }
        assert expected_sections.issubset(section_ids)

        # Check metadata
        assert 'restricted_fields' in schema['metadata']
        assert 'emergency_medical_info' in schema['metadata']['restricted_fields']
        assert 'emergency_contact_phone' in schema['metadata']['restricted_fields']
