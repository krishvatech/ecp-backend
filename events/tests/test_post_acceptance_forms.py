"""
Tests for post-acceptance forms functionality.
Tests trigger conditions, duplicate prevention, and service functions.
"""
import pytest
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

from events.models import (
    Event, EventRegistration, PostAcceptanceFormTemplate,
    PostAcceptanceFormAssignment, PostAcceptanceFormSubmission,
    PostAcceptanceFormAnswer, PostAcceptanceReminderLog, Community
)
from events.services import (
    trigger_post_acceptance_forms,
    mark_assignment_in_progress,
    mark_assignment_completed,
    mark_assignment_lapsed,
    get_pending_assignments_for_event,
    get_lapsed_assignments,
)


@pytest.fixture
def user():
    """Create a test user."""
    return User.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='testpass123'
    )


@pytest.fixture
def community(user):
    """Create a test community."""
    return Community.objects.create(
        name='Test Community',
        created_by=user
    )


@pytest.fixture
def in_person_event(community, user):
    """Create an in-person event."""
    return Event.objects.create(
        community=community,
        title='In-Person Event',
        created_by=user,
        format='in_person',
        start_time=timezone.now() + timedelta(days=1),
        end_time=timezone.now() + timedelta(days=1, hours=2),
    )


@pytest.fixture
def hybrid_event(community, user):
    """Create a hybrid event."""
    return Event.objects.create(
        community=community,
        title='Hybrid Event',
        created_by=user,
        format='hybrid',
        start_time=timezone.now() + timedelta(days=1),
        end_time=timezone.now() + timedelta(days=1, hours=2),
    )


@pytest.fixture
def virtual_event(community, user):
    """Create a virtual event."""
    return Event.objects.create(
        community=community,
        title='Virtual Event',
        created_by=user,
        format='virtual',
        start_time=timezone.now() + timedelta(days=1),
        end_time=timezone.now() + timedelta(days=1, hours=2),
    )


@pytest.fixture
def event_registration(user, in_person_event):
    """Create an event registration."""
    return EventRegistration.objects.create(
        event=in_person_event,
        user=user,
        attendee_status='confirmed'
    )


@pytest.mark.django_db
class TestPostAcceptanceFormTemplates:
    """Tests for PostAcceptanceFormTemplate model."""

    def test_create_form_template(self, in_person_event):
        """Test creating a form template."""
        template = PostAcceptanceFormTemplate.objects.create(
            event=in_person_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )
        assert template.event == in_person_event
        assert template.form_type == 'participant_information'
        assert template.is_enabled is True
        assert template.deadline_days == 7

    def test_unique_constraint_form_type_per_event(self, in_person_event):
        """Test that only one template per form_type per event is allowed."""
        PostAcceptanceFormTemplate.objects.create(
            event=in_person_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        with pytest.raises(Exception):  # IntegrityError
            PostAcceptanceFormTemplate.objects.create(
                event=in_person_event,
                form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
                is_enabled=True,
                deadline_days=7
            )


@pytest.mark.django_db
class TestTriggerPostAcceptanceForms:
    """Tests for trigger_post_acceptance_forms service function."""

    def test_trigger_participant_form_on_confirmed_in_person(self, event_registration):
        """Test Participant Info form triggers for confirmed in-person attendees."""
        event = event_registration.event

        PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        created = trigger_post_acceptance_forms(event_registration)

        assert PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION in created
        assignment = created[PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION]
        assert assignment.status == PostAcceptanceFormAssignment.STATUS_NOT_STARTED
        assert assignment.event_registration == event_registration

    def test_trigger_promotional_form_on_confirmed(self, event_registration):
        """Test Promotional Profile form triggers for confirmed attendees."""
        event = event_registration.event

        PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PROMOTIONAL_PROFILE,
            is_enabled=True,
            deadline_days=7
        )

        created = trigger_post_acceptance_forms(event_registration)

        assert PostAcceptanceFormTemplate.FORM_TYPE_PROMOTIONAL_PROFILE in created
        assignment = created[PostAcceptanceFormTemplate.FORM_TYPE_PROMOTIONAL_PROFILE]
        assert assignment.status == PostAcceptanceFormAssignment.STATUS_NOT_STARTED

    def test_no_trigger_on_virtual_event(self, user, virtual_event):
        """Test Participant Info form does NOT trigger for virtual events."""
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

        created = trigger_post_acceptance_forms(registration)

        assert PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION not in created

    def test_trigger_both_forms_in_person(self, event_registration):
        """Test both forms trigger for confirmed in-person attendees."""
        event = event_registration.event

        PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )
        PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PROMOTIONAL_PROFILE,
            is_enabled=True,
            deadline_days=7
        )

        created = trigger_post_acceptance_forms(event_registration)

        assert len(created) == 2
        assert PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION in created
        assert PostAcceptanceFormTemplate.FORM_TYPE_PROMOTIONAL_PROFILE in created

    def test_no_trigger_disabled_form(self, event_registration):
        """Test no assignment created if form is disabled."""
        event = event_registration.event

        PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=False,
            deadline_days=7
        )

        created = trigger_post_acceptance_forms(event_registration)

        assert PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION not in created

    def test_no_trigger_on_non_confirmed_status(self, user, in_person_event):
        """Test no forms trigger if attendee status is not confirmed."""
        registration = EventRegistration.objects.create(
            event=in_person_event,
            user=user,
            attendee_status='payment_pending'
        )

        PostAcceptanceFormTemplate.objects.create(
            event=in_person_event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        created = trigger_post_acceptance_forms(registration)

        assert PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION not in created


@pytest.mark.django_db
class TestDuplicatePrevention:
    """Tests for preventing duplicate form assignments."""

    def test_duplicate_assignment_returns_none(self, event_registration):
        """Test that duplicate assignments return None (not created)."""
        event = event_registration.event

        PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        # First trigger
        created1 = trigger_post_acceptance_forms(event_registration)
        first_assignment = created1[PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION]

        # Second trigger - should not create duplicate
        created2 = trigger_post_acceptance_forms(event_registration)

        # Second call should return empty (no new assignments)
        assert PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION not in created2

        # Verify only one assignment exists
        assignments = PostAcceptanceFormAssignment.objects.filter(
            event_registration=event_registration,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION
        )
        assert assignments.count() == 1


@pytest.mark.django_db
class TestAssignmentStateTransitions:
    """Tests for assignment status state machine."""

    def test_mark_in_progress(self, event_registration):
        """Test marking assignment as in-progress."""
        event = event_registration.event

        template = PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        assignment = PostAcceptanceFormAssignment.objects.create(
            event=event,
            event_registration=event_registration,
            form_template=template,
            form_type=template.form_type,
            deadline=timezone.now() + timedelta(days=7),
            status=PostAcceptanceFormAssignment.STATUS_NOT_STARTED
        )

        mark_assignment_in_progress(assignment)

        assignment.refresh_from_db()
        assert assignment.status == PostAcceptanceFormAssignment.STATUS_IN_PROGRESS
        assert assignment.started_at is not None

    def test_mark_completed(self, event_registration):
        """Test marking assignment as completed."""
        event = event_registration.event

        template = PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        assignment = PostAcceptanceFormAssignment.objects.create(
            event=event,
            event_registration=event_registration,
            form_template=template,
            form_type=template.form_type,
            deadline=timezone.now() + timedelta(days=7),
            status=PostAcceptanceFormAssignment.STATUS_IN_PROGRESS,
            started_at=timezone.now()
        )

        mark_assignment_completed(assignment)

        assignment.refresh_from_db()
        assert assignment.status == PostAcceptanceFormAssignment.STATUS_COMPLETED
        assert assignment.completed_at is not None

    def test_mark_lapsed(self, event_registration):
        """Test marking assignment as lapsed."""
        event = event_registration.event

        template = PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        assignment = PostAcceptanceFormAssignment.objects.create(
            event=event,
            event_registration=event_registration,
            form_template=template,
            form_type=template.form_type,
            deadline=timezone.now() + timedelta(days=7),
            status=PostAcceptanceFormAssignment.STATUS_NOT_STARTED
        )

        mark_assignment_lapsed(assignment)

        assignment.refresh_from_db()
        assert assignment.status == PostAcceptanceFormAssignment.STATUS_LAPSED

    def test_cannot_complete_lapsed_form(self, event_registration):
        """Test that completed forms stay completed when mark_lapsed is called."""
        event = event_registration.event

        template = PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        assignment = PostAcceptanceFormAssignment.objects.create(
            event=event,
            event_registration=event_registration,
            form_template=template,
            form_type=template.form_type,
            deadline=timezone.now() + timedelta(days=7),
            status=PostAcceptanceFormAssignment.STATUS_COMPLETED,
            started_at=timezone.now(),
            completed_at=timezone.now()
        )

        mark_assignment_lapsed(assignment)

        assignment.refresh_from_db()
        assert assignment.status == PostAcceptanceFormAssignment.STATUS_COMPLETED


@pytest.mark.django_db
class TestQueryFunctions:
    """Tests for query helper functions."""

    def test_get_pending_assignments_for_event(self, event_registration):
        """Test getting pending assignments for an event."""
        event = event_registration.event

        template = PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        assignment1 = PostAcceptanceFormAssignment.objects.create(
            event=event,
            event_registration=event_registration,
            form_template=template,
            form_type=template.form_type,
            deadline=timezone.now() + timedelta(days=7),
            status=PostAcceptanceFormAssignment.STATUS_NOT_STARTED
        )

        assignment2 = PostAcceptanceFormAssignment.objects.create(
            event=event,
            event_registration=event_registration,
            form_template=template,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PROMOTIONAL_PROFILE,
            deadline=timezone.now() + timedelta(days=7),
            status=PostAcceptanceFormAssignment.STATUS_COMPLETED
        )

        pending = get_pending_assignments_for_event(event)

        assert pending.count() == 1
        assert pending.first().id == assignment1.id

    def test_get_lapsed_assignments(self, event_registration):
        """Test getting assignments that have passed deadline."""
        event = event_registration.event

        template = PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
            is_enabled=True,
            deadline_days=7
        )

        # Past deadline
        past_deadline = timezone.now() - timedelta(days=1)
        assignment1 = PostAcceptanceFormAssignment.objects.create(
            event=event,
            event_registration=event_registration,
            form_template=template,
            form_type=template.form_type,
            deadline=past_deadline,
            status=PostAcceptanceFormAssignment.STATUS_NOT_STARTED
        )

        # Future deadline
        future_deadline = timezone.now() + timedelta(days=7)
        assignment2 = PostAcceptanceFormAssignment.objects.create(
            event=event,
            event_registration=event_registration,
            form_template=template,
            form_type=PostAcceptanceFormTemplate.FORM_TYPE_PROMOTIONAL_PROFILE,
            deadline=future_deadline,
            status=PostAcceptanceFormAssignment.STATUS_NOT_STARTED
        )

        lapsed = get_lapsed_assignments()

        assert lapsed.count() == 1
        assert lapsed.first().id == assignment1.id
