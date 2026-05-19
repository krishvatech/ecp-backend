"""
Service for managing post-acceptance forms for event attendees.
Handles assignment, tracking, triggering, and writeback of forms post-event-approval.
"""
import logging
from django.utils import timezone
from datetime import timedelta
from django.db import transaction
from events.models import (
    PostAcceptanceFormTemplate,
    PostAcceptanceFormAssignment,
    EventRegistration,
    PostAcceptanceFormSubmission,
    PostAcceptanceFormAnswer,
)

logger = logging.getLogger(__name__)


# Event Format Helper Functions
# These ensure consistent format handling across the system

def is_online_event(event):
    """
    Check if event is online/virtual only (no in-person component).

    Supports both 'online' and 'virtual' format values for compatibility.

    Args:
        event: Event instance

    Returns:
        bool: True if event format is 'virtual' or 'online'
    """
    return event.format in ['virtual', 'online']


def is_in_person_event(event):
    """
    Check if event is in-person only (no hybrid or online component).

    Args:
        event: Event instance

    Returns:
        bool: True if event format is 'in_person'
    """
    return event.format == 'in_person'


def is_hybrid_event(event):
    """
    Check if event is hybrid (has both in-person and online components).

    Args:
        event: Event instance

    Returns:
        bool: True if event format is 'hybrid'
    """
    return event.format == 'hybrid'


def should_show_physical_sections(event, attendance_mode=None):
    """
    Determine if physical-only sections should be visible.

    Logic:
    - In-person: Always show physical sections
    - Hybrid + attendance_mode='in_person': Show physical sections
    - Hybrid + attendance_mode='online': Hide physical sections
    - Virtual: Never show physical sections

    Args:
        event: Event instance
        attendance_mode: User's selected attendance (None for in-person events, 'in_person' or 'online' for hybrid)

    Returns:
        bool: True if physical sections should be shown
    """
    if is_in_person_event(event):
        return True
    elif is_hybrid_event(event):
        # For hybrid, check if user selected in-person attendance
        return attendance_mode == 'in_person'
    else:
        # Virtual/online events never show physical sections
        return False


def trigger_post_acceptance_forms(event_registration):
    """
    Trigger post-acceptance form assignments for a confirmed attendee.

    Idempotent: Safe to call multiple times. Only creates new assignments.
    Non-blocking: Errors are logged but do not break payment/confirmation flow.

    Requirements:
    - If attendee status is confirmed and event is in-person or hybrid:
      create Participant Information Form assignment (role-agnostic)
    - If attendee status is confirmed and has a speaker/moderator/host role:
      create Promotional Profile assignment (role-based)

    Args:
        event_registration: EventRegistration instance

    Returns:
        dict: Created assignments with form_type as key, assignment as value
              Returns empty dict {} if already assigned or conditions not met

    Raises:
        TypeError: If event_registration is not an EventRegistration instance
    """
    if not isinstance(event_registration, EventRegistration):
        raise TypeError("event_registration must be an EventRegistration instance")

    event = event_registration.event
    user = event_registration.user
    created_assignments = {}

    try:
        with transaction.atomic():
            # Trigger Participant Information Form if confirmed and in-person/hybrid
            if (
                event_registration.attendee_status == 'confirmed'
                and (is_in_person_event(event) or is_hybrid_event(event))
            ):
                try:
                    assignment = _create_form_assignment(
                        event_registration,
                        PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION
                    )
                    if assignment:
                        created_assignments[PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION] = assignment
                        logger.info(
                            f"Participant Information Form assigned to {user.username} "
                            f"for event '{event.title}' (event_id={event.id})"
                        )
                except Exception as e:
                    logger.error(
                        f"Failed to create Participant Information Form for {user.username} "
                        f"on event '{event.title}' (event_id={event.id}): {str(e)}",
                        exc_info=True
                    )

            # Trigger Promotional Profile if confirmed AND user has a special role
            # Only speakers, moderators, and hosts get promotional profiles (not regular attendees)
            if event_registration.attendee_status == 'confirmed':
                from events.models import EventParticipant
                has_promotional_role = EventParticipant.objects.filter(
                    event=event,
                    user=user,
                    role__in=['speaker', 'moderator', 'host']
                ).exists()

                if has_promotional_role:
                    try:
                        assignment = _create_form_assignment(
                            event_registration,
                            PostAcceptanceFormTemplate.FORM_TYPE_PROMOTIONAL_PROFILE
                        )
                        if assignment:
                            created_assignments[PostAcceptanceFormTemplate.FORM_TYPE_PROMOTIONAL_PROFILE] = assignment
                            logger.info(
                                f"Promotional Profile Form assigned to {user.username} "
                                f"for event '{event.title}' (event_id={event.id})"
                            )
                    except Exception as e:
                        logger.error(
                            f"Failed to create Promotional Profile Form for {user.username} "
                            f"on event '{event.title}' (event_id={event.id}): {str(e)}",
                            exc_info=True
                        )

        if created_assignments:
            logger.info(
                f"Successfully created {len(created_assignments)} form(s) "
                f"for {user.username} on event '{event.title}'"
            )

    except Exception as e:
        logger.error(
            f"Unexpected error triggering post-acceptance forms for {user.username} "
            f"on event '{event.title}': {str(e)}",
            exc_info=True
        )
        # Do not re-raise - allow payment/confirmation flow to continue

    return created_assignments


def _calculate_form_deadline(event, form_template):
    """
    Calculate deadline for form assignment.

    Logic:
    1. Default: event.start_time - 21 days
    2. If event < 21 days away: min(now + 7 days, event.start_time)
    3. If no start_time: now + deadline_days (or 7 days)
    4. Never allow deadline after event start

    Args:
        event: Event instance
        form_template: PostAcceptanceFormTemplate instance

    Returns:
        datetime: The calculated deadline
    """
    now = timezone.now()
    default_days = form_template.deadline_days or 7

    if event.start_time:
        # Calculate default: 21 days before event start
        default_deadline = event.start_time - timedelta(days=21)

        # If event is less than 21 days away, use min(now + 7 days, event.start_time)
        time_until_event = event.start_time - now
        if time_until_event < timedelta(days=21):
            fallback_deadline = min(
                now + timedelta(days=7),
                event.start_time
            )
            return fallback_deadline

        return default_deadline
    else:
        # No start_time: use now + default_days
        return now + timedelta(days=default_days)


def _create_form_assignment(event_registration, form_type):
    """
    Create or get a form assignment for an attendee.

    Prevents duplicate assignments via unique_together constraint on
    (event_registration, form_type).

    Sends notification email if assignment is newly created.

    Args:
        event_registration: EventRegistration instance
        form_type: Form type constant

    Returns:
        PostAcceptanceFormAssignment or None if form is not enabled
    """
    event = event_registration.event

    form_template = PostAcceptanceFormTemplate.objects.filter(
        event=event,
        form_type=form_type,
        is_enabled=True
    ).first()

    if not form_template:
        return None

    # Only apply complex event-based deadline logic to Participant Information forms
    # Promotional Profile uses simple deadline_days calculation
    if form_type == PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION:
        deadline = _calculate_form_deadline(event, form_template)
    else:
        # For other form types (e.g., Promotional Profile), use simple deadline
        now = timezone.now()
        deadline_days = form_template.deadline_days or 7
        deadline = now + timedelta(days=deadline_days)

    assignment, created = PostAcceptanceFormAssignment.objects.get_or_create(
        event_registration=event_registration,
        form_type=form_type,
        defaults={
            'event': event,
            'form_template': form_template,
            'deadline': deadline,
        }
    )

    # Note: Email is now sent explicitly in approve_application() endpoint
    # to avoid duplicate emails. This function only creates the assignment.

    return assignment if created else None


def mark_assignment_in_progress(assignment):
    """
    Mark a form assignment as in-progress when user starts the form.

    Args:
        assignment: PostAcceptanceFormAssignment instance
    """
    if assignment.status != PostAcceptanceFormAssignment.STATUS_NOT_STARTED:
        raise ValueError(f"Cannot start form with status {assignment.status}")

    assignment.status = PostAcceptanceFormAssignment.STATUS_IN_PROGRESS
    assignment.started_at = timezone.now()
    assignment.save(update_fields=['status', 'started_at'])


def mark_assignment_completed(assignment):
    """
    Mark a form assignment as completed when user submits the form.

    Args:
        assignment: PostAcceptanceFormAssignment instance
    """
    if assignment.status not in [
        PostAcceptanceFormAssignment.STATUS_NOT_STARTED,
        PostAcceptanceFormAssignment.STATUS_IN_PROGRESS,
    ]:
        raise ValueError(f"Cannot complete form with status {assignment.status}")

    assignment.status = PostAcceptanceFormAssignment.STATUS_COMPLETED
    assignment.completed_at = timezone.now()
    if not assignment.started_at:
        assignment.started_at = timezone.now()
    assignment.save(update_fields=['status', 'started_at', 'completed_at'])


def mark_assignment_lapsed(assignment):
    """
    Mark a form assignment as lapsed when deadline passes.

    Args:
        assignment: PostAcceptanceFormAssignment instance
    """
    if assignment.status == PostAcceptanceFormAssignment.STATUS_COMPLETED:
        return

    assignment.status = PostAcceptanceFormAssignment.STATUS_LAPSED
    assignment.save(update_fields=['status'])


def get_pending_assignments_for_event(event):
    """
    Get all incomplete form assignments for an event.

    Args:
        event: Event instance

    Returns:
        QuerySet of PostAcceptanceFormAssignment
    """
    return PostAcceptanceFormAssignment.objects.filter(
        event=event,
        status__in=[
            PostAcceptanceFormAssignment.STATUS_NOT_STARTED,
            PostAcceptanceFormAssignment.STATUS_IN_PROGRESS,
        ]
    )


def get_lapsed_assignments(deadline_before=None):
    """
    Get all form assignments that have passed their deadline.

    Args:
        deadline_before: datetime to check against (defaults to now)

    Returns:
        QuerySet of PostAcceptanceFormAssignment
    """
    if not deadline_before:
        deadline_before = timezone.now()

    return PostAcceptanceFormAssignment.objects.filter(
        status__in=[
            PostAcceptanceFormAssignment.STATUS_NOT_STARTED,
            PostAcceptanceFormAssignment.STATUS_IN_PROGRESS,
        ],
        deadline__lt=deadline_before
    )


def send_form_assignment_email(assignment):
    """
    Send form assignment notification email to user.

    Creates and sends an email with the form URL.

    Args:
        assignment: PostAcceptanceFormAssignment instance

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    try:
        from users.email_utils import send_template_email, format_event_time_for_email
        from django.conf import settings

        user = assignment.event_registration.user
        event = assignment.event
        form_template = assignment.form_template

        # Generate form access URL
        frontend_url = (settings.FRONTEND_URL or 'http://localhost:5173').rstrip('/')
        form_url = f"{frontend_url}/forms/{assignment.id}"

        # Prepare context
        event_time_info = format_event_time_for_email(event)
        context = {
            'first_name': user.first_name or user.username,
            'event_title': event.title,
            'form_title': form_template.title if hasattr(form_template, 'title') else 'Participant Information',
            'form_url': form_url,
            'deadline': (assignment.deadline).strftime('%B %d, %Y') if assignment.deadline else 'TBD',
            'event_date': event_time_info.get('event_date_str', ''),
            **event_time_info,
        }

        # Send email
        result = send_template_email(
            template_key='post_acceptance_form_sent',
            to_email=user.email,
            context=context,
            event=event,
            fail_silently=False
        )

        if result:
            logger.info(f"Form assignment email sent to {user.email} for assignment {assignment.id}")
        return result

    except Exception as e:
        logger.error(f"Failed to send form assignment email for assignment {assignment.id}: {str(e)}", exc_info=True)
        return False


def send_form_reminder_email(assignment):
    """
    Send reminder email for incomplete form assignment.

    Args:
        assignment: PostAcceptanceFormAssignment instance

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    try:
        from users.email_utils import send_template_email, format_event_time_for_email
        from django.conf import settings

        user = assignment.event_registration.user
        event = assignment.event
        form_template = assignment.form_template

        # Generate form access URL
        frontend_url = (settings.FRONTEND_URL or 'http://localhost:5173').rstrip('/')
        form_url = f"{frontend_url}/forms/{assignment.id}"

        # Prepare context
        event_time_info = format_event_time_for_email(event)
        context = {
            'first_name': user.first_name or user.username,
            'event_title': event.title,
            'form_title': form_template.title if hasattr(form_template, 'title') else 'Participant Information',
            'form_url': form_url,
            'deadline': (assignment.deadline).strftime('%B %d, %Y') if assignment.deadline else 'TBD',
            'event_date': event_time_info.get('event_date_str', ''),
            **event_time_info,
        }

        # Send reminder email
        result = send_template_email(
            template_key='post_acceptance_form_reminder',
            to_email=user.email,
            context=context,
            event=event,
            fail_silently=False
        )

        if result:
            logger.info(f"Form reminder email sent to {user.email} for assignment {assignment.id}")
        return result

    except Exception as e:
        logger.error(f"Failed to send form reminder email for assignment {assignment.id}: {str(e)}", exc_info=True)
        return False


def writeback_participant_information_form(assignment):
    """
    Write form submission data back to EventRegistration.

    Updates registration with:
    - directory_visibility (from share_contact_details: 'yes' -> True)
    - photo_video_consent (from photo_video_consent: 'yes' -> 'full', 'no' -> 'no')
    - visa_support_requested (from visa_support: 'required' OR 'not_yet_sure' -> True)
    - participant_information_completed_at (timestamp)

    Args:
        assignment: PostAcceptanceFormAssignment instance

    Returns:
        bool: True if writeback successful, False otherwise
    """
    if assignment.form_type != PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION:
        logger.warning(f"Writeback called on non-participant-info form: {assignment.id}")
        return False

    try:
        submission = assignment.submission
    except PostAcceptanceFormSubmission.DoesNotExist:
        logger.warning(f"No submission found for assignment {assignment.id}")
        return False

    try:
        registration = assignment.event_registration
        answers = {ans.question_key: ans for ans in submission.answers.all()}

        update_fields = ['participant_information_completed_at']

        # share_contact_details: 'yes' -> True, otherwise False
        if 'share_contact_details' in answers:
            registration.directory_visibility = answers['share_contact_details'].answer_text == 'yes'
            update_fields.append('directory_visibility')

        # photo_video_consent: 'yes' -> 'full' (best option), 'no' -> 'no'
        if 'photo_video_consent' in answers:
            consent_value = answers['photo_video_consent'].answer_text or 'no'
            # Map new form values to model choices
            if consent_value == 'yes':
                registration.photo_video_consent = 'full'
            else:
                registration.photo_video_consent = 'no'
            update_fields.append('photo_video_consent')

        # visa_support: 'required' OR 'not_yet_sure' -> True
        # This allows attendee to request visa support letter or indicate uncertainty
        if 'visa_support' in answers:
            visa_value = answers['visa_support'].answer_text or ''
            registration.visa_support_requested = visa_value in ['required', 'not_yet_sure']
            update_fields.append('visa_support_requested')

        # accessibility_support_needs: 'yes' indicates accessibility declaration
        # This flag helps admin identify attendees who need accessibility support
        # Set to True if support_needs = 'yes' AND any detail field is provided
        accessibility_declared = False
        if 'accessibility_support_needs' in answers and answers['accessibility_support_needs'].answer_text == 'yes':
            # Check if any detail was provided
            has_detail = (
                ('accessibility_needs_detail' in answers and answers['accessibility_needs_detail'].answer_text) or
                ('mobility_seating_requirements' in answers and answers['mobility_seating_requirements'].answer_text) or
                ('medical_info_emergency' in answers and answers['medical_info_emergency'].answer_text)
            )
            accessibility_declared = has_detail

        if accessibility_declared:
            registration.accessibility_need_declared = True
            update_fields.append('accessibility_need_declared')

        # Mark completion
        registration.participant_information_completed_at = timezone.now()

        registration.save(update_fields=update_fields)

        logger.info(
            f"Wrote back form {assignment.id} to registration {registration.id} "
            f"for user {registration.user.username}. "
            f"Accessibility declared: {accessibility_declared}"
        )
        return True

    except Exception as e:
        logger.error(
            f"Writeback failed for assignment {assignment.id}: {str(e)}",
            exc_info=True
        )
        return False
