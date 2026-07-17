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


def trigger_post_acceptance_forms(event_registration, form_template_cache=None):
    """
    Trigger post-acceptance form assignments only for CONFIRMED origins.

    For multi-track applications:
    - Participant Information Form: only if has confirmed non-speaker origins AND in-person/hybrid event
    - Promotional Profile: only if has confirmed speaker/moderator/host origins

    Idempotent: Safe to call multiple times. Only creates new assignments.
    Non-blocking: Errors are logged but do not break payment/confirmation flow.

    Args:
        event_registration: EventRegistration instance
        form_template_cache: Optional dict {form_type: template} for reuse in bulk operations

    Returns:
        dict: Created assignments with form_type as key, assignment as value
              Returns empty dict {} if already assigned or conditions not met

    Raises:
        TypeError: If event_registration is not an EventRegistration instance
    """
    if form_template_cache is None:
        form_template_cache = {}
    if not isinstance(event_registration, EventRegistration):
        raise TypeError("event_registration must be an EventRegistration instance")

    event = event_registration.event
    user = event_registration.user
    created_assignments = {}

    # Skip form assignment for event organizers/creators (event owner)
    if user == event.created_by:
        logger.debug(f"Skipping form assignments for {user.username} - event organizer")
        return created_assignments

    try:
        with transaction.atomic():
            # Get only CONFIRMED origins
            confirmed_origins = event_registration.origins.filter(
                status='active',
                origin_status='confirmed'
            ).select_related('role')

            if not confirmed_origins.exists():
                logger.debug(
                    f"No confirmed origins for {user.username} on event '{event.title}', skipping form assignments"
                )
                return created_assignments

            # Trigger Participant Information Form for ALL confirmed attendees in in-person/hybrid events
            # Per Jira: Form is role-agnostic. One form per attendee regardless of roles.
            if is_in_person_event(event) or is_hybrid_event(event):
                try:
                    assignment = _create_form_assignment(
                        event_registration,
                        PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION,
                        form_template_cache=form_template_cache
                    )
                    if assignment:
                        created_assignments[PostAcceptanceFormTemplate.FORM_TYPE_PARTICIPANT_INFORMATION] = assignment
                        logger.debug(
                            f"Participant Information Form assigned to {user.username} "
                            f"for event '{event.title}' (event_id={event.id})"
                        )
                except Exception as e:
                    logger.error(
                        f"Failed to create Participant Information Form for {user.username} "
                        f"on event '{event.title}' (event_id={event.id}): {str(e)}",
                        exc_info=True
                    )

            # Trigger Promotional Profile if has confirmed roles with triggers_promotional_profile=true
            # Per Jira §1: Fires when attendee has at least one role flagged triggers_promotional_profile=true
            has_promotional_role = confirmed_origins.filter(
                role__triggers_promotional_profile=True
            ).exists()

            if has_promotional_role:
                from events.services.promotional_profile_service import get_promotional_modules_for_attendee
                modules = get_promotional_modules_for_attendee(event_registration)

                if modules:
                    try:
                        from events.services.promotional_profile_service import get_or_create_promotional_profile
                        assignment, created = get_or_create_promotional_profile(event_registration)
                        if assignment:
                            created_assignments[PostAcceptanceFormTemplate.FORM_TYPE_PROMOTIONAL_PROFILE] = assignment
                            logger.debug(
                                f"Promotional Profile Form assigned to {user.username} "
                                f"for event '{event.title}' (event_id={event.id}) with modules: {modules}"
                            )
                    except Exception as e:
                        logger.error(
                            f"Failed to create Promotional Profile Form for {user.username} "
                            f"on event '{event.title}' (event_id={event.id}): {str(e)}",
                            exc_info=True
                        )

        if created_assignments:
            logger.debug(
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


def _create_form_assignment(event_registration, form_type, form_template_cache=None):
    """
    Create or get a form assignment for an attendee.

    Prevents duplicate assignments via unique_together constraint on
    (event_registration, form_type).

    Sends notification email if assignment is newly created.

    Args:
        event_registration: EventRegistration instance
        form_type: Form type constant
        form_template_cache: Optional dict {form_type: template} for reuse in bulk operations

    Returns:
        PostAcceptanceFormAssignment or None if form is not enabled
    """
    if form_template_cache is None:
        form_template_cache = {}

    event = event_registration.event

    # Use cache or query template
    if form_type in form_template_cache:
        form_template = form_template_cache[form_type]
    else:
        form_template = PostAcceptanceFormTemplate.objects.filter(
            event=event,
            form_type=form_type,
            is_enabled=True
        ).first()
        form_template_cache[form_type] = form_template

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
    restored = False
    if not created and getattr(assignment, 'is_deleted', False):
        assignment.restore(status_value=PostAcceptanceFormAssignment.STATUS_NOT_STARTED)
        assignment.form_template = form_template
        assignment.deadline = deadline
        assignment.save(update_fields=['form_template', 'deadline', 'updated_at'])
        restored = True

    # FIX: Send form email synchronously (reliable) after assignment is persisted
    if created or restored:
        def send_email():
            try:
                # Send synchronously for reliability - users should receive form email immediately
                send_form_assignment_email(assignment)
                logger.info(f"Form assignment email sent to {assignment.event_registration.user.email} for assignment {assignment.id}")
            except Exception as e:
                logger.error(
                    f"Failed to send form assignment email for {assignment.id}: {str(e)}",
                    exc_info=True
                )
                # Don't fail assignment creation if email fails

        from django.db import transaction
        transaction.on_commit(send_email)

    return assignment if (created or restored) else None


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
        is_deleted=False,
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
        is_deleted=False,
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
        # Optimize query: only fetch needed fields, exclude large JSON data
        answers = {
            ans.question_key: ans
            for ans in submission.answers.all().only('question_key', 'answer_text', 'answer_data')
        }

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

        # attendance_mode: save for hybrid events ('in_person' or 'online')
        if 'attendance_mode' in answers and answers['attendance_mode'].answer_text:
            registration.attendance_mode = answers['attendance_mode'].answer_text
            update_fields.append('attendance_mode')

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


# ==================== SPEAKER MODULE VALIDATION ====================

def validate_speaker_module_submission(answers, assignment=None):
    """
    Validate speaker module form submission.

    Validates required fields, file uploads, text lengths, and URLs.

    Args:
        answers: dict of form answers {field_id: value}
        assignment: PostAcceptanceFormAssignment instance (optional, for context)

    Returns:
        dict: {
            'valid': bool,
            'errors': {'field_id': 'error message', ...}
        }
    """
    from events.validators import (
        validate_headshot,
        validate_slide_deck,
        validate_speaker_bio,
        validate_short_bio
    )
    from django.core.exceptions import ValidationError

    errors = {}

    # FIX 4: Use prefixed field keys (speaker_* prefix)
    # Required text fields
    required_fields = [
        'speaker_display_name', 'speaker_programme_title', 'speaker_programme_affiliation',
        'speaker_headshot', 'speaker_programme_bio', 'speaker_short_bio',
        'speaker_talk_title', 'speaker_talk_abstract', 'speaker_session_format', 'speaker_display_consent'
    ]

    for field in required_fields:
        if field not in answers or not answers[field]:
            errors[field] = f'{field} is required'

    # Display name validation
    if 'speaker_display_name' in answers and answers['speaker_display_name']:
        name = answers['speaker_display_name']
        if len(name) < 2 or len(name) > 150:
            errors['speaker_display_name'] = 'Display name must be 2-150 characters'

    # Programme title validation
    if 'speaker_programme_title' in answers and answers['speaker_programme_title']:
        title = answers['speaker_programme_title']
        if len(title) < 2 or len(title) > 100:
            errors['speaker_programme_title'] = 'Professional title must be 2-100 characters'

    # Programme affiliation validation
    if 'speaker_programme_affiliation' in answers and answers['speaker_programme_affiliation']:
        aff = answers['speaker_programme_affiliation']
        if len(aff) < 2 or len(aff) > 150:
            errors['speaker_programme_affiliation'] = 'Organization must be 2-150 characters'

    # Headshot validation
    if 'speaker_headshot' in answers and answers['speaker_headshot']:
        try:
            validate_headshot(answers['speaker_headshot'])
        except ValidationError as e:
            errors['speaker_headshot'] = str(e.message)

    # Programme bio validation (100-200 words)
    if 'speaker_programme_bio' in answers and answers['speaker_programme_bio']:
        bio_result = validate_speaker_bio(answers['speaker_programme_bio'], 'Programme bio')
        if not bio_result['valid']:
            errors['speaker_programme_bio'] = '; '.join(bio_result['errors'])

    # Short bio validation (max 200 characters)
    if 'speaker_short_bio' in answers and answers['speaker_short_bio']:
        try:
            validate_short_bio(answers['speaker_short_bio'])
        except ValidationError as e:
            errors['speaker_short_bio'] = str(e.message)

    # Talk title validation
    if 'speaker_talk_title' in answers and answers['speaker_talk_title']:
        title = answers['speaker_talk_title']
        if len(title) < 3 or len(title) > 200:
            errors['speaker_talk_title'] = 'Talk title must be 3-200 characters'

    # Talk abstract validation (20-200 words)
    if 'speaker_talk_abstract' in answers and answers['speaker_talk_abstract']:
        abstract = answers['speaker_talk_abstract']
        words = len([w for w in abstract.split() if w.strip()])
        if words < 20 or words > 200:
            errors['speaker_talk_abstract'] = f'Talk abstract must be 20-200 words (currently {words} words)'

    # Session format validation
    valid_formats = ['keynote', 'presentation', 'panel', 'workshop', 'lightning_talk', 'fireside_chat', 'demo', 'other']
    if 'speaker_session_format' in answers and answers['speaker_session_format']:
        if answers['speaker_session_format'] not in valid_formats:
            errors['speaker_session_format'] = f'Invalid session format'

    # Slide deck validation (optional but if provided, must be valid)
    if 'speaker_slide_deck' in answers and answers['speaker_slide_deck']:
        try:
            validate_slide_deck(answers['speaker_slide_deck'])
        except ValidationError as e:
            errors['speaker_slide_deck'] = str(e.message)

    # LinkedIn URL validation (optional)
    if 'speaker_linkedin_url' in answers and answers['speaker_linkedin_url']:
        url = answers['speaker_linkedin_url']
        if not url.startswith(('http://', 'https://')):
            errors['speaker_linkedin_url'] = 'LinkedIn URL must start with http:// or https://'
        if len(url) > 255:
            errors['speaker_linkedin_url'] = 'LinkedIn URL is too long'

    # Twitter handle validation (optional)
    if 'speaker_twitter_handle' in answers and answers['speaker_twitter_handle']:
        handle = answers['speaker_twitter_handle']
        handle = handle.lstrip('@')  # Remove @ if present
        if not (1 <= len(handle) <= 15):
            errors['speaker_twitter_handle'] = 'Twitter handle must be 1-15 characters (without @)'
        if not handle.replace('_', '').isalnum():
            errors['speaker_twitter_handle'] = 'Twitter handle can only contain letters, numbers, and underscores'

    # Personal website validation (optional)
    if 'speaker_personal_website' in answers and answers['speaker_personal_website']:
        url = answers['speaker_personal_website']
        if not url.startswith(('http://', 'https://')):
            errors['speaker_personal_website'] = 'Website URL must start with http:// or https://'
        if len(url) > 255:
            errors['speaker_personal_website'] = 'Website URL is too long'

    # Display consent validation
    if 'speaker_display_consent' in answers and answers['speaker_display_consent']:
        if answers['speaker_display_consent'] not in ['yes', 'no']:
            errors['speaker_display_consent'] = 'Display consent must be "yes" or "no"'

    return {
        'valid': len(errors) == 0,
        'errors': errors
    }


def writeback_speaker_profile_form(assignment):
    """
    Write speaker module submission data back to EventRegistration.

    Updates speaker-related fields and marks form as complete.

    Args:
        assignment: PostAcceptanceFormAssignment instance

    Returns:
        bool: True if writeback successful, False otherwise
    """
    try:
        submission = assignment.submission
        registration = assignment.event_registration

        # Extract answer data
        answers_dict = {}
        for answer in submission.answers.all():
            answers_dict[answer.question_key] = answer.answer_text or answer.answer_data

        # FIX 4: Update display_consent using prefixed field key
        if 'speaker_display_consent' in answers_dict:
            registration.display_consent = answers_dict['speaker_display_consent']

        # Mark promotional profile as complete
        registration.promotional_profile_completed_at = timezone.now()

        update_fields = ['display_consent', 'promotional_profile_completed_at']
        registration.save(update_fields=update_fields)

        logger.info(
            f"Wrote back speaker profile {assignment.id} to registration {registration.id} "
            f"for user {registration.user.username}. "
            f"Display consent: {registration.display_consent}"
        )
        return True

    except Exception as e:
        logger.error(
            f"Speaker profile writeback failed for assignment {assignment.id}: {str(e)}",
            exc_info=True
        )
        return False


# ==================== SPONSOR MODULE VALIDATION ====================

def validate_sponsor_organisation_submission(answers):
    """
    Validate sponsor organisation module submission.

    Args:
        answers: dict of form answers

    Returns:
        dict: {'valid': bool, 'errors': {field: message}}
    """
    from events.validators import (
        validate_organisation_logo,
        validate_organisation_description
    )
    from django.core.exceptions import ValidationError

    errors = {}

    # FIX 4: Use prefixed field keys (sponsor_org_* prefix)
    # Required fields
    required_fields = [
        'sponsor_org_organisation_name_display', 'sponsor_org_organisation_logo', 'sponsor_org_tagline',
        'sponsor_org_programme_description', 'sponsor_org_website_url', 'sponsor_org_primary_contact_name',
        'sponsor_org_primary_contact_email'
    ]

    for field in required_fields:
        if field not in answers or not answers[field]:
            errors[field] = f'{field} is required'

    # Validate organisation name
    if 'sponsor_org_organisation_name_display' in answers and answers['sponsor_org_organisation_name_display']:
        name = answers['sponsor_org_organisation_name_display']
        if len(name) < 2 or len(name) > 150:
            errors['sponsor_org_organisation_name_display'] = 'Name must be 2-150 characters'

    # Validate tagline
    if 'sponsor_org_tagline' in answers and answers['sponsor_org_tagline']:
        tagline = answers['sponsor_org_tagline']
        if len(tagline) < 5 or len(tagline) > 100:
            errors['sponsor_org_tagline'] = 'Tagline must be 5-100 characters'

    # Validate description
    if 'sponsor_org_programme_description' in answers and answers['sponsor_org_programme_description']:
        desc_result = validate_organisation_description(answers['sponsor_org_programme_description'])
        if not desc_result['valid']:
            errors['sponsor_org_programme_description'] = '; '.join(desc_result['errors'])

    # Validate logos
    if 'sponsor_org_organisation_logo' in answers and answers['sponsor_org_organisation_logo']:
        try:
            validate_organisation_logo(answers['sponsor_org_organisation_logo'], 'sponsor_org_organisation_logo')
        except ValidationError as e:
            errors['sponsor_org_organisation_logo'] = str(e.message)

    if 'sponsor_org_organisation_logo_dark' in answers and answers['sponsor_org_organisation_logo_dark']:
        try:
            validate_organisation_logo(answers['sponsor_org_organisation_logo_dark'], 'sponsor_org_organisation_logo_dark')
        except ValidationError as e:
            errors['sponsor_org_organisation_logo_dark'] = str(e.message)

    # Validate URLs
    if 'sponsor_org_website_url' in answers and answers['sponsor_org_website_url']:
        if not answers['sponsor_org_website_url'].startswith(('http://', 'https://')):
            errors['sponsor_org_website_url'] = 'URL must start with http:// or https://'

    # Validate email
    if 'sponsor_org_primary_contact_email' in answers and answers['sponsor_org_primary_contact_email']:
        import re
        email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_pattern, answers['sponsor_org_primary_contact_email']):
            errors['sponsor_org_primary_contact_email'] = 'Invalid email format'

    return {'valid': len(errors) == 0, 'errors': errors}


# ==================== SPONSOR STAFF MODULE VALIDATION ====================

def validate_sponsor_staff_submission(answers):
    """Validate sponsor staff module submission."""
    # FIX 4: Use prefixed field keys (sponsor_staff_* prefix)
    errors = {}

    required_fields = ['sponsor_staff_display_name', 'sponsor_staff_role_at_sponsor', 'sponsor_staff_booth_presence', 'sponsor_staff_display_consent']

    for field in required_fields:
        if field not in answers or not answers[field]:
            errors[field] = f'{field} is required'

    # Validate display name
    if 'sponsor_staff_display_name' in answers and answers['sponsor_staff_display_name']:
        if len(answers['sponsor_staff_display_name']) < 2 or len(answers['sponsor_staff_display_name']) > 150:
            errors['sponsor_staff_display_name'] = 'Name must be 2-150 characters'

    # Validate role
    if 'sponsor_staff_role_at_sponsor' in answers and answers['sponsor_staff_role_at_sponsor']:
        if len(answers['sponsor_staff_role_at_sponsor']) < 2 or len(answers['sponsor_staff_role_at_sponsor']) > 100:
            errors['sponsor_staff_role_at_sponsor'] = 'Role must be 2-100 characters'

    return {'valid': len(errors) == 0, 'errors': errors}


# ==================== STARTUP MODULE VALIDATION ====================

def validate_startup_submission(answers):
    """Validate startup module submission."""
    from events.validators import (
        validate_startup_pitch,
        validate_startup_description,
        validate_pitch_deck,
        validate_founder_photos
    )
    from django.core.exceptions import ValidationError

    # FIX 4: Use prefixed field keys (startup_* prefix)
    errors = {}

    required_fields = [
        'startup_company_name_display', 'startup_company_logo', 'startup_one_line_pitch',
        'startup_programme_description', 'startup_stage', 'startup_sector_industry',
        'startup_founded_year', 'startup_website_url', 'startup_founder_names_roles', 'startup_display_consent'
    ]

    for field in required_fields:
        if field not in answers or not answers[field]:
            errors[field] = f'{field} is required'

    # Validate pitch
    if 'startup_one_line_pitch' in answers and answers['startup_one_line_pitch']:
        try:
            validate_startup_pitch(answers['startup_one_line_pitch'])
        except ValidationError as e:
            errors['startup_one_line_pitch'] = str(e.message)

    # Validate description
    if 'startup_programme_description' in answers and answers['startup_programme_description']:
        desc_result = validate_startup_description(answers['startup_programme_description'])
        if not desc_result['valid']:
            errors['startup_programme_description'] = '; '.join(desc_result['errors'])

    # Validate founded year
    if 'startup_founded_year' in answers and answers['startup_founded_year']:
        try:
            year = int(answers['startup_founded_year'])
            if year < 2000 or year > 2026:
                errors['startup_founded_year'] = 'Year must be between 2000 and 2026'
        except (ValueError, TypeError):
            errors['startup_founded_year'] = 'Invalid year format'

    # Validate pitch deck
    if 'startup_public_pitch_deck' in answers and answers['startup_public_pitch_deck']:
        try:
            validate_pitch_deck(answers['startup_public_pitch_deck'])
        except ValidationError as e:
            errors['startup_public_pitch_deck'] = str(e.message)

    # Validate founder photos
    if 'startup_founder_photos' in answers and answers['startup_founder_photos']:
        try:
            validate_founder_photos(answers['startup_founder_photos'])
        except ValidationError as e:
            errors['startup_founder_photos'] = str(e.message)

    return {'valid': len(errors) == 0, 'errors': errors}


# ==================== INVESTOR MODULE VALIDATION ====================

def validate_investor_submission(answers):
    """Validate investor module submission."""
    from events.validators import validate_thesis_tagline
    from django.core.exceptions import ValidationError

    # FIX 4: Use prefixed field keys (investor_* prefix)
    errors = {}

    required_fields = [
        'investor_display_name', 'investor_thesis_tagline', 'investor_stage_focus',
        'investor_sector_focus', 'investor_geographic_focus', 'investor_cheque_size_range',
        'investor_open_to_inbound', 'investor_display_consent'
    ]

    for field in required_fields:
        if field not in answers or not answers[field]:
            errors[field] = f'{field} is required'

    # Validate display name
    if 'investor_display_name' in answers and answers['investor_display_name']:
        if len(answers['investor_display_name']) < 2 or len(answers['investor_display_name']) > 150:
            errors['investor_display_name'] = 'Name must be 2-150 characters'

    # Validate tagline
    if 'investor_thesis_tagline' in answers and answers['investor_thesis_tagline']:
        try:
            validate_thesis_tagline(answers['investor_thesis_tagline'])
        except ValidationError as e:
            errors['investor_thesis_tagline'] = str(e.message)

    return {'valid': len(errors) == 0, 'errors': errors}


# ==================== PROMOTIONAL PROFILE WRITEBACK ====================

def writeback_promotional_profile_module(assignment, module_type):
    """
    Generic writeback for promotional profile modules.

    Args:
        assignment: PostAcceptanceFormAssignment
        module_type: 'speaker', 'sponsor_staff', 'startup', 'investor', 'sponsor_organisation'

    Returns:
        bool: Success status
    """
    try:
        submission = assignment.submission
        registration = assignment.event_registration

        # FIX 4: Map module_type to field prefix and look for prefixed display_consent
        prefix_map = {
            'speaker': 'speaker_',
            'sponsor_staff': 'sponsor_staff_',
            'startup': 'startup_',
            'investor': 'investor_',
            'sponsor_organisation': 'sponsor_org_',
        }
        prefix = prefix_map.get(module_type, '')
        consent_field_key = f'{prefix}display_consent'

        # Update display_consent using prefixed field key
        for answer in submission.answers.all():
            if answer.question_key == consent_field_key:
                registration.display_consent = answer.answer_text
                break

        # Mark promotional profile as complete
        registration.promotional_profile_completed_at = timezone.now()

        update_fields = ['display_consent', 'promotional_profile_completed_at']
        registration.save(update_fields=update_fields)

        logger.info(
            f"Wrote back {module_type} module {assignment.id} to registration {registration.id}"
        )
        return True

    except Exception as e:
        logger.error(
            f"Writeback failed for {module_type} module {assignment.id}: {str(e)}",
            exc_info=True
        )
        return False
