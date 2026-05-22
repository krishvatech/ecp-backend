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
        form_template_cache: Optional dict {form_type: template} for reuse in bulk operations
                            Allows caching templates across multiple registrations

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

            # Trigger Promotional Profile if confirmed AND user has promotional-eligible roles
            if event_registration.attendee_status == 'confirmed':
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

    # Queue email notification asynchronously after assignment is persisted
    if created:
        def queue_email():
            from events.tasks import send_form_assignment_email_task
            try:
                send_form_assignment_email_task.delay(assignment.id)
            except Exception as e:
                logger.error(
                    f"Failed to queue form assignment email for {assignment.id}: {str(e)}",
                    exc_info=True
                )
                # If Celery is unavailable, fall back to synchronous send
                try:
                    send_form_assignment_email(assignment)
                except Exception as fallback_e:
                    logger.error(
                        f"Fallback: Failed to send form assignment email for {assignment.id}: {str(fallback_e)}",
                        exc_info=True
                    )
                    # Don't fail assignment creation if email fails

        from django.db import transaction
        transaction.on_commit(queue_email)

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

    # Required text fields
    required_fields = [
        'display_name', 'programme_title', 'programme_affiliation',
        'headshot', 'programme_bio', 'short_bio',
        'talk_title', 'talk_abstract', 'session_format', 'display_consent'
    ]

    for field in required_fields:
        if field not in answers or not answers[field]:
            errors[field] = f'{field} is required'

    # Display name validation
    if 'display_name' in answers and answers['display_name']:
        name = answers['display_name']
        if len(name) < 2 or len(name) > 150:
            errors['display_name'] = 'Display name must be 2-150 characters'

    # Programme title validation
    if 'programme_title' in answers and answers['programme_title']:
        title = answers['programme_title']
        if len(title) < 2 or len(title) > 100:
            errors['programme_title'] = 'Professional title must be 2-100 characters'

    # Programme affiliation validation
    if 'programme_affiliation' in answers and answers['programme_affiliation']:
        aff = answers['programme_affiliation']
        if len(aff) < 2 or len(aff) > 150:
            errors['programme_affiliation'] = 'Organization must be 2-150 characters'

    # Headshot validation
    if 'headshot' in answers and answers['headshot']:
        try:
            validate_headshot(answers['headshot'])
        except ValidationError as e:
            errors['headshot'] = str(e.message)

    # Programme bio validation (100-200 words)
    if 'programme_bio' in answers and answers['programme_bio']:
        bio_result = validate_speaker_bio(answers['programme_bio'], 'Programme bio')
        if not bio_result['valid']:
            errors['programme_bio'] = '; '.join(bio_result['errors'])

    # Short bio validation (max 200 characters)
    if 'short_bio' in answers and answers['short_bio']:
        try:
            validate_short_bio(answers['short_bio'])
        except ValidationError as e:
            errors['short_bio'] = str(e.message)

    # Talk title validation
    if 'talk_title' in answers and answers['talk_title']:
        title = answers['talk_title']
        if len(title) < 3 or len(title) > 200:
            errors['talk_title'] = 'Talk title must be 3-200 characters'

    # Talk abstract validation (20-200 words)
    if 'talk_abstract' in answers and answers['talk_abstract']:
        abstract = answers['talk_abstract']
        words = len([w for w in abstract.split() if w.strip()])
        if words < 20 or words > 200:
            errors['talk_abstract'] = f'Talk abstract must be 20-200 words (currently {words} words)'

    # Session format validation
    valid_formats = ['keynote', 'presentation', 'panel', 'workshop', 'lightning_talk', 'fireside_chat', 'other']
    if 'session_format' in answers and answers['session_format']:
        if answers['session_format'] not in valid_formats:
            errors['session_format'] = f'Invalid session format'

    # Slide deck validation (optional but if provided, must be valid)
    if 'slide_deck' in answers and answers['slide_deck']:
        try:
            validate_slide_deck(answers['slide_deck'])
        except ValidationError as e:
            errors['slide_deck'] = str(e.message)

    # LinkedIn URL validation (optional)
    if 'linkedin_url' in answers and answers['linkedin_url']:
        url = answers['linkedin_url']
        if not url.startswith(('http://', 'https://')):
            errors['linkedin_url'] = 'LinkedIn URL must start with http:// or https://'
        if len(url) > 255:
            errors['linkedin_url'] = 'LinkedIn URL is too long'

    # Twitter handle validation (optional)
    if 'twitter_handle' in answers and answers['twitter_handle']:
        handle = answers['twitter_handle']
        handle = handle.lstrip('@')  # Remove @ if present
        if not (1 <= len(handle) <= 15):
            errors['twitter_handle'] = 'Twitter handle must be 1-15 characters (without @)'
        if not handle.replace('_', '').isalnum():
            errors['twitter_handle'] = 'Twitter handle can only contain letters, numbers, and underscores'

    # Personal website validation (optional)
    if 'personal_website' in answers and answers['personal_website']:
        url = answers['personal_website']
        if not url.startswith(('http://', 'https://')):
            errors['personal_website'] = 'Website URL must start with http:// or https://'
        if len(url) > 255:
            errors['personal_website'] = 'Website URL is too long'

    # Display consent validation
    if 'display_consent' in answers and answers['display_consent']:
        if answers['display_consent'] not in ['yes', 'no']:
            errors['display_consent'] = 'Display consent must be "yes" or "no"'

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

        # Update display_consent
        if 'display_consent' in answers_dict:
            registration.display_consent = answers_dict['display_consent']

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

    # Required fields
    required_fields = [
        'organisation_name_display', 'organisation_logo', 'tagline',
        'programme_description', 'website_url', 'primary_contact_name',
        'primary_contact_email', 'display_consent'
    ]

    for field in required_fields:
        if field not in answers or not answers[field]:
            errors[field] = f'{field} is required'

    # Validate organisation name
    if 'organisation_name_display' in answers and answers['organisation_name_display']:
        name = answers['organisation_name_display']
        if len(name) < 2 or len(name) > 150:
            errors['organisation_name_display'] = 'Name must be 2-150 characters'

    # Validate tagline
    if 'tagline' in answers and answers['tagline']:
        tagline = answers['tagline']
        if len(tagline) < 5 or len(tagline) > 100:
            errors['tagline'] = 'Tagline must be 5-100 characters'

    # Validate description
    if 'programme_description' in answers and answers['programme_description']:
        desc_result = validate_organisation_description(answers['programme_description'])
        if not desc_result['valid']:
            errors['programme_description'] = '; '.join(desc_result['errors'])

    # Validate logos
    if 'organisation_logo' in answers and answers['organisation_logo']:
        try:
            validate_organisation_logo(answers['organisation_logo'], 'organisation_logo')
        except ValidationError as e:
            errors['organisation_logo'] = str(e.message)

    if 'organisation_logo_dark' in answers and answers['organisation_logo_dark']:
        try:
            validate_organisation_logo(answers['organisation_logo_dark'], 'organisation_logo_dark')
        except ValidationError as e:
            errors['organisation_logo_dark'] = str(e.message)

    # Validate URLs
    if 'website_url' in answers and answers['website_url']:
        if not answers['website_url'].startswith(('http://', 'https://')):
            errors['website_url'] = 'URL must start with http:// or https://'

    # Validate email
    if 'primary_contact_email' in answers and answers['primary_contact_email']:
        import re
        email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_pattern, answers['primary_contact_email']):
            errors['primary_contact_email'] = 'Invalid email format'

    return {'valid': len(errors) == 0, 'errors': errors}


# ==================== SPONSOR STAFF MODULE VALIDATION ====================

def validate_sponsor_staff_submission(answers):
    """Validate sponsor staff module submission."""
    errors = {}

    required_fields = ['display_name', 'role_at_sponsor', 'booth_presence', 'areas_of_conversation', 'display_consent']

    for field in required_fields:
        if field not in answers or not answers[field]:
            errors[field] = f'{field} is required'

    # Validate display name
    if 'display_name' in answers and answers['display_name']:
        if len(answers['display_name']) < 2 or len(answers['display_name']) > 150:
            errors['display_name'] = 'Name must be 2-150 characters'

    # Validate role
    if 'role_at_sponsor' in answers and answers['role_at_sponsor']:
        if len(answers['role_at_sponsor']) < 2 or len(answers['role_at_sponsor']) > 100:
            errors['role_at_sponsor'] = 'Role must be 2-100 characters'

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

    errors = {}

    required_fields = [
        'company_name_display', 'company_logo', 'one_line_pitch',
        'programme_description', 'stage', 'sector_industry',
        'founded_year', 'website_url', 'founder_names_roles', 'display_consent'
    ]

    for field in required_fields:
        if field not in answers or not answers[field]:
            errors[field] = f'{field} is required'

    # Validate pitch
    if 'one_line_pitch' in answers and answers['one_line_pitch']:
        try:
            validate_startup_pitch(answers['one_line_pitch'])
        except ValidationError as e:
            errors['one_line_pitch'] = str(e.message)

    # Validate description
    if 'programme_description' in answers and answers['programme_description']:
        desc_result = validate_startup_description(answers['programme_description'])
        if not desc_result['valid']:
            errors['programme_description'] = '; '.join(desc_result['errors'])

    # Validate founded year
    if 'founded_year' in answers and answers['founded_year']:
        try:
            year = int(answers['founded_year'])
            if year < 2000 or year > 2026:
                errors['founded_year'] = 'Year must be between 2000 and 2026'
        except (ValueError, TypeError):
            errors['founded_year'] = 'Invalid year format'

    # Validate pitch deck
    if 'public_pitch_deck' in answers and answers['public_pitch_deck']:
        try:
            validate_pitch_deck(answers['public_pitch_deck'])
        except ValidationError as e:
            errors['public_pitch_deck'] = str(e.message)

    # Validate founder photos
    if 'founder_photos' in answers and answers['founder_photos']:
        try:
            validate_founder_photos(answers['founder_photos'])
        except ValidationError as e:
            errors['founder_photos'] = str(e.message)

    return {'valid': len(errors) == 0, 'errors': errors}


# ==================== INVESTOR MODULE VALIDATION ====================

def validate_investor_submission(answers):
    """Validate investor module submission."""
    from events.validators import validate_thesis_tagline
    from django.core.exceptions import ValidationError

    errors = {}

    required_fields = [
        'display_name', 'thesis_tagline', 'stage_focus',
        'sector_focus', 'geographic_focus', 'cheque_size_range',
        'open_to_inbound', 'display_consent'
    ]

    for field in required_fields:
        if field not in answers or not answers[field]:
            errors[field] = f'{field} is required'

    # Validate display name
    if 'display_name' in answers and answers['display_name']:
        if len(answers['display_name']) < 2 or len(answers['display_name']) > 150:
            errors['display_name'] = 'Name must be 2-150 characters'

    # Validate tagline
    if 'thesis_tagline' in answers and answers['thesis_tagline']:
        try:
            validate_thesis_tagline(answers['thesis_tagline'])
        except ValidationError as e:
            errors['thesis_tagline'] = str(e.message)

    return {'valid': len(errors) == 0, 'errors': errors}


# ==================== PROMOTIONAL PROFILE WRITEBACK ====================

def writeback_promotional_profile_module(assignment, module_type):
    """
    Generic writeback for promotional profile modules.

    Args:
        assignment: PostAcceptanceFormAssignment
        module_type: 'sponsor', 'sponsor_staff', 'startup', or 'investor'

    Returns:
        bool: Success status
    """
    try:
        submission = assignment.submission
        registration = assignment.event_registration

        # Update display_consent
        for answer in submission.answers.all():
            if answer.question_key == 'display_consent':
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
