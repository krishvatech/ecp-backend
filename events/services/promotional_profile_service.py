"""
Service module for Promotional Profile form management.

Handles:
- Determining which attendees should get promotional profiles
- Computing active modules based on attendee roles
- Creating promotional profiles
- Preventing duplicates
"""
import logging
from django.utils import timezone
from events.models import (
    EventParticipant,
    PostAcceptanceFormAssignment,
    PostAcceptanceFormTemplate,
    PostAcceptanceFormSubmission,
    PostAcceptanceFormAnswer,
    EventRegistration,
)
from events.promotional_profile_schemas import PROMOTIONAL_PROFILE_SCHEMA

logger = logging.getLogger('events')


def get_promotional_modules_for_attendee(event_registration):
    """
    Get list of promotional profile modules that should be active for an attendee.

    Args:
        event_registration (EventRegistration): The attendee's event registration

    Returns:
        list: List of module names (e.g., ['speaker', 'sponsor'])
        empty list if attendee doesn't have promotional profile-triggering roles
    """
    if not event_registration or not event_registration.event:
        return []

    # Get all roles for this attendee at this event
    roles = EventParticipant.objects.filter(
        event=event_registration.event,
        user=event_registration.user
    ).values_list('role', flat=True)

    # Map roles to promotional modules
    modules = []
    for role in roles:
        if role in EventParticipant.TRIGGERS_PROMOTIONAL_PROFILE_ROLES:
            module = EventParticipant.ROLE_MODULE_MAP.get(role)
            if module and module not in modules:
                modules.append(module)

    return sorted(modules)  # Return in consistent order


def should_create_promotional_profile(event_registration):
    """
    Determine if attendee should get a promotional profile.

    Returns:
        bool: True if attendee has any promotional profile-triggering roles
    """
    modules = get_promotional_modules_for_attendee(event_registration)
    return len(modules) > 0


def get_or_create_promotional_profile(event_registration):
    """
    Get existing promotional profile or create new one.

    Ensures exactly one Promotional Profile per attendee per event.
    If multiple roles exist, all modules are added to the same profile.

    Args:
        event_registration (EventRegistration): The attendee's registration

    Returns:
        tuple: (assignment, created) where:
            - assignment is PostAcceptanceFormAssignment instance
            - created is boolean indicating if it was newly created
    """
    # Check if promotional profile already exists
    existing = PostAcceptanceFormAssignment.objects.filter(
        event_registration=event_registration,
        form_type='promotional_profile'
    ).first()

    if existing:
        # Repair broken template if needed
        if existing.form_template:
            template = existing.form_template
            if not template.question_schema or not template.question_schema.get("sections"):
                template.question_schema = PROMOTIONAL_PROFILE_SCHEMA
                template.is_enabled = True
                template.deadline_days = 14
                template.save(update_fields=['question_schema', 'is_enabled', 'deadline_days'])
                logger.info(f"Repaired broken template for existing assignment {existing.id}")

        # Ensure modules are set
        if not existing.active_modules:
            modules = get_promotional_modules_for_attendee(event_registration)
            if modules:
                existing.active_modules = modules
                existing.module_completion_status = {module: False for module in modules}
                existing.save(update_fields=['active_modules', 'module_completion_status'])
                logger.info(f"Updated modules for existing assignment {existing.id}: {modules}")

        return existing, False

    # Get modules for this attendee
    modules = get_promotional_modules_for_attendee(event_registration)

    if not modules:
        return None, False

    # Get or create form template with full schema
    form_template, created = PostAcceptanceFormTemplate.objects.get_or_create(
        event=event_registration.event,
        form_type='promotional_profile',
        defaults={
            'title': 'Promotional Profile',
            'description': 'Share your professional profile for public visibility',
            'question_schema': PROMOTIONAL_PROFILE_SCHEMA,
            'is_enabled': True,
            'deadline_days': 14
        }
    )

    # Repair existing broken templates (missing schema)
    if not created and (not form_template.question_schema or
                        not form_template.question_schema.get("sections")):
        form_template.question_schema = PROMOTIONAL_PROFILE_SCHEMA
        form_template.is_enabled = True
        form_template.deadline_days = 14
        form_template.save(update_fields=['question_schema', 'is_enabled', 'deadline_days'])
        logger.info(f"Repaired promotional profile template for event {event_registration.event.id}")

    # Create assignment with active modules
    assignment = PostAcceptanceFormAssignment.objects.create(
        event=event_registration.event,
        form_template=form_template,
        event_registration=event_registration,
        form_type='promotional_profile',
        active_modules=modules,
        module_completion_status={module: False for module in modules},
        deadline=event_registration.event.end_time
    )

    # Send assignment notification email
    try:
        from events.services.post_acceptance_forms import send_form_assignment_email
        send_form_assignment_email(assignment)
    except Exception as e:
        logger.error(
            f"Failed to send promotional profile email for {event_registration.user.username}: {str(e)}",
            exc_info=True
        )
        # Don't fail assignment creation if email fails

    logger.info(
        f"Created promotional profile for {event_registration.user.username} "
        f"at {event_registration.event.title} with modules: {modules}"
    )

    return assignment, True


def mark_module_completed(assignment, module_name):
    """
    Mark a specific module as completed in promotional profile.

    Args:
        assignment (PostAcceptanceFormAssignment): The promotional profile assignment
        module_name (str): Name of module to mark complete (e.g., 'speaker')

    Returns:
        bool: True if successful, False if module not in active_modules
    """
    if not assignment or not assignment.active_modules:
        return False

    if module_name not in assignment.active_modules:
        logger.warning(
            f"Module {module_name} not in active modules for assignment {assignment.id}"
        )
        return False

    # Update module completion status
    if not assignment.module_completion_status:
        assignment.module_completion_status = {}

    assignment.module_completion_status[module_name] = True
    assignment.save(update_fields=['module_completion_status'])

    # Check if all modules completed
    all_completed = all(
        assignment.module_completion_status.get(m, False)
        for m in assignment.active_modules
    )

    if all_completed:
        assignment.status = PostAcceptanceFormAssignment.STATUS_COMPLETED
        assignment.completed_at = timezone.now()
        assignment.save(update_fields=['status', 'completed_at'])

        # Update attendee record
        assignment.event_registration.promotional_profile_completed_at = timezone.now()
        assignment.event_registration.save(update_fields=['promotional_profile_completed_at'])

        logger.info(
            f"All modules completed for promotional profile {assignment.id}"
        )

    return True


def get_promotional_profile_completion_summary(assignment):
    """
    Get completion summary for a promotional profile assignment.

    Returns:
        dict: {
            'modules': [list of module names],
            'completed_modules': [list of completed module names],
            'completion_percentage': int (0-100),
            'fully_completed': bool
        }
    """
    if not assignment or not assignment.active_modules:
        return {
            'modules': [],
            'completed_modules': [],
            'completion_percentage': 0,
            'fully_completed': False
        }

    status = assignment.module_completion_status or {}
    completed = [m for m in assignment.active_modules if status.get(m, False)]
    total = len(assignment.active_modules)

    return {
        'modules': assignment.active_modules,
        'completed_modules': completed,
        'completion_percentage': int((len(completed) / total * 100)) if total > 0 else 0,
        'fully_completed': len(completed) == total
    }


def trigger_promotional_profiles_for_event(event):
    """
    Trigger promotional profiles for all newly confirmed attendees.

    Called after event is set up or when attendee status changes to confirmed.

    Args:
        event (Event): The event to process

    Returns:
        dict: {
            'created': count of newly created profiles,
            'already_exists': count of existing profiles,
            'skipped': count of attendees without promotional profile roles,
            'errors': list of error messages
        }
    """
    from events.models import EventRegistration

    stats = {
        'created': 0,
        'already_exists': 0,
        'skipped': 0,
        'errors': []
    }

    # Get all confirmed registrations
    confirmed_registrations = EventRegistration.objects.filter(
        event=event,
        attendee_status='confirmed'
    ).select_related('user')

    for registration in confirmed_registrations:
        try:
            if not should_create_promotional_profile(registration):
                stats['skipped'] += 1
                continue

            assignment, created = get_or_create_promotional_profile(registration)

            if created:
                stats['created'] += 1
            else:
                stats['already_exists'] += 1

        except Exception as e:
            error_msg = f"Error creating profile for {registration.user.username}: {str(e)}"
            logger.error(error_msg)
            stats['errors'].append(error_msg)

    logger.info(f"Promotional profile trigger summary for {event.title}: {stats}")
    return stats


def consolidate_promotional_profiles_for_registration(registration):
    """
    Consolidate multiple role changes into a single promotional profile.

    When an attendee gains or loses roles, update their promotional profile
    to reflect the current set of active modules.

    Args:
        registration (EventRegistration): The attendee's registration

    Returns:
        PostAcceptanceFormAssignment: Updated assignment or None
    """
    modules = get_promotional_modules_for_attendee(registration)

    assignment = PostAcceptanceFormAssignment.objects.filter(
        event_registration=registration,
        form_type='promotional_profile'
    ).first()

    if not modules and assignment:
        # User lost all promotional profile roles - delete profile
        assignment.delete()
        logger.info(
            f"Deleted promotional profile for {registration.user.username} "
            f"(no more triggering roles)"
        )
        return None

    if not modules:
        # User never had promotional profile
        return None

    if not assignment:
        # Create new profile
        assignment, _ = get_or_create_promotional_profile(registration)
        return assignment

    # Update existing profile with new modules
    new_modules = set(modules)
    old_modules = set(assignment.active_modules or [])

    if new_modules == old_modules:
        # No change needed
        return assignment

    # Add new modules, preserve completion status of existing ones
    assignment.active_modules = modules
    new_completion_status = {
        module: assignment.module_completion_status.get(module, False)
        for module in modules
    }
    assignment.module_completion_status = new_completion_status
    assignment.save()

    logger.info(
        f"Updated promotional profile for {registration.user.username}: "
        f"{old_modules} → {new_modules}"
    )

    return assignment
