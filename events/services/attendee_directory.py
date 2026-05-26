"""
Phase 11/12: Attendee Directory Service
Handles creation/update of attendee records and payment status management.
"""
import logging
from django.utils import timezone
from django.db import transaction
from events.models import EventAttendeeOrigin

logger = logging.getLogger(__name__)

# Avoid circular import by importing at function level when needed
def _get_trigger_post_acceptance_forms():
    """Lazy import to avoid circular dependencies."""
    try:
        from events.services.post_acceptance_forms import trigger_post_acceptance_forms
        return trigger_post_acceptance_forms
    except ImportError:
        return None


def create_or_update_attendee(track_application, registration):
    """
    Create or update attendee origin metadata when an application is accepted.

    For each role in the track's role_mappings_on_acceptance, creates an EventAttendeeOrigin record
    storing the acceptance metadata (track, mode, tier, reviewer, nominator).

    Uniqueness is scoped to (registration, role, track), allowing the same user to have
    the same role from multiple different tracks.

    Args:
        track_application: EventApplicationTrackApplication instance (accepted)
        registration: EventRegistration instance (already created by accept_track_application)

    Returns:
        tuple: (registration, confirmed_origin)
        - registration: Updated EventRegistration with origins populated
        - confirmed_origin: First confirmed origin created (if any), else None

    Side Effects:
        - Creates EventAttendeeOrigin records for each role in track.role_mappings_on_acceptance
        - Updates existing origins if attendee already has those roles from the same track
    """
    with transaction.atomic():
        # Get the track and application for origin metadata
        track = track_application.track
        application = track_application.application

        # FIX 1: Determine origin_status based on tier price
        # If tier has a price > 0 → payment_pending, else → confirmed
        origin_status = 'confirmed'
        if track_application.accepted_tier and track_application.accepted_tier.price and track_application.accepted_tier.price > 0:
            origin_status = 'payment_pending'

        confirmed_origin = None  # Track first confirmed origin for form triggering

        # Iterate through each role defined for this track
        # role_mappings_on_acceptance is a list of role keys like ["speaker", "sponsor"]
        role_names = track.role_mappings_on_acceptance or []
        PROMOTIONAL_ROLE_KEYS = {"speaker", "sponsor", "sponsor_staff", "startup", "investor"}
        for role_name in role_names:
            if not role_name:  # Skip empty strings
                continue

            # FIX 3: Get or create the EventRole with promotional_profile trigger
            from events.models import EventRole
            role, _ = EventRole.objects.get_or_create(
                event=track.event,
                key=role_name,
                defaults={
                    'label': role_name.replace("_", " ").title(),
                    'triggers_promotional_profile': role_name in PROMOTIONAL_ROLE_KEYS
                }
            )

            # Get nominator info if this is a third-party nomination
            nominator_name = ''
            nominator_email = ''
            if application.submission_mode == 'third_party_nomination':
                nominator_name = getattr(application, 'nominator_name', '')
                nominator_email = getattr(application, 'nominator_email', '')

            # Create or update the EventAttendeeOrigin
            # Uniqueness constraint: (registration, role, track)
            # Allows same user/role from multiple different tracks
            origin, created = EventAttendeeOrigin.objects.update_or_create(
                registration=registration,
                role=role,
                track=track,
                defaults={
                    'submission_mode': application.submission_mode,
                    'accepted_by': track_application.reviewed_by,
                    'accepted_at': track_application.accepted_at,
                    'accepted_tier': track_application.accepted_tier,
                    'nominator_name': nominator_name,
                    'nominator_email': nominator_email,
                    'status': 'active',
                    'origin_status': origin_status,  # FIX 1: Set per-track payment status
                }
            )

            # Track first confirmed origin for FIX 1: form triggering
            if not confirmed_origin and origin.origin_status == 'confirmed':
                confirmed_origin = origin

        return registration, confirmed_origin


def mark_origin_paid(origin, marked_by_user, payment_reference=''):
    """
    FIX 2: Manually mark a payment_pending origin as confirmed.

    Updates the origin's payment status and recalculates the registration's
    attendee_status based on all origins.

    Args:
        origin: EventAttendeeOrigin instance (must have origin_status='payment_pending')
        marked_by_user: User performing the action (admin)
        payment_reference: Optional payment reference (invoice, check number, etc.)

    Returns:
        origin: Updated EventAttendeeOrigin with origin_status='confirmed'

    Raises:
        ValueError: If origin.origin_status is not 'payment_pending'
    """
    if origin.origin_status != 'payment_pending':
        raise ValueError(
            f"Cannot mark origin as paid: origin status is '{origin.origin_status}', "
            f"not 'payment_pending'"
        )

    with transaction.atomic():
        # Update origin status
        origin.origin_status = 'confirmed'
        origin.marked_paid_by = marked_by_user
        origin.marked_paid_at = timezone.now()
        if payment_reference:
            origin.payment_reference = payment_reference
        origin.save(update_fields=[
            'origin_status',
            'marked_paid_by',
            'marked_paid_at',
            'payment_reference'
        ])

        # Recalculate registration.attendee_status based on all origins
        registration = origin.registration
        _recalculate_registration_status(registration)

        # Send payment confirmed email
        def send_email_on_commit():
            from events.services.communication import send_payment_confirmed_email
            try:
                send_payment_confirmed_email(origin)
            except Exception as e:
                logger.error(
                    f"Error sending payment confirmed email for origin {origin.id}: {e}",
                    exc_info=True
                )

        # Trigger post-acceptance forms if registration is now confirmed
        if registration.attendee_status == 'confirmed':
            def trigger_forms_on_commit():
                trigger_func = _get_trigger_post_acceptance_forms()
                if trigger_func:
                    try:
                        trigger_func(registration)
                    except Exception as e:
                        logger.error(
                            f"Error triggering post-acceptance forms for registration {registration.id}: {e}",
                            exc_info=True
                        )

            transaction.on_commit(trigger_forms_on_commit)

        # Send email on commit
        transaction.on_commit(send_email_on_commit)

    return origin


def _recalculate_registration_status(registration):
    """
    FIX 1: Recalculate registration.attendee_status based on all origins.

    Logic:
    - If ANY origin is payment_pending → registration = payment_pending
    - Else if ALL are confirmed → registration = confirmed
    - Else fallback to cancelled
    """
    origins = registration.origins.filter(status='active').all()
    if not origins.exists():
        # No active origins, mark as cancelled
        registration.attendee_status = 'cancelled'
    elif origins.filter(origin_status='payment_pending').exists():
        # Any pending payment
        registration.attendee_status = 'payment_pending'
    elif origins.filter(origin_status='confirmed').exists():
        # All confirmed
        registration.attendee_status = 'confirmed'
    else:
        # Fallback
        registration.attendee_status = 'cancelled'

    registration.save(update_fields=['attendee_status'])
    logger.info(
        f"Recalculated status for registration {registration.id}: {registration.attendee_status}"
    )


def mark_paid(registration, marked_by_user, payment_reference=''):
    """
    Manually mark a payment_pending registration as confirmed.

    Updates the registration status and triggers post-acceptance forms
    if the status transitions to confirmed.

    Args:
        registration: EventRegistration instance (must have attendee_status='payment_pending')
        marked_by_user: User performing the action (admin)
        payment_reference: Optional payment reference (invoice, check number, etc.)

    Returns:
        registration: Updated EventRegistration with attendee_status='confirmed'

    Raises:
        ValueError: If registration.attendee_status is not 'payment_pending'
    """
    if registration.attendee_status != 'payment_pending':
        raise ValueError(
            f"Cannot mark as paid: attendee status is '{registration.attendee_status}', "
            f"not 'payment_pending'"
        )

    with transaction.atomic():
        # Update registration status
        registration.attendee_status = 'confirmed'
        registration.marked_paid_by = marked_by_user
        registration.marked_paid_at = timezone.now()
        if payment_reference:
            registration.payment_reference = payment_reference
        registration.save(update_fields=[
            'attendee_status',
            'marked_paid_by',
            'marked_paid_at',
            'payment_reference'
        ])

        # Schedule post-acceptance forms trigger after commit
        # This ensures the registration is persisted before triggering forms
        def trigger_forms_on_commit():
            trigger_func = _get_trigger_post_acceptance_forms()
            if trigger_func:
                try:
                    trigger_func(registration)
                except Exception as e:
                    logger.error(
                        f"Error triggering post-acceptance forms for registration {registration.id}: {e}",
                        exc_info=True
                    )

        transaction.on_commit(trigger_forms_on_commit)

    return registration
