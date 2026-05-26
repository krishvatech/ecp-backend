"""
Application cancellation service.

Handles cancellation of applications and registrations consistently across all linked records:
- EventApplication
- EventApplicationTrackApplication
- EventRegistration
- EventAttendeeOrigin

Distinguishes between "cancelled" (application-initiated withdrawal) and "declined" (admin rejection).
"""
from django.utils import timezone
from django.db import transaction
from events.models import (
    EventApplication,
    EventApplicationTrackApplication,
    EventRegistration,
    EventAttendeeOrigin,
)


def cancel_application(
    event_application,
    cancellation_reason='user_withdrawal',
    admin_user=None
):
    """
    Cancel an EventApplication and all its track applications and registrations.

    This is distinct from declining - cancellation is when the applicant withdraws
    their application (or decides to not attend after being accepted).
    Decline is when admin rejects the application.

    Args:
        event_application: EventApplication instance
        cancellation_reason: 'user_withdrawal', 'registration_cancelled', 'admin_cancellation'
        admin_user: User performing the cancellation (if admin-initiated)

    Returns:
        event_application: Updated instance
    """
    with transaction.atomic():
        # Update main application
        event_application.status = 'cancelled'
        event_application.cancelled_at = timezone.now()
        event_application.save(update_fields=['status', 'cancelled_at'])

        # Update all track applications
        track_apps = EventApplicationTrackApplication.objects.filter(
            application=event_application
        ).exclude(status__in=['declined', 'cancelled'])

        for track_app in track_apps:
            track_app.status = EventApplicationTrackApplication.STATUS_CANCELLED
            track_app.cancelled_at = timezone.now()
            track_app.cancellation_reason = cancellation_reason
            track_app.save(update_fields=['status', 'cancelled_at', 'cancellation_reason'])

        # Update any related registration and its origins
        try:
            registration = EventRegistration.objects.get(
                event=event_application.event,
                user=event_application.user
            )
            _cancel_registration(registration, origin='application_cancellation')
        except EventRegistration.DoesNotExist:
            pass

    return event_application


def cancel_registration_for_application(
    event_registration,
    application=None,
    cancellation_reason='registration_cancelled'
):
    """
    Cancel a registration and update related applications.

    When a user cancels their registration after being accepted, we need to:
    1. Cancel the registration
    2. Cancel the application/track applications
    3. Update attending_count safely
    4. Mark origins as cancelled

    Args:
        event_registration: EventRegistration instance
        application: EventApplication instance (will fetch if not provided)
        cancellation_reason: Reason for cancellation

    Returns:
        dict with 'registration' and 'application' keys
    """
    with transaction.atomic():
        # Update registration
        _cancel_registration(
            event_registration,
            origin='user_cancellation'
        )

        # Update associated application
        if not application and event_registration.user:
            application = EventApplication.objects.filter(
                event=event_registration.event,
                user=event_registration.user,
                status__in=['pending', 'approved']
            ).first()

        if application:
            cancel_application(
                application,
                cancellation_reason=cancellation_reason,
                admin_user=None
            )

        return {
            'registration': event_registration,
            'application': application
        }


def _cancel_registration(registration, origin='user_cancellation'):
    """
    Internal helper to cancel a registration and update related records.

    Args:
        registration: EventRegistration instance
        origin: How the cancellation was initiated (user, application, admin)
    """
    # Update registration
    registration.status = 'cancelled'
    registration.attendee_status = 'cancelled'
    registration.save(update_fields=['status', 'attendee_status'])

    # Cancel all active origins
    registration.origins.filter(status='active').update(
        status='cancelled',
        origin_status='cancelled'
    )

    # Safely recalculate attending_count
    from events.views import _recalculate_event_attending_count
    _recalculate_event_attending_count(registration.event_id)


def allow_reapplication(event_registration, event_application=None):
    """
    Check if user can reapply after cancellation.

    Returns True if:
    - Application/registration is cancelled
    - Event is still open
    - Event registration type is 'apply'

    Args:
        event_registration: EventRegistration or None
        event_application: EventApplication or None

    Returns:
        bool: Whether user can reapply
    """
    if event_registration:
        event = event_registration.event
        return (
            event_registration.status in ['cancelled', 'deregistered'] and
            event.registration_type == 'apply' and
            event.status in ['draft', 'published']
        )

    if event_application:
        event = event_application.event
        return (
            event_application.status == 'cancelled' and
            event.registration_type == 'apply' and
            event.status in ['draft', 'published']
        )

    return False
