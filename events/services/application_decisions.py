"""
Phase 10: Application decision service
Handles accept, decline, and waitlist decisions with attendee management and notifications.
Phase 11: Extended to create attendee origin metadata.
"""
from django.utils import timezone
from django.db import transaction
from events.models import (
    EventApplicationTrackApplication,
    EventRegistration,
    EventParticipant,
    EventRole,
    TrackPricingTier,
)
from users.email_utils import send_application_decision_email
from events.services.attendee_directory import create_or_update_attendee
from events.services.post_acceptance_forms import trigger_post_acceptance_forms


def accept_track_application(
    track_application,
    reviewer_user,
    accepted_tier=None,
    notes=None
):
    """
    Accept a track application with tier selection and attendee management.

    Args:
        track_application: EventApplicationTrackApplication instance
        reviewer_user: User performing the acceptance
        accepted_tier: TrackPricingTier to assign
        notes: Optional notes about the decision

    Returns:
        track_application: Updated instance

    Raises:
        ValueError: If no tier can be determined
    """
    with transaction.atomic():
        event = track_application.track.event
        application = track_application.application
        user = application.user
        track = track_application.track

        # Determine tier using priority order:
        # 1. Explicitly provided tier
        # 2. Applicant's preference
        # 3. Default tier (is_default=True, is_active=True)
        # 4. First active tier by sort_order
        if not accepted_tier:
            accepted_tier = track_application.tier_preference

        if not accepted_tier:
            # Try to find default tier
            accepted_tier = TrackPricingTier.objects.filter(
                track=track,
                is_default=True,
                is_active=True
            ).first()

        if not accepted_tier:
            # Fallback to first active tier by sort_order
            accepted_tier = TrackPricingTier.objects.filter(
                track=track,
                is_active=True
            ).order_by('sort_order').first()

        if not accepted_tier:
            raise ValueError(
                f"No pricing tier found for track '{track.label}'. "
                f"Please configure at least one active tier."
            )

        # Update track application
        track_application.status = EventApplicationTrackApplication.STATUS_ACCEPTED
        track_application.accepted_tier = accepted_tier
        track_application.accepted_at = timezone.now()
        track_application.reviewed_by = reviewer_user
        track_application.reviewed_at = timezone.now()
        track_application.save(update_fields=[
            'status', 'accepted_tier', 'accepted_at', 'reviewed_by', 'reviewed_at'
        ])

        # Create or update EventRegistration if user is authenticated
        if user:
            # Determine initial attendee status based on tier price
            if accepted_tier and accepted_tier.price and accepted_tier.price > 0:
                attendee_status = 'payment_pending'
            else:
                attendee_status = 'confirmed'

            registration, created = EventRegistration.objects.get_or_create(
                event=event,
                user=user,
                defaults={
                    'status': 'registered',
                    'attendee_status': attendee_status,
                    'admission_status': 'waiting' if event.waiting_room_enabled else 'admitted',
                }
            )

            if not created:
                registration.status = 'registered'
                # FIX 4: Do NOT set attendee_status directly - will recalculate after creating origins
                registration.save(update_fields=['status'])

            # FIX 3: Assign roles from track's role_mappings_on_acceptance
            # Set promotional_profile trigger for specific roles
            role_names = track.role_mappings_on_acceptance or []
            PROMOTIONAL_ROLE_KEYS = {"speaker", "sponsor", "sponsor_staff", "startup", "investor"}
            for role_name in role_names:
                if role_name:  # Skip empty strings
                    role, _ = EventRole.objects.get_or_create(
                        event=event,
                        key=role_name,
                        defaults={
                            'label': role_name.replace("_", " ").title(),
                            'triggers_promotional_profile': role_name in PROMOTIONAL_ROLE_KEYS
                        }
                    )
                    registration.roles.add(role)

            # Phase 11/12: Create attendee origin metadata (track, tier, mode, reviewer, etc.)
            registration, confirmed_origin = create_or_update_attendee(track_application, registration)

            # FIX 4: Recalculate registration status based on ALL origins
            # (not just the current track being accepted)
            from events.services.attendee_directory import _recalculate_registration_status
            _recalculate_registration_status(registration)

            # FIX 1: Trigger post-acceptance forms based on ORIGIN status, not registration status
            # This allows forms to trigger immediately when origin is confirmed, even if other
            # origins are still payment_pending. Form service is idempotent so safe to call multiple times.
            if confirmed_origin:
                def trigger_forms():
                    try:
                        trigger_post_acceptance_forms(registration)
                    except Exception as e:
                        import logging
                        logger = logging.getLogger(__name__)
                        logger.error(f"Failed to trigger post-acceptance forms: {e}")

                transaction.on_commit(trigger_forms)

        # Queue acceptance email asynchronously (non-blocking, respects opt_out flag)
        try:
            from events.tasks import send_application_acceptance_email_task
            send_application_acceptance_email_task.delay(track_application.id)
        except Exception as e:
            # Log but don't fail the acceptance
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to queue acceptance email task: {e}")

        return track_application


def decline_track_application(
    track_application,
    reviewer_user,
    send_email=True,
    notes=None
):
    """
    Decline a track application.

    Args:
        track_application: EventApplicationTrackApplication instance
        reviewer_user: User performing the decline
        send_email: Whether to send decline notification email
        notes: Optional notes about the decision

    Returns:
        track_application: Updated instance
    """
    with transaction.atomic():
        track_application.status = EventApplicationTrackApplication.STATUS_DECLINED
        track_application.declined_at = timezone.now()
        track_application.reviewed_by = reviewer_user
        track_application.reviewed_at = timezone.now()
        track_application.save(update_fields=[
            'status', 'declined_at', 'reviewed_by', 'reviewed_at'
        ])

        # Queue email asynchronously if enabled (non-blocking)
        if send_email:
            try:
                from events.tasks import send_application_decline_email_task
                send_application_decline_email_task.delay(track_application.id)
            except Exception as e:
                # Log but don't fail the decline
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to queue decline email task: {e}")

        return track_application


def waitlist_track_application(
    track_application,
    reviewer_user,
    send_email=True,
    notes=None
):
    """
    Waitlist a track application.

    Args:
        track_application: EventApplicationTrackApplication instance
        reviewer_user: User performing the waitlist
        send_email: Whether to send waitlist notification email
        notes: Optional notes about the decision

    Returns:
        track_application: Updated instance
    """
    with transaction.atomic():
        track_application.status = EventApplicationTrackApplication.STATUS_WAITLISTED
        track_application.waitlisted_at = timezone.now()
        track_application.reviewed_by = reviewer_user
        track_application.reviewed_at = timezone.now()
        track_application.save(update_fields=[
            'status', 'waitlisted_at', 'reviewed_by', 'reviewed_at'
        ])

        # Queue email asynchronously if enabled (non-blocking)
        if send_email:
            try:
                from events.tasks import send_application_waitlist_email_task
                send_application_waitlist_email_task.delay(track_application.id)
            except Exception as e:
                # Log but don't fail the waitlist
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Failed to queue waitlist email task: {e}")

        return track_application
