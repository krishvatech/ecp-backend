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
    EventAttendeeOrigin,
    EventParticipant,
    EventRole,
    TrackPricingTier,
)
from users.email_utils import send_application_decision_email
from events.services.attendee_directory import (
    create_or_update_attendee,
    _recalculate_registration_status,
)
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

            # Increment attending_count only when a new registration is created
            if created:
                from django.db.models import F
                from events.models import Event
                Event.objects.filter(pk=event.pk).update(
                    attending_count=F('attending_count') + 1
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


def _rollback_acceptance_side_effects(track_application):
    """
    Reverse the registration/role/attendee-origin side effects created by
    accept_track_application(), without deleting any historical data.

    Cancels the EventAttendeeOrigin record(s) tied to this track (preserving
    them for audit history), drops the associated EventRole from the
    registration only if no other active origin still needs it, and
    recalculates the registration's attendee_status from its remaining
    active origins.

    If no active origins remain, the registration itself is cancelled through
    the shared cancellation helper so the applicant is no longer counted as
    attending and can apply again.
    """
    application = track_application.application
    user = application.user
    if not user:
        return

    registration = EventRegistration.objects.filter(
        event=track_application.track.event, user=user
    ).first()
    if not registration:
        return

    origins = EventAttendeeOrigin.objects.filter(
        registration=registration,
        track=track_application.track,
        status='active',
    )
    role_ids = list(origins.values_list('role_id', flat=True))
    if not origins.exists():
        return

    origins.update(status='cancelled', origin_status='cancelled')

    for role_id in role_ids:
        still_needed = EventAttendeeOrigin.objects.filter(
            registration=registration,
            role_id=role_id,
            status='active',
        ).exists()
        if not still_needed:
            registration.roles.remove(role_id)

    if registration.origins.filter(status='active').exists():
        # Other accepted tracks still hold this registration open
        _recalculate_registration_status(registration)
    else:
        from events.services.application_cancellation import _cancel_registration
        _cancel_registration(registration, origin='application_decision')


def decline_track_application(
    track_application,
    reviewer_user,
    send_email=True,
    notes=None
):
    """
    Decline a track application. Supports declining from pending as well as
    from an already-accepted state, in which case acceptance side effects
    (registration roles, attendee origins) are rolled back safely without
    deleting historical records.

    Args:
        track_application: EventApplicationTrackApplication instance
        reviewer_user: User performing the decline
        send_email: Whether to send decline notification email
        notes: Optional notes about the decision

    Returns:
        track_application: Updated instance
    """
    with transaction.atomic():
        was_accepted = track_application.status == EventApplicationTrackApplication.STATUS_ACCEPTED

        if was_accepted:
            _rollback_acceptance_side_effects(track_application)

        track_application.status = EventApplicationTrackApplication.STATUS_DECLINED
        track_application.declined_at = timezone.now()
        track_application.reviewed_by = reviewer_user
        track_application.reviewed_at = timezone.now()
        track_application.save(update_fields=[
            'status', 'declined_at', 'reviewed_by', 'reviewed_at'
        ])

        # Update parent application status if ALL track applications are now declined
        parent_app = track_application.application
        all_track_apps = parent_app.track_applications.all()
        if all_track_apps.exists() and all(
            ta.status == EventApplicationTrackApplication.STATUS_DECLINED
            for ta in all_track_apps
        ):
            parent_app.status = 'declined'
            parent_app.save(update_fields=['status'])

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


def delete_track_application(
    track_application,
    actor_user,
    reason=""
):
    """
    Soft-delete a track application (any status, including accepted).

    If the application was accepted, rolls back the same acceptance side
    effects as decline_track_application() (cancels attendee origins, drops
    now-unneeded registration roles, recalculates attendee_status) so the
    applicant is no longer treated as "already registered" for the event.
    No historical records are hard-deleted.

    Also mirrors decline_track_application()'s parent-status cascade: if the
    parent EventApplication has no remaining (non-deleted) track applications
    after this deletion, its status is set to 'cancelled' so eligibility
    checks (event list badge, reapply gating) stop treating the removed
    track application's stale parent status as still pending/active.

    Args:
        track_application: EventApplicationTrackApplication instance
        actor_user: User performing the deletion
        reason: Optional deletion reason

    Returns:
        track_application: Updated instance
    """
    with transaction.atomic():
        if track_application.status == EventApplicationTrackApplication.STATUS_ACCEPTED:
            _rollback_acceptance_side_effects(track_application)

        track_application.soft_delete(user=actor_user, reason=reason)

        # Update parent application status if it has no remaining active track applications
        parent_app = track_application.application
        if not parent_app.track_applications.exists():
            parent_app.status = 'cancelled'
            parent_app.cancelled_at = timezone.now()
            parent_app.save(update_fields=['status', 'cancelled_at'])

        return track_application
