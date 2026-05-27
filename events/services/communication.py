"""
Phase 12: Communication templates service
Handles configurable email templates for application outcomes with support for
track, submission mode, outcome, and tier-specific customization.
"""
import logging
from django.utils import timezone
from users.email_utils import send_template_email, format_event_time_for_email, get_support_email

logger = logging.getLogger(__name__)


def build_email_context(track_application, outcome=None, tier=None):
    """
    Build context dict with all template variables for application decision emails.

    Args:
        track_application: EventApplicationTrackApplication instance
        outcome: 'accepted' | 'declined' | 'waitlisted'
        tier: Optional TrackPricingTier instance

    Returns:
        dict: Template context with all variables
    """
    application = track_application.application
    user = application.user
    event = track_application.track.event

    # Get applicant name (from user or application fields)
    applicant_first_name = user.first_name if user else application.first_name
    applicant_last_name = user.last_name if user else application.last_name
    applicant_email = user.email if user else application.email

    # Get tier info (from argument or track_application)
    if not tier:
        tier = track_application.accepted_tier

    tier_label = tier.label if tier else ''
    tier_price = float(tier.price) if tier and tier.price else 0.0
    tier_cost_type = 'paid' if tier_price > 0 else 'free'

    # Event time formatting
    event_times = format_event_time_for_email(event)

    # Build context
    context = {
        # Applicant info
        'applicant_first_name': applicant_first_name,
        'applicant_last_name': applicant_last_name,
        'applicant_name': f"{applicant_first_name} {applicant_last_name}".strip(),
        'applicant_email': applicant_email,

        # Event info
        'event_name': event.title,
        'event_description': event.description or '',
        'event_location': event.location or '',
        'event_timezone': event.timezone,
        'event_start_str': event_times.get('event_start_str', ''),
        'event_end_str': event_times.get('event_end_str', ''),
        'event_date_str': event_times.get('event_date_str', ''),
        'event_date_range_str': event_times.get('event_date_range_str', ''),

        # Track info
        'track_label': track_application.track.label,
        'track_description': getattr(track_application.track, 'short_description', '') or '',
        'track_id': track_application.track.id,

        # FIX 13: Use track_application submission_mode, not parent application's
        'submission_mode': track_application.submission_mode,
        'submission_mode_display': track_application.get_submission_mode_display() if hasattr(track_application, 'get_submission_mode_display') else track_application.submission_mode,

        # Tier info
        'tier_label': tier_label,
        'tier_price': tier_price,
        'tier_cost_type': tier_cost_type,
        'tier_id': tier.id if tier else None,

        # Outcome
        'outcome': outcome or '',

        # Nominator info (for third-party nominations)
        'nominator_name': application.nominator_name or '',
        'nominator_email': application.nominator_email or '',
        'nominee_name': application.nominee_name or '',

        # Custom message from reviewer
        'custom_message': application.rejection_message or getattr(track_application, 'custom_message', '') or '',

        # Links and placeholders
        'completion_link': '',  # Set by caller if third-party nominee
        'payment_link_placeholder': '{{payment_link}}',  # Placeholder for payment system
        'support_email': get_support_email(),
        'app_name': 'Community Platform',
    }

    return context


def send_application_decision_email(track_application, outcome, custom_message=None):
    """
    Send decision email to applicant using template hierarchy.
    For accepted applications with paid tiers, sends payment_pending email instead.
    Respects opt_out_automated_communication flag.

    Args:
        track_application: EventApplicationTrackApplication instance
        outcome: 'accepted' | 'declined' | 'waitlisted'
        custom_message: Optional override for rejection_message

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    application = track_application.application
    event = track_application.track.event
    user = application.user

    # Check opt-out flag
    if getattr(application, 'opt_out_automated_communication', False):
        logger.info(f"Skipping decision email for {application.email} - opted out")
        return False

    # Determine recipient
    recipient_email = user.email if user else application.email
    if not recipient_email:
        logger.warning(f"No email found for track application {track_application.id}")
        return False

    # Check if accepted with paid tier (payment pending scenario)
    is_payment_pending = (
        outcome in ['accept', 'accepted']
        and track_application.accepted_tier
        and track_application.accepted_tier.price
        and track_application.accepted_tier.price > 0
    )

    # Map outcome to template key
    if is_payment_pending:
        template_key = 'application_accepted_payment_pending'
    else:
        template_key_map = {
            'accept': 'application_accepted_applicant',
            'accepted': 'application_accepted_applicant',
            'decline': 'application_declined_applicant',
            'declined': 'application_declined_applicant',
            'waitlist': 'application_waitlisted_applicant',
            'waitlisted': 'application_waitlisted_applicant',
        }
        template_key = template_key_map.get(outcome)

    if not template_key:
        logger.error(f"Unknown outcome type: {outcome}")
        return False

    # Build context
    context = build_email_context(track_application, outcome=outcome)

    # Add payment tier information for payment_pending emails
    if is_payment_pending:
        context.update({
            'accepted_tier_label': track_application.accepted_tier.label,
            'amount_due': str(track_application.accepted_tier.price),
            'currency': track_application.accepted_tier.currency or 'USD',
            'payment_message': 'Your registration is pending payment. Please complete payment to confirm your spot.',
        })

    # Store custom message if provided
    if custom_message:
        context['custom_message'] = custom_message

    # Handle third-party nominee with completion link
    if application.submission_mode == 'third_party_nomination':
        # TODO: Generate or fetch completion link for nominee
        context['completion_link'] = ''  # Will be populated by future integration

    # Send email via template hierarchy
    try:
        result = send_template_email(
            template_key=template_key,
            to_email=recipient_email,
            context=context,
            subject_override=(
                f"Application approved - payment pending for {event.title}"
                if is_payment_pending else None
            ),
            event=event,
            fail_silently=False
        )
        logger.info(f"Sent {outcome} email to {recipient_email} for track app {track_application.id}")
        return result
    except Exception as e:
        logger.error(f"Failed to send {outcome} email to {recipient_email}: {e}")
        return False


def send_payment_confirmed_email(origin):
    """
    Send confirmation email after admin marks origin as paid.

    Args:
        origin: EventAttendeeOrigin instance with origin_status='confirmed'

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    registration = origin.registration
    user = registration.user
    event = registration.event

    if not user or not user.email:
        logger.warning(f"No email found for registration {registration.id}")
        return False

    # Build context
    context = {
        'app_name': 'IMAA Connect',
        'event_name': event.title,
        'track_label': origin.track.label if origin.track else 'Event',
        'user_first_name': user.first_name or user.username,
        'confirmation_message': 'Your registration is confirmed! You are all set for the event.',
        'support_email': get_support_email(),
    }

    # Add tier information if available
    if origin.accepted_tier:
        context.update({
            'tier_label': origin.accepted_tier.label,
            'amount_paid': str(origin.accepted_tier.price),
            'currency': origin.accepted_tier.currency or 'USD',
        })

    try:
        result = send_template_email(
            template_key='payment_confirmed_applicant',
            to_email=user.email,
            context=context,
            subject_override=f"Payment confirmed - you are registered for {event.title}",
            event=event,
            fail_silently=False
        )
        logger.info(f"Sent payment confirmed email to {user.email} for registration {registration.id}")
        return result
    except Exception as e:
        logger.error(f"Failed to send payment confirmed email to {user.email}: {e}")
        return False


def send_nominator_acknowledgement_email(track_application, nominator_name=None, nominator_email=None):
    """
    Send acknowledgement email to nominator when third-party nomination is submitted.

    Args:
        track_application: EventApplicationTrackApplication instance
        nominator_name: Override for nominator name
        nominator_email: Override for nominator email

    Returns:
        bool: True if email sent successfully
    """
    application = track_application.application
    event = track_application.track.event

    # Get nominator details
    nom_email = nominator_email or application.nominator_email
    nom_name = nominator_name or application.nominator_name

    if not nom_email:
        logger.warning(f"No nominator email for track application {track_application.id}")
        return False

    # Build context
    event_times = format_event_time_for_email(event)
    context = {
        'nominator_first_name': nom_name.split()[0] if nom_name else '',
        'nominator_name': nom_name,
        'nominator_email': nom_email,
        'nominee_name': application.nominee_name or '',
        'event_name': event.title,
        'event_date_str': event_times.get('event_date_str', ''),
        'track_label': track_application.track.label,
        'support_email': get_support_email(),
        'app_name': 'Community Platform',
    }

    # Send email
    try:
        result = send_template_email(
            template_key='application_acknowledgement_nominator',
            to_email=nom_email,
            context=context,
            event=event,
            fail_silently=False
        )
        logger.info(f"Sent nominator acknowledgement to {nom_email}")
        return result
    except Exception as e:
        logger.error(f"Failed to send nominator acknowledgement to {nom_email}: {e}")
        return False


def send_nominator_outcome_email(track_application, outcome, nominator_name=None, nominator_email=None):
    """
    Send outcome notification to nominator (accepted/declined).

    Args:
        track_application: EventApplicationTrackApplication instance
        outcome: 'accepted' | 'declined'
        nominator_name: Override for nominator name
        nominator_email: Override for nominator email

    Returns:
        bool: True if email sent successfully
    """
    application = track_application.application
    event = track_application.track.event

    # Get nominator details
    nom_email = nominator_email or application.nominator_email
    nom_name = nominator_name or application.nominator_name

    if not nom_email:
        logger.warning(f"No nominator email for track application {track_application.id}")
        return False

    # Map outcome to template key
    if outcome in ['accept', 'accepted']:
        template_key = 'application_accepted_nominator'
    elif outcome in ['decline', 'declined']:
        template_key = 'application_declined_nominator'
    else:
        logger.error(f"Unknown outcome type for nominator: {outcome}")
        return False

    # Get tier for accepted notifications
    tier = None
    if outcome in ['accept', 'accepted']:
        tier = track_application.accepted_tier

    # Build context
    event_times = format_event_time_for_email(event)
    context = {
        'nominator_first_name': nom_name.split()[0] if nom_name else '',
        'nominator_name': nom_name,
        'nominator_email': nom_email,
        'nominee_name': application.nominee_name or '',
        'event_name': event.title,
        'event_date_str': event_times.get('event_date_str', ''),
        'track_label': track_application.track.label,
        'tier_label': tier.label if tier else '',
        'tier_price': float(tier.price) if tier and tier.price else 0.0,
        'custom_message': application.rejection_message or '',
        'support_email': get_support_email(),
        'app_name': 'Community Platform',
    }

    # Send email
    try:
        result = send_template_email(
            template_key=template_key,
            to_email=nom_email,
            context=context,
            event=event,
            fail_silently=False
        )
        logger.info(f"Sent nominator {outcome} notification to {nom_email}")
        return result
    except Exception as e:
        logger.error(f"Failed to send nominator {outcome} notification to {nom_email}: {e}")
        return False


def send_reminder_to_complete_email(track_application):
    """
    Send reminder email to incomplete registrations (payment-pending tiers).

    Args:
        track_application: EventApplicationTrackApplication instance

    Returns:
        bool: True if email sent successfully
    """
    application = track_application.application
    event = track_application.track.event
    user = application.user

    # Check opt-out flag
    if getattr(application, 'opt_out_automated_communication', False):
        logger.info(f"Skipping reminder email for {application.email} - opted out")
        return False

    # Only send reminder for paid tiers
    tier = track_application.accepted_tier
    if not tier or not tier.price or tier.price == 0:
        logger.info(f"Skipping reminder - free tier for track app {track_application.id}")
        return False

    # Determine recipient
    recipient_email = user.email if user else application.email
    if not recipient_email:
        logger.warning(f"No email found for track application {track_application.id}")
        return False

    # Build context
    context = build_email_context(track_application, outcome='reminder', tier=tier)

    # Send email
    try:
        result = send_template_email(
            template_key='application_reminder_to_complete',
            to_email=recipient_email,
            context=context,
            event=event,
            fail_silently=False
        )
        logger.info(f"Sent reminder email to {recipient_email}")
        return result
    except Exception as e:
        logger.error(f"Failed to send reminder email to {recipient_email}: {e}")
        return False
