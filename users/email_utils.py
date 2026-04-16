"""
Email utilities for user account management.
Centralizes email sending logic with consistent error handling.
"""
import logging
import boto3
import secrets
from django.conf import settings
from django.core.mail import send_mail
from django.template import Template as DjangoTemplate, Context
from django.template.loader import render_to_string
from django.utils.crypto import get_random_string
from django.utils import timezone
from datetime import timedelta
from botocore.exceptions import ClientError
from .cognito_groups import add_user_to_speaker_group

logger = logging.getLogger(__name__)


def generate_magic_login_token(user, event=None, expires_in_hours=24):
    """
    Generate a magic login token for guest application approval.

    Args:
        user: User instance to create token for
        event: Optional Event instance for redirect context
        expires_in_hours: Token expiration time in hours (default 24)

    Returns:
        str: The generated token
    """
    from .models import MagicLoginToken

    # Generate secure random token
    token = secrets.token_urlsafe(48)
    expires_at = timezone.now() + timedelta(hours=expires_in_hours)

    # Create and save token
    magic_token = MagicLoginToken.objects.create(
        user=user,
        event=event,
        token=token,
        expires_at=expires_at
    )

    logger.info(f"Generated magic token for user {user.id} ({user.email}), expires in {expires_in_hours} hours")
    return token


def send_template_email(template_key, to_email, context, subject_override=None, fail_silently=False):
    """
    Central email sending helper with DB-first and file fallback logic.

    Attempts to load email template from DB (EmailTemplate model).
    If found and is_active=True: renders html_body/text_body using Django Template engine.
    If not found or is_active=False: falls back to file-based templates (emails/<key>.html/.txt).

    All template fields support full Django template syntax:
    - Variables: {{ variable }}
    - Tags: {% if %}, {% for %}, etc.
    - Filters: |date:"F j, Y", |truncatewords:30, etc.

    Args:
        template_key: One of the 17 EmailTemplate.TEMPLATE_KEY_CHOICES values
        to_email: Recipient email address
        context: Dict of template variables
        subject_override: If provided, overrides the DB/default subject
        fail_silently: Passed to send_mail (False blocks errors, True logs silently)

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    db_template = None
    try:
        from cms.models import EmailTemplate
        db_template = EmailTemplate.objects.get(template_key=template_key, is_active=True)
    except Exception:
        # DoesNotExist, ImportError, or DB error — fallback to files
        pass

    # --- Step 1: Render subject, html_body, text_body ---
    try:
        if db_template:
            # Render DB-stored template strings through Django template engine
            ctx = Context(context)
            subject = subject_override or DjangoTemplate(db_template.subject).render(ctx)
            html_body = DjangoTemplate(db_template.html_body).render(ctx)
            text_body = DjangoTemplate(db_template.text_body).render(ctx)
        else:
            # Fallback to file templates
            subject = subject_override or f"[{template_key}]"
            html_path = f"emails/{template_key}.html"
            txt_path = f"emails/{template_key}.txt"
            try:
                html_body = render_to_string(html_path, context)
            except Exception:
                html_body = None
            try:
                text_body = render_to_string(txt_path, context)
            except Exception:
                text_body = ""

    except Exception as e:
        logger.error(f"send_template_email: Failed to render template '{template_key}': {e}")
        return False

    # --- Step 2: Send ---
    try:
        send_mail(
            subject=subject,
            message=text_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to_email],
            html_message=html_body or None,
            fail_silently=fail_silently,
        )
        logger.info(f"send_template_email: Sent '{template_key}' to {to_email}")
        return True
    except Exception as e:
        logger.error(f"send_template_email: Failed to send '{template_key}' to {to_email}: {e}")
        return False


def generate_temporary_password(length=12):
    """
    Generate a secure temporary password that meets Cognito requirements.
    Must include: uppercase, lowercase, numbers, and symbols.

    Args:
        length: Password length (default 12 characters)

    Returns:
        str: Random password with uppercase, lowercase, numbers, and special chars
    """
    import random

    # Character sets for different requirements
    uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    lowercase = 'abcdefghijklmnopqrstuvwxyz'
    digits = '0123456789'
    symbols = '!@#$%'

    # Ensure at least one character from each required set
    password_chars = [
        random.choice(uppercase),
        random.choice(lowercase),
        random.choice(digits),
        random.choice(symbols),
    ]

    # Fill remaining length with random characters from all sets
    all_chars = uppercase + lowercase + digits + symbols
    remaining_length = length - len(password_chars)
    password_chars.extend(random.choice(all_chars) for _ in range(remaining_length))

    # Shuffle to avoid predictable patterns
    random.shuffle(password_chars)

    return ''.join(password_chars)


def create_cognito_user(username, email, temp_password, first_name="", last_name=""):
    """
    Create a user in AWS Cognito with a temporary password.

    Args:
        username: Django username (non-email format, required by Cognito)
        email: User email address (will be set as email attribute/alias)
        temp_password: Temporary password for the user
        first_name: User's first name
        last_name: User's last name

    Returns:
        bool: True if user created successfully, False otherwise
    """
    region = getattr(settings, "COGNITO_REGION", "") or ""
    pool_id = getattr(settings, "COGNITO_USER_POOL_ID", "") or ""

    if not region or not pool_id:
        logger.warning("Cognito not configured; skipping user creation (missing region/pool_id)")
        return False

    try:
        client = boto3.client("cognito-idp", region_name=region)

        # Create user in Cognito
        # Note: Username must NOT be in email format when pool is configured with email alias
        client.admin_create_user(
            UserPoolId=pool_id,
            Username=username,  # Use Django username (non-email format)
            TemporaryPassword=temp_password,
            UserAttributes=[
                {"Name": "email", "Value": email},
                {"Name": "email_verified", "Value": "true"},  # Mark email as verified
                {"Name": "given_name", "Value": first_name},
                {"Name": "family_name", "Value": last_name},
            ],
            MessageAction="SUPPRESS",  # Don't send Cognito's default email
        )

        # Set password as permanent so user can log in immediately without password change
        client.admin_set_user_password(
            UserPoolId=pool_id,
            Username=username,
            Password=temp_password,
            Permanent=True,  # Allow login without forcing password change
        )

        logger.info(f"Cognito user created: username={username}, email={email}")
        return True

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")

        # User already exists - that's OK, we can still send credentials
        if error_code == "UsernameExistsException":
            logger.info(f"Cognito user already exists: username={username}")
            # Still set the temporary password for existing user
            try:
                client.admin_set_user_password(
                    UserPoolId=pool_id,
                    Username=username,
                    Password=temp_password,
                    Permanent=True,  # Allow login without forcing password change
                )
                logger.info(f"Temporary password set for existing Cognito user: {username}")
                return True
            except Exception as set_pwd_error:
                logger.error(f"Failed to set password for existing Cognito user {username}: {set_pwd_error}")
                return False
        else:
            logger.error(f"Failed to create Cognito user {username}: {e}")
            return False
    except Exception as e:
        logger.error(f"Unexpected error creating Cognito user {username}: {e}")
        return False


def update_cognito_user_email(username, email):
    """
    Update the email attribute of an existing Cognito user.

    Args:
        username: Cognito username
        email: New email address

    Returns:
        bool: True if email updated successfully, False otherwise
    """
    region = getattr(settings, "COGNITO_REGION", "") or ""
    pool_id = getattr(settings, "COGNITO_USER_POOL_ID", "") or ""

    if not region or not pool_id:
        logger.warning("Cognito not configured; skipping email update")
        return False

    try:
        client = boto3.client("cognito-idp", region_name=region)
        client.admin_update_user_attributes(
            UserPoolId=pool_id,
            Username=username,
            UserAttributes=[
                {"Name": "email", "Value": email},
                {"Name": "email_verified", "Value": "true"},
            ]
        )
        logger.info(f"Updated Cognito user email: username={username}, email={email}")
        return True
    except Exception as e:
        logger.error(f"Failed to update Cognito user email for {username}: {e}")
        return False


def set_cognito_user_password(username, password, aliases=None):
    """
    Set/reset an existing Cognito user's password as permanent.

    Args:
        username: Cognito username
        password: Raw password to set
        aliases: Optional list of fallback usernames/aliases to try

    Returns:
        bool: True if password updated successfully, False otherwise
    """
    region = getattr(settings, "COGNITO_REGION", "") or ""
    pool_id = getattr(settings, "COGNITO_USER_POOL_ID", "") or ""

    if not region or not pool_id:
        logger.warning("Cognito not configured; skipping password update")
        return False

    candidates = [username] + [a for a in (aliases or []) if a]
    # Preserve order while de-duplicating
    seen = set()
    candidates = [c for c in candidates if not (c in seen or seen.add(c))]

    client = boto3.client("cognito-idp", region_name=region)
    last_error = None
    for candidate in candidates:
        try:
            client.admin_set_user_password(
                UserPoolId=pool_id,
                Username=candidate,
                Password=password,
                Permanent=True,
            )
            logger.info(f"Updated Cognito password for user: {candidate}")
            return True
        except Exception as e:
            last_error = e
            logger.warning(f"Failed Cognito password update with identifier {candidate}: {e}")

    logger.error(f"Failed to update Cognito password for {username}: {last_error}")
    return False


def delete_cognito_user(username):
    """
    Delete a user from AWS Cognito.
    """
    region = getattr(settings, "COGNITO_REGION", "") or ""
    pool_id = getattr(settings, "COGNITO_USER_POOL_ID", "") or ""

    if not region or not pool_id:
        logger.warning(f"Cognito not configured; skipping deletion for {username}")
        return False

    try:
        client = boto3.client("cognito-idp", region_name=region)
        client.admin_delete_user(UserPoolId=pool_id, Username=username)
        logger.info(f"Deleted Cognito user: {username}")
        return True
    except client.exceptions.UserNotFoundException:
        logger.warning(f"Cognito user {username} not found during deletion.")
        return True # Considered success as user is gone
    except Exception as e:
        logger.error(f"Failed to delete Cognito user {username}: {e}")
        return False



def send_speaker_credentials_email(user, frontend_url=None):
    """
    Send email to speaker with temporary password to set up their account.
    Creates user in both Django and AWS Cognito.

    Args:
        user: User instance
        frontend_url: Optional frontend base URL (defaults to settings)

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not user.email:
        logger.warning(f"Cannot send credentials email: User {user.username} has no email")
        return False

    # Generate temporary password
    temp_password = generate_temporary_password()

    # 1. Create/update user in AWS Cognito
    cognito_success = create_cognito_user(
        username=user.username,
        email=user.email,
        temp_password=temp_password,
        first_name=user.first_name or "",
        last_name=user.last_name or ""
    )

    if not cognito_success:
        logger.error(f"Failed to create Cognito user for {user.email}; email not sent")
        return False

    # 2. Add user to 'speaker' group in Cognito
    add_user_to_speaker_group(username=user.username)

    # 3. Set the temporary password on the Django user account
    user.set_password(temp_password)
    user.save(update_fields=['password'])
    logger.info(f"Temporary password set for user {user.username}")

    # Build login URL
    frontend_base = frontend_url or getattr(settings, 'FRONTEND_URL', '')
    login_url = f"{frontend_base}/login"

    # Prepare email context
    ctx = {
        "app_name": "IMAA Connect",
        "first_name": user.first_name or user.username or "there",
        "last_name": user.last_name or "",
        "username": user.username,
        "email": user.email,
        "temporary_password": temp_password,
        "login_url": login_url,
        "support_email": settings.DEFAULT_FROM_EMAIL,
    }

    # Send email via template helper
    return send_template_email(
        template_key="speaker_credentials",
        to_email=user.email,
        context=ctx,
        subject_override=f"Your {ctx['app_name']} Speaker Account - Login Credentials",
        fail_silently=False,
    )


def send_event_confirmation_email(participant):
    """
    Send email to speaker confirming they've been added to an event.

    Args:
        participant: EventParticipant instance

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    user = participant.user
    if not user or not user.email:
        logger.warning(f"Cannot send event confirmation: EventParticipant {participant.id} has no user or email")
        return False

    event = participant.event
    frontend_base = getattr(settings, 'FRONTEND_URL', '')
    event_url = f"{frontend_base}/events/{event.slug}/"

    # Prepare email context
    ctx = {
        "app_name": "IMAA Connect",
        "first_name": user.first_name or user.username or "there",
        "last_name": user.last_name or "",
        "role": participant.get_role_display(),
        "event_title": event.title,
        "event_description": event.description or "",
        "event_start": event.start_time,
        "event_end": event.end_time,
        "is_multi_day": event.is_multi_day,
        "event_timezone": event.timezone,
        "event_url": event_url,
        "profile_url": f"{frontend_base}/profile/{user.username}",
        "login_url": f"{frontend_base}/login",
        "support_email": settings.DEFAULT_FROM_EMAIL,
    }

    # Send email via template helper
    return send_template_email(
        template_key="event_confirmation",
        to_email=user.email,
        context=ctx,
        subject_override=f"You're Confirmed as {ctx['role']} - {event.title}",
        fail_silently=False,
    )


def send_admin_credentials_email(user, frontend_url=None):
    """
    Send email to a new admin/staff user with their temporary password.
    Also creates/updates the user in Cognito.

    Args:
        user: User instance
        frontend_url: Optional frontend base URL

    Returns:
        bool: True if successful
    """
    if not user.email:
        logger.warning(f"Cannot send admin credentials: User {user.username} has no email")
        return False

    # Generate temporary password
    temp_password = generate_temporary_password()

    # 1. Create/update user in AWS Cognito
    cognito_success = create_cognito_user(
        username=user.username,
        email=user.email,
        temp_password=temp_password,
        first_name=user.first_name or "",
        last_name=user.last_name or ""
    )

    if not cognito_success:
        logger.error(f"Failed to create Cognito user for {user.email}; email not sent")
        return False

    # 2. Update Django user password
    user.set_password(temp_password)
    user.save(update_fields=['password'])
    logger.info(f"Temporary password set for admin user {user.username}")

    # 3. Build login URL
    frontend_base = frontend_url or getattr(settings, 'FRONTEND_URL', '')
    login_url = f"{frontend_base}/login"

    # 4. Prepare email context
    ctx = {
        "app_name": "IMAA Connect",
        "first_name": user.first_name or user.username or "there",
        "username": user.username,
        "email": user.email,
        "temporary_password": temp_password,
        "login_url": login_url,
        "support_email": settings.DEFAULT_FROM_EMAIL,
    }

    # 5. Send email via template helper
    return send_template_email(
        template_key="admin_credentials",
        to_email=user.email,
        context=ctx,
        subject_override=f"Welcome to {ctx['app_name']} - Your Admin Credentials",
        fail_silently=False,
    )

def send_event_cancelled_email(event):
    """
    Send email to all participants (registered, cancellation_requested) when an event is cancelled.
    """
    from events.models import EventRegistration
    
    frontend_base = getattr(settings, 'FRONTEND_URL', '')
    event_url = f"{frontend_base}/events/{event.slug}/"
    recommended_event_url = ""
    if getattr(event, 'recommended_event', None):
        recommended_event_url = f"{frontend_base}/events/{event.recommended_event.slug}/"
        
    registrations = EventRegistration.objects.filter(
        event=event,
        status__in=["registered", "cancellation_requested"]
    ).select_related("user")
    
    success_count = 0
    support_email = getattr(settings, 'DEFAULT_FROM_EMAIL', '')
    
    for reg in registrations:
        user = reg.user
        if not user or not user.email:
            continue

        ctx = {
            "app_name": "IMAA Connect",
            "first_name": user.first_name or user.username or "there",
            "event_title": event.title,
            "event_start": event.start_time,
            "event_end": event.end_time,
            "is_multi_day": event.is_multi_day,
            "event_timezone": event.timezone,
            "cancellation_message": event.cancellation_message or "",
            "has_recommended_event": bool(event.recommended_event),
            "recommended_event_title": event.recommended_event.title if event.recommended_event else "",
            "recommended_event_url": recommended_event_url,
            "event_url": event_url,
            "support_email": support_email,
        }

        if send_template_email(
            template_key="event_cancelled",
            to_email=user.email,
            context=ctx,
            subject_override=f"Update: '{event.title}' has been cancelled",
            fail_silently=True,
        ):
            success_count += 1
            
    logger.info(f"Sent {success_count} cancellation emails for event {event.id}")
    return success_count


def send_group_invite_email(to_email, group, inviter, invite_url):
    """
    Send an email invitation to join a group.
    """
    app_name = "IMAA Connect"
    inviter_name = inviter.get_full_name() or inviter.username or inviter.email
    support_email = getattr(settings, 'DEFAULT_FROM_EMAIL', '')

    ctx = {
        "app_name": app_name,
        "inviter_name": inviter_name,
        "group_name": group.name,
        "invite_url": invite_url,
        "support_email": support_email,
    }

    return send_template_email(
        template_key="group_invite",
        to_email=to_email,
        context=ctx,
        subject_override=f"You're invited to join '{group.name}' on {app_name}",
        fail_silently=True,
    )


def send_event_invite_email(to_email, event, inviter, invite_url):
    """
    Send an email invitation to attend an event.
    """
    app_name = "IMAA Connect"
    inviter_name = inviter.get_full_name() or inviter.username or inviter.email
    support_email = getattr(settings, 'DEFAULT_FROM_EMAIL', '')

    ctx = {
        "app_name": app_name,
        "inviter_name": inviter_name,
        "event_title": event.title,
        "event_start": event.start_time,
        "event_end": event.end_time,
        "is_multi_day": event.is_multi_day,
        "event_timezone": event.timezone,
        "invite_url": invite_url,
        "support_email": support_email,
    }

    return send_template_email(
        template_key="event_invite",
        to_email=to_email,
        context=ctx,
        subject_override=f"You're invited to '{event.title}' on {app_name}",
        fail_silently=True,
    )


def send_replay_noshow_email(user, event):
    """
    Send "You missed the webinar - here is the recording" email to a no-show registrant.
    Called per-user by the Celery task.
    """
    if not user or not user.email:
        return False

    app_name = "IMAA Connect"
    frontend_base = getattr(settings, 'FRONTEND_URL', '')
    event_url = f"{frontend_base}/events/{event.slug}/"
    replay_url = f"{frontend_base}/account/recordings"
    support_email = getattr(settings, 'DEFAULT_FROM_EMAIL', '')

    ctx = {
        "app_name": app_name,
        "first_name": user.first_name or user.username or "there",
        "event_title": event.title,
        "event_start": event.start_time,
        "event_end": event.end_time,
        "event_timezone": event.timezone,
        "event_url": event_url,
        "replay_url": replay_url,
        "support_email": support_email,
    }

    return send_template_email(
        template_key="replay_no_show",
        to_email=user.email,
        context=ctx,
        subject_override=f"You missed '{event.title}' – the recording is now available",
        fail_silently=True,
    )


def send_replay_partial_email(user, event):
    """
    Send "Here are the parts you missed" email to a partial attendee.
    Called per-user by the Celery task.
    """
    if not user or not user.email:
        return False

    app_name = "IMAA Connect"
    frontend_base = getattr(settings, 'FRONTEND_URL', '')
    event_url = f"{frontend_base}/events/{event.slug}/"
    replay_url = f"{frontend_base}/account/recordings"
    support_email = getattr(settings, 'DEFAULT_FROM_EMAIL', '')

    ctx = {
        "app_name": app_name,
        "first_name": user.first_name or user.username or "there",
        "event_title": event.title,
        "event_start": event.start_time,
        "event_end": event.end_time,
        "event_timezone": event.timezone,
        "event_url": event_url,
        "replay_url": replay_url,
        "support_email": support_email,
    }

    return send_template_email(
        template_key="replay_partial",
        to_email=user.email,
        context=ctx,
        subject_override=f"You left '{event.title}' early – catch what you missed",
        fail_silently=True,
    )


def send_user_registration_acknowledgement_email(user, event):
    """
    Send an acknowledgement email to an authenticated user when they register for an open event.

    Confirms their registration and provides event details.

    Args:
        user: User instance
        event: Event instance

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not user or not user.email or not event:
        return False

    app_name = "IMAA Connect"
    frontend_base = getattr(settings, 'FRONTEND_URL', '')
    event_url = f"{frontend_base}/events/{event.slug or event.id}/"

    ctx = {
        "app_name": app_name,
        "first_name": user.first_name or user.username or "there",
        "event_title": event.title,
        "event_date": event.start_time,
        "event_start": event.start_time,
        "event_end": event.end_time,
        "is_multi_day": event.is_multi_day,
        "event_timezone": event.timezone,
        "event_url": event_url,
        "support_email": settings.DEFAULT_FROM_EMAIL,
    }

    return send_template_email(
        template_key="user_registration_acknowledgement",
        to_email=user.email,
        context=ctx,
        subject_override=f"Registration Confirmed – '{event.title}'",
        fail_silently=True,
    )


def send_guest_registration_acknowledgement_email(guest_name, email, event):
    """
    Send an acknowledgement email to a guest when they register for an open registration event.

    Confirms their registration and provides event details.

    Args:
        guest_name: Guest's display name (first_name last_name)
        email: Guest's email address
        event: Event instance

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not email or not event:
        return False

    app_name = "IMAA Connect"
    frontend_base = getattr(settings, 'FRONTEND_URL', '')
    event_url = f"{frontend_base}/events/{event.slug or event.id}/"

    ctx = {
        "app_name": app_name,
        "guest_name": guest_name or "Guest",
        "event_title": event.title,
        "event_date": event.start_time,
        "event_start": event.start_time,
        "event_end": event.end_time,
        "is_multi_day": event.is_multi_day,
        "event_timezone": event.timezone,
        "event_url": event_url,
        "support_email": settings.DEFAULT_FROM_EMAIL,
    }

    return send_template_email(
        template_key="guest_registration_acknowledgement",
        to_email=email,
        context=ctx,
        subject_override=f"You're Registered for '{event.title}' ✅",
        fail_silently=True,
    )


def send_application_acknowledgement_email(application):
    """
    Send an acknowledgement email to an applicant when their application is submitted.

    Confirms receipt of application and sets expectations for review timeline.

    Args:
        application: EventApplication instance with pending status (newly created)

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not application or not application.email:
        return False

    app_name = "IMAA Connect"
    frontend_base = getattr(settings, 'FRONTEND_URL', '')
    event_url = f"{frontend_base}/events/{application.event.slug or application.event.id}/"

    ctx = {
        "app_name": app_name,
        "applicant_name": f"{application.first_name} {application.last_name}",
        "event_title": application.event.title,
        "event_date": application.event.start_time,
        "event_start": application.event.start_time,
        "event_end": application.event.end_time,
        "is_multi_day": application.event.is_multi_day,
        "event_timezone": application.event.timezone,
        "event_url": event_url,
        "support_email": settings.DEFAULT_FROM_EMAIL,
    }

    return send_template_email(
        template_key="application_acknowledgement",
        to_email=application.email,
        context=ctx,
        subject_override=f"Application Received – '{application.event.title}'",
        fail_silently=True,
    )


def send_application_approved_email(application):
    """
    Send an approval email to an applicant with magic login link for guests.

    Args:
        application: EventApplication instance with approved status

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not application or not application.email:
        return False

    app_name = "IMAA Connect"
    frontend_base = getattr(settings, 'FRONTEND_URL', '')
    event_url = f"{frontend_base}/events/{application.event.slug}/"
    magic_link = None

    # For guest applications (no linked user yet), generate magic login token
    # Backend already created user during approval, so application.user should exist
    if application.user:
        try:
            from urllib.parse import quote
            token = generate_magic_login_token(application.user, application.event, expires_in_hours=24)
            # Direct guests to live meeting page instead of event detail page
            # Use path-only URL (next will be relative) - simpler and more reliable
            live_path = f"/live/{application.event.slug or application.event.id}?id={application.event.id}&role=audience"
            # URL encode only the path (preserves / ? = &)
            next_param = quote(live_path, safe='/?=&')
            magic_link = f"{frontend_base}/auth/magic-link?token={token}&next={next_param}"
            logger.info(f"Generated magic link for approved guest application {application.id}")
        except Exception as e:
            logger.error(f"Failed to generate magic link for application {application.id}: {e}")
            # Continue without magic link if generation fails

    ctx = {
        "app_name": app_name,
        "applicant_name": f"{application.first_name} {application.last_name}",
        "event_title": application.event.title,
        "event_date": application.event.start_time,
        "event_start": application.event.start_time,
        "event_end": application.event.end_time,
        "is_multi_day": application.event.is_multi_day,
        "event_timezone": application.event.timezone,
        "event_url": event_url,
        "magic_link": magic_link,
    }

    return send_template_email(
        template_key="application_approved",
        to_email=application.email,
        context=ctx,
        subject_override=f"Your application to '{application.event.title}' has been approved!",
        fail_silently=True,
    )


def send_application_declined_email(application, custom_message=''):
    """
    Send a decline email to an applicant with optional custom message.

    Args:
        application: EventApplication instance with declined status
        custom_message: Optional custom rejection message from the host

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not application or not application.email:
        return False

    app_name = "IMAA Connect"

    ctx = {
        "app_name": app_name,
        "applicant_name": f"{application.first_name} {application.last_name}",
        "event_title": application.event.title,
        "event_start": application.event.start_time,
        "event_end": application.event.end_time,
        "is_multi_day": application.event.is_multi_day,
        "event_timezone": application.event.timezone,
        "custom_message": custom_message or '',
    }

    return send_template_email(
        template_key="application_declined",
        to_email=application.email,
        context=ctx,
        subject_override=f"Your application to '{application.event.title}' – status update",
        fail_silently=True,
    )


def send_guest_otp_email(to_email, guest_name, otp_code, event_title):
    """
    Send a 6-digit OTP verification code to a guest's email.

    Used when a guest joins an event and needs to verify their email
    before receiving a guest JWT token.

    Args:
        to_email: Guest's email address
        guest_name: Guest's first name for personalization
        otp_code: 6-digit numeric OTP code
        event_title: Title of the event being joined

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not to_email or not otp_code:
        return False

    app_name = "IMAA Connect"

    ctx = {
        "app_name": app_name,
        "guest_name": guest_name or "Guest",
        "otp_code": otp_code,
        "event_title": event_title,
        "expiry_minutes": 10,
    }

    return send_template_email(
        template_key="guest_otp",
        to_email=to_email,
        context=ctx,
        subject_override=f"Your verification code for {event_title}",
        fail_silently=True,
    )


def send_guest_followup_email(to_email, guest_name, event_title, signup_url):
    """
    Send a follow-up email to encourage a guest to register after attending an event.

    Sent 24 hours after an event ends to guests who attended but haven't registered yet.
    Highlights benefits like access to past events, certificates, and personalized dashboard.

    Args:
        to_email: Guest's email address
        guest_name: Guest's first name for personalization
        event_title: Title of the event they attended
        signup_url: URL for signing up with pre-filled email

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    if not to_email:
        return False

    app_name = "IMAA Connect"

    ctx = {
        "app_name": app_name,
        "guest_name": guest_name or "Guest",
        "event_title": event_title,
        "signup_url": signup_url,
        "benefits": [
            "Access to past events and replays",
            "Digital certificates and badges",
            "Personalized networking dashboard",
            "Event recommendations tailored to your interests",
        ],
    }

    return send_template_email(
        template_key="guest_followup",
        to_email=to_email,
        context=ctx,
        subject_override=f"Join {app_name} to unlock exclusive benefits",
        fail_silently=True,
    )


def link_guest_history_to_user(user, email):
    """
    Link all past GuestAttendee records matching an email to a registered user.

    Called when:
    - Guest converts to registered user (GuestRegisterView)
    - Existing user links to guest session (GuestRegisterLinkView)
    - Standard user registration matches a guest email (signal)
    - User verifies an email alias (UserEmailAlias verification)

    This ensures the user's attendance history is consolidated across
    all email addresses they've used as a guest.

    Args:
        user: Django User instance
        email: Email address to link guest records from

    Returns:
        int: Number of GuestAttendee records linked
    """
    from events.models import GuestAttendee

    if not user or not email:
        return 0

    email = email.strip().lower()

    # Find all unlinked GuestAttendee records for this email
    guests = GuestAttendee.objects.filter(
        email=email,
        converted_user__isnull=True  # Only link unlinked records
    )

    count = guests.count()
    if count > 0:
        # Link all guests to this user
        guests.update(converted_user=user, converted_at=timezone.now())
        logger.info(
            f"Linked {count} guest attendee record(s) for email {email} to user {user.id}"
        )

    return count
