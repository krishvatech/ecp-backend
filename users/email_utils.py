"""
Email utilities for user account management.
Centralizes email sending logic with consistent error handling.
"""
import logging
import boto3
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.crypto import get_random_string
from botocore.exceptions import ClientError
from .cognito_groups import add_user_to_speaker_group

logger = logging.getLogger(__name__)


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

    # Render email templates
    try:
        text_body = render_to_string("emails/speaker_credentials.txt", ctx)
        html_body = render_to_string("emails/speaker_credentials.html", ctx)
    except Exception as e:
        logger.error(f"Failed to render speaker credentials email templates: {e}")
        return False

    # Send email
    try:
        send_mail(
            subject=f"Your {ctx['app_name']} Speaker Account - Login Credentials",
            message=text_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_body,
            fail_silently=False,
        )
        logger.info(f"Speaker credentials email sent to {user.email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send speaker credentials email to {user.email}: {e}")
        return False


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
        "event_url": event_url,
        "profile_url": f"{frontend_base}/profile/{user.username}",
        "login_url": f"{frontend_base}/login",
        "support_email": settings.DEFAULT_FROM_EMAIL,
    }

    # Render email templates
    try:
        text_body = render_to_string("emails/event_confirmation.txt", ctx)
        html_body = render_to_string("emails/event_confirmation.html", ctx)
    except Exception as e:
        logger.error(f"Failed to render event confirmation email templates: {e}")
        return False

    # Send email
    try:
        send_mail(
            subject=f"You're Confirmed as {ctx['role']} - {event.title}",
            message=text_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_body,
            fail_silently=False,
        )
        logger.info(f"Event confirmation email sent to {user.email} for event {event.id}")
        return False
    except Exception as e:
        logger.error(f"Failed to send event confirmation email to {user.email}: {e}")
        return False


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

    # 5. Render templates
    try:
        text_body = render_to_string("emails/admin_credentials.txt", ctx)
        html_body = render_to_string("emails/admin_credentials.html", ctx)
    except Exception as e:
        logger.error(f"Failed to render admin credentials email templates: {e}")
        return False

    # 6. Send email
    try:
        send_mail(
            subject=f"Welcome to {ctx['app_name']} - Your Admin Credentials",
            message=text_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_body,
            fail_silently=False,
        )
        logger.info(f"Admin credentials email sent to {user.email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send admin credentials email to {user.email}: {e}")
        return False

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
            "cancellation_message": event.cancellation_message or "",
            "has_recommended_event": bool(event.recommended_event),
            "recommended_event_title": event.recommended_event.title if event.recommended_event else "",
            "recommended_event_url": recommended_event_url,
            "event_url": event_url,
            "support_email": support_email,
        }
        
        try:
            text_body = render_to_string("emails/event_cancelled.txt", ctx)
            html_body = render_to_string("emails/event_cancelled.html", ctx)
            
            send_mail(
                subject=f"Update: '{event.title}' has been cancelled",
                message=text_body,
                from_email=support_email,
                recipient_list=[user.email],
                html_message=html_body,
                fail_silently=True,
            )
            success_count += 1
        except Exception as e:
            logger.error(f"Failed to send cancellation email to {user.email} for event {event.id}: {e}")
            
    logger.info(f"Sent {success_count} cancellation emails for event {event.id}")
    return success_count

