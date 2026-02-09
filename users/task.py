from celery import shared_task
from django.utils import timezone
import requests
from django.conf import settings
from .models import LinkedInAccount

@shared_task
def linkedin_sync_profile(user_id: int) -> dict:
    try:
        acc = LinkedInAccount.objects.get(user_id=user_id)
    except LinkedInAccount.DoesNotExist:
        return {"ok": False, "error": "no_linked_account"}

    headers = {"Authorization": f"Bearer {acc.access_token}"}
    # Lite profile:
    me = requests.get("https://api.linkedin.com/v2/me", headers=headers, timeout=15)
    # Email:
    em = requests.get("https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
                      headers=headers, timeout=15)

    data = {"profile": None, "email": None}
    if me.status_code == 200:
        data["profile"] = me.json()
    if em.status_code == 200:
        ej = em.json()
        try:
            data["email"] = ej["elements"][0]["handle~"]["emailAddress"]
        except Exception:
            pass

    # (If you have access to additional products like Profile Details API,
    #  add calls here with proper projections and store them as well.)
    # e.g., GET /identityMe or other approved endpoints per your product access. :contentReference[oaicite:8]{index=8}

    if data["profile"]:
        acc.raw_profile_json = data["profile"]
    if data["email"]:
        acc.email = data["email"]
    acc.save()
    return {"ok": True}


@shared_task
def send_speaker_credentials_task(user_id):
    """
    Celery task to send speaker credentials email asynchronously.

    Args:
        user_id: User primary key
    """
    from django.contrib.auth.models import User
    from .email_utils import send_speaker_credentials_email

    try:
        user = User.objects.get(pk=user_id)
        send_speaker_credentials_email(user)
    except User.DoesNotExist:
        import logging
        logging.getLogger(__name__).error(f"User {user_id} not found for credentials email")


@shared_task
def send_event_confirmation_task(participant_id):
    """
    Celery task to send event confirmation email asynchronously.

    Args:
        participant_id: EventParticipant primary key
    """
    from .email_utils import send_event_confirmation_email

    try:
        from events.models import EventParticipant
        participant = EventParticipant.objects.select_related('user', 'event').get(pk=participant_id)
        send_event_confirmation_email(participant)
    except EventParticipant.DoesNotExist:
        import logging
        logging.getLogger(__name__).error(f"EventParticipant {participant_id} not found for confirmation email")