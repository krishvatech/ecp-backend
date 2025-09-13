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