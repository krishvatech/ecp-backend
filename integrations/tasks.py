"""
Celery tasks for the integrations app.

Currently supports syncing registrant information to HubSpot CRM after a
successful registration or purchase.  The task looks up the
organization's integration configuration, maps user details to
HubSpot properties and sends a request to create or update a
contact.  Sync attempts are logged in the SyncLog model.
"""
from __future__ import annotations

import requests
from celery import shared_task
from django.contrib.auth import get_user_model
from django.conf import settings
from organizations.models import Organization
from events.models import Event
from .models import IntegrationConfig, SyncLog

User = get_user_model()


@shared_task(bind=True, autoretry_for=(requests.RequestException,), retry_backoff=True, max_retries=5)
def sync_registrant_to_hubspot(self, org_id: int, user_id: int, event_id: int | None = None) -> None:
    """Sync a registrant's profile information to HubSpot.

    Args:
        org_id: Organization primary key.
        user_id: User primary key.
        event_id: Optional event primary key for context.
    """
    # Fetch integration config
    try:
        config = IntegrationConfig.objects.get(
            organization_id=org_id, type=IntegrationConfig.TYPE_HUBSPOT, enabled=True
        )
    except IntegrationConfig.DoesNotExist:
        return
    token = config.secrets.get("token")
    if not token:
        return
    try:
        user = User.objects.select_related("profile").get(pk=user_id)
    except User.DoesNotExist:
        return
    # Map user fields to HubSpot properties
    properties = {
        "email": user.email or "",
        "firstname": user.first_name or "",
        "lastname": user.last_name or "",
        "company": getattr(user.profile, "company", "") or "",
        "jobtitle": getattr(user.profile, "job_title", "") or "",
    }
    # Additional dynamic fields can be added from config.settings
    custom_props = config.settings.get("properties", {})
    for k, v in custom_props.items():
        properties[k] = v.format(user=user, profile=user.profile)
    payload = {"properties": properties}
    # Build endpoint
    endpoint = "https://api.hubapi.com/crm/v3/objects/contacts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(endpoint, json=payload, headers=headers, timeout=10)
        status = SyncLog.STATUS_SUCCESS if resp.status_code < 300 else SyncLog.STATUS_FAILED
        error_msg = "" if status == SyncLog.STATUS_SUCCESS else resp.text[:1024]
    except requests.RequestException as exc:
        status = SyncLog.STATUS_FAILED
        error_msg = str(exc)[:1024]
        raise
    # Record sync log
    SyncLog.objects.create(
        organization_id=org_id,
        integration_type=IntegrationConfig.TYPE_HUBSPOT,
        status=status,
        payload_snippet=str(payload)[:1024],
        error=error_msg,
    )
