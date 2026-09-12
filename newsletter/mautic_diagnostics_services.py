"""Read-only Mautic and newsletter operational diagnostics."""

from __future__ import annotations

from urllib.parse import urlparse

from django.conf import settings
from django.db.models import Count, Max, OuterRef, Subquery
from django.urls import reverse
from django.utils import timezone

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .models import NewsletterCampaignTrackingEvent, NewsletterSyncEvent
from .webhooks import EVENT_TYPE_MAP


def get_mautic_diagnostics(request=None) -> dict:
    checked_at = timezone.now()
    config = _configuration_status()
    rest = _rest_status(config)
    marketing_bridge = _marketing_bridge_status(config)
    campaign_bridge = _campaign_builder_bridge_status(config)
    webhook = _webhook_status(request)
    sync = _sync_status()
    background = _background_processing_status()
    warnings = _warnings(config, rest, marketing_bridge, campaign_bridge, webhook, sync)

    return {
        "checked_at": checked_at,
        "connection": {
            "configured": config["configured"],
            "status": config["status"],
            "host": config["host"],
            "base_url": config["base_url"],
            "reachable": rest["reachable"],
            "authenticated": rest["authenticated"],
            "version": marketing_bridge.get("mautic_version"),
        },
        "api": rest,
        "bridges": {
            "marketing": marketing_bridge,
            "campaign_builder": campaign_bridge,
        },
        "webhook": webhook,
        "sync": sync,
        "background_processing": background,
        "diagnostics": {
            "status": "Healthy" if not warnings else "Degraded",
            "warnings": warnings,
        },
    }


def _configuration_status() -> dict:
    base_url = str(getattr(settings, "MAUTIC_BASE_URL", "") or "").strip().rstrip("/")
    username = str(getattr(settings, "MAUTIC_USERNAME", "") or "").strip()
    password = str(getattr(settings, "MAUTIC_PASSWORD", "") or "")
    parsed = urlparse(base_url)
    host = parsed.netloc or ""
    configured = bool(base_url and username and password and parsed.scheme in {"http", "https"} and host)
    missing = []
    if not base_url:
        missing.append("MAUTIC_BASE_URL")
    if base_url and not parsed.scheme in {"http", "https"}:
        missing.append("valid MAUTIC_BASE_URL")
    if not username:
        missing.append("MAUTIC_USERNAME")
    if not password:
        missing.append("MAUTIC_PASSWORD")
    return {
        "configured": configured,
        "status": "Configured" if configured else "Not Configured",
        "host": host or None,
        "base_url": f"{parsed.scheme}://{host}" if parsed.scheme and host else None,
        "missing": missing,
    }


def _rest_status(config: dict) -> dict:
    if not config["configured"]:
        return {
            "status": "Not Configured",
            "available": False,
            "reachable": False,
            "authenticated": False,
            "detail": "Required Mautic API configuration is missing.",
        }

    try:
        MauticClient().health_check()
    except PermanentMauticError as exc:
        message = str(exc)
        auth_failed = "HTTP 401" in message or "HTTP 403" in message or "credentials" in message.lower()
        return {
            "status": "Authentication Failed" if auth_failed else "Unavailable",
            "available": False,
            "reachable": True,
            "authenticated": False,
            "detail": message,
        }
    except TemporaryMauticError as exc:
        return {
            "status": "Unavailable",
            "available": False,
            "reachable": False,
            "authenticated": False,
            "detail": str(exc),
        }

    return {
        "status": "Healthy",
        "available": True,
        "reachable": True,
        "authenticated": True,
        "detail": "Authenticated lightweight REST request succeeded.",
    }


def _marketing_bridge_status(config: dict) -> dict:
    if not config["configured"]:
        return _bridge_unavailable("Not Configured", "Required Mautic API configuration is missing.")
    try:
        data = MauticClient().get_marketing_bridge_capabilities()
    except (PermanentMauticError, TemporaryMauticError) as exc:
        return _bridge_unavailable("Unavailable", str(exc))
    return {
        "status": "Healthy",
        "available": True,
        "plugin": data.get("plugin") or "EcpMarketingBridgeBundle",
        "version": data.get("version"),
        "mautic_version": data.get("mauticVersion"),
        "capabilities": [str(item) for item in data.get("capabilities", [])],
        "detail": "Marketing bridge capability endpoint responded.",
    }


def _campaign_builder_bridge_status(config: dict) -> dict:
    if not config["configured"]:
        return _bridge_unavailable("Not Configured", "Required Mautic API configuration is missing.")
    try:
        data = MauticClient().get_campaign_builder_capabilities()
    except (PermanentMauticError, TemporaryMauticError) as exc:
        return _bridge_unavailable("Unavailable", str(exc))
    return {
        "status": "Healthy",
        "available": True,
        "plugin": "EcpCampaignBuilderBundle",
        "capabilities": {
            "actions": len(data.get("actions", [])),
            "conditions": len(data.get("conditions", [])),
            "decisions": len(data.get("decisions", [])),
            "runtime_event_discovery": True,
            "form_schema_available": bool((data.get("formSchema") or {}).get("available")),
        },
        "detail": "Campaign Builder capability endpoint responded.",
    }


def _bridge_unavailable(status: str, detail: str) -> dict:
    return {
        "status": status,
        "available": False,
        "capabilities": [],
        "detail": detail,
    }


def _webhook_status(request=None) -> dict:
    secret_configured = bool(str(getattr(settings, "MAUTIC_WEBHOOK_SECRET", "") or ""))
    latest = NewsletterCampaignTrackingEvent.objects.filter(source="mautic").order_by("-created_at").first()
    path = reverse("newsletter-mautic-webhook")
    return {
        "receiver": "Ready" if secret_configured else "Not Configured",
        "endpoint_configured": secret_configured,
        "endpoint_path": path,
        "endpoint_url": request.build_absolute_uri(path) if request is not None else path,
        "registration": "Not Verifiable",
        "last_received_at": latest.created_at if latest else None,
        "last_processing_status": "Received" if latest else "Never Received",
        "supported_event_types": sorted(EVENT_TYPE_MAP.keys()),
    }


def _sync_status() -> dict:
    current_events = _current_sync_events_queryset()
    counts = {
        row["status"]: row["count"]
        for row in current_events.values("status").annotate(count=Count("id"))
    }
    failed = counts.get(NewsletterSyncEvent.Status.FAILED, 0)
    retrying = counts.get(NewsletterSyncEvent.Status.RETRYING, 0)
    latest_success = NewsletterSyncEvent.objects.filter(
        status=NewsletterSyncEvent.Status.SUCCEEDED
    ).aggregate(value=Max("completed_at"))["value"]
    latest_failure = current_events.filter(
        status__in=[NewsletterSyncEvent.Status.FAILED, NewsletterSyncEvent.Status.RETRYING]
    ).order_by("-created_at", "-id").first()
    return {
        "enabled": bool(getattr(settings, "MAUTIC_SYNC_ENABLED", False)),
        "status": "Enabled" if getattr(settings, "MAUTIC_SYNC_ENABLED", False) else "Disabled",
        "pending": counts.get(NewsletterSyncEvent.Status.PENDING, 0),
        "processing": counts.get(NewsletterSyncEvent.Status.PROCESSING, 0),
        "retrying": retrying,
        "failed": failed,
        "succeeded": counts.get(NewsletterSyncEvent.Status.SUCCEEDED, 0),
        "current_warning": failed > 0 or retrying > 0,
        "latest_success_at": latest_success,
        "latest_failure_at": latest_failure.updated_at if latest_failure else None,
        "latest_failure": _truncate(latest_failure.last_error) if latest_failure else "",
    }


def _current_sync_events_queryset():
    latest_for_target = NewsletterSyncEvent.objects.filter(
        user_id=OuterRef("user_id"),
        category_id=OuterRef("category_id"),
    ).order_by("-created_at", "-id")
    return NewsletterSyncEvent.objects.filter(id=Subquery(latest_for_target.values("id")[:1]))


def _background_processing_status() -> dict:
    beat_schedule = getattr(settings, "CELERY_BEAT_SCHEDULE", {}) or {}
    return {
        "configuration": "Enabled" if bool(getattr(settings, "CELERY_BROKER_URL", "")) else "Not Configured",
        "live_worker_status": "Not Verifiable",
        "newsletter_sync_scheduled": "newsletter.dispatch_due_sync_events" in {
            item.get("task") for item in beat_schedule.values() if isinstance(item, dict)
        },
    }


def _warnings(config, rest, marketing_bridge, campaign_bridge, webhook, sync) -> list[str]:
    warnings = []
    if not config["configured"]:
        warnings.append("Mautic API configuration is incomplete.")
    if rest["status"] != "Healthy":
        warnings.append(f"Mautic REST API: {rest['status']}.")
    if marketing_bridge["status"] != "Healthy":
        warnings.append("ECP Marketing Bridge is unavailable.")
    if campaign_bridge["status"] != "Healthy":
        warnings.append("Campaign Builder Bridge is unavailable.")
    if webhook["last_received_at"] is None:
        warnings.append("Webhook receiver has not recorded a Mautic event yet.")
    if sync.get("current_warning"):
        warnings.append("Newsletter sync has failed or retrying events.")
    return warnings


def _truncate(value, limit=240) -> str:
    text = str(value or "")
    return text if len(text) <= limit else f"{text[:limit]}..."
