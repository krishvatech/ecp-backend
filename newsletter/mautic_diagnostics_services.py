"""Read-only Mautic and newsletter operational diagnostics."""

from __future__ import annotations

import hmac
import ipaddress
import logging
import threading
from datetime import timedelta
from urllib.parse import urlparse

from django.conf import settings
from django.db.models import Count, Max, OuterRef, Subquery
from django.urls import reverse
from django.utils import timezone

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.identity import per_user_execution_enabled
from .mautic.identity_assertion import is_identity_assertion_configured
from .models import (
    MauticUserConnection,
    NewsletterCampaign,
    NewsletterCampaignTrackingEvent,
    NewsletterSyncEvent,
)
from .task_heartbeats import (
    DEGRADED,
    DISABLED,
    HEALTHY,
    NOT_VERIFIED,
    STALE,
    background_health_enabled,
    periodic_task_health,
    task_stale_after_seconds,
)
from .scheduler_monitoring import (
    build_scheduler_monitoring,
    fetch_mautic_background_report,
    legacy_beat_status,
    scheduler_warnings,
)
from .webhooks import EVENT_TYPE_MAP, webhook_observations

logger = logging.getLogger(__name__)

#: Bounded so a diagnostics request never waits long on the broker.
BROKER_PROBE_TIMEOUT_SECONDS = 1.0

#: Celery worker ping budget. ``control.ping(timeout=...)`` only bounds the wait
#: for replies; the broker connection it opens is retried by kombu and, with the
#: Redis transport's default socket_connect_timeout=None, a single connect to an
#: unreachable host blocks for the kernel's SYN retries (over two minutes). So
#: the probe uses its own connection with a 1 s connect timeout and no retries,
#: waits 1 s for replies, and runs under a hard wall-clock deadline that also
#: covers what socket options cannot bound (DNS resolution, publish retries).
WORKER_PROBE_CONNECT_TIMEOUT_SECONDS = 1.0
WORKER_PROBE_REPLY_TIMEOUT_SECONDS = 1.0
#: Longer than the reply wait so slow-but-healthy pings still read (2 s > 1 s).
WORKER_PROBE_SOCKET_TIMEOUT_SECONDS = 2.0
#: Hard limit on how long a diagnostics request waits for the worker probe:
#: connect (1 s) + reply wait (1 s) + 1 s margin for scheduling and teardown.
WORKER_PROBE_DEADLINE_SECONDS = 3.0
#: One probe at a time: a probe that outlives its deadline keeps this lock until
#: it finishes, so repeated requests cannot pile up blocked threads.
_worker_probe_lock = threading.Lock()


def get_mautic_diagnostics(request=None) -> dict:
    checked_at = timezone.now()
    config = _configuration_status()
    rest = _rest_status(config)
    marketing_bridge = _marketing_bridge_status(config)
    campaign_bridge = _campaign_builder_bridge_status(config)
    webhook = _webhook_status(request, config=config, marketing_bridge=marketing_bridge)
    sync = _sync_status()
    redis_probe = _redis_status()
    worker = _worker_status(broker=redis_probe)
    scheduled_processing = periodic_task_health(now=checked_at)
    background = _background_processing_status(worker)
    native_broadcasts = _native_broadcast_status()
    broadcast_sends = _broadcast_send_status()
    scheduler_monitoring = build_scheduler_monitoring(
        redis_probe=redis_probe,
        worker_probe=worker,
        scheduled_processing=scheduled_processing,
        **_mautic_background_evidence(config, marketing_bridge),
        now=checked_at,
    )
    health = _health_summary(
        redis_probe,
        worker,
        scheduled_processing,
        broadcast_sends,
        native_broadcasts,
        now=checked_at,
        beat=legacy_beat_status(scheduler_monitoring["components"]["celery_beat"]),
    )
    identity = _identity_status(request, marketing_bridge)
    warnings = _warnings(config, rest, marketing_bridge, campaign_bridge, webhook, sync)
    if native_broadcasts["needs_attention"]:
        warnings.append("Native Mautic broadcasts need attention.")
    if broadcast_sends["needs_review"]:
        warnings.append(
            "Broadcast sends have no confirmed outcome; check them in Mautic."
        )
    warnings.extend(health["warnings"])
    # Redis, worker and task-run problems are already warned about above.
    warnings.extend(
        scheduler_warnings(scheduler_monitoring, only=("celery_beat", "mautic_cron", "mautic_worker"))
    )
    warnings.extend(identity["warnings"])

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
        "native_broadcasts": native_broadcasts,
        "broadcast_sends": broadcast_sends,
        "health": health["components"],
        "scheduler_monitoring": scheduler_monitoring,
        "identity": identity,
        "diagnostics": {
            "status": "Healthy" if not warnings else "Degraded",
            "warnings": warnings,
        },
    }


def collect_scheduler_monitoring(*, include_mautic: bool = True) -> dict:
    """Scheduler monitoring alone, for check_background_health and other
    observers outside the request path. Same probes and bounds as the
    diagnostics endpoint; read-only."""
    now = timezone.now()
    redis_probe = _redis_status()
    mautic = {"mautic_report": None, "mautic_error": "not_checked"}
    if include_mautic:
        config = _configuration_status()
        mautic = (
            {"mautic_report": None, "mautic_error": "not_configured"}
            if not config["configured"]
            else dict(zip(
                ("mautic_report", "mautic_error"),
                fetch_mautic_background_report(client_factory=MauticClient),
            ))
        )
    return build_scheduler_monitoring(
        redis_probe=redis_probe,
        worker_probe=_worker_status(broker=redis_probe),
        scheduled_processing=periodic_task_health(now=now),
        **mautic,
        now=now,
    )


def _identity_status(request=None, marketing_bridge: dict | None = None) -> dict:
    """Per-user execution readiness. Booleans and counts only, never key material."""
    signing_configured = is_identity_assertion_configured()
    per_user_enabled = per_user_execution_enabled()

    active_connections = MauticUserConnection.objects.filter(
        is_active=True,
        status=MauticUserConnection.Status.ACTIVE,
    ).count()

    actor = getattr(request, "user", None) if request is not None else None
    actor_connected = False
    if actor is not None and getattr(actor, "is_authenticated", False):
        actor_connected = MauticUserConnection.objects.filter(
            user_id=actor.pk,
            is_active=True,
            status=MauticUserConnection.Status.ACTIVE,
        ).exists()

    # Reported by the Mautic plugin's capabilities endpoint when reachable.
    remote = {}
    if isinstance(marketing_bridge, dict):
        remote = marketing_bridge.get("identity") or {}

    warnings = []
    if per_user_enabled and not signing_configured:
        warnings.append(
            "Per-user Mautic execution is enabled but ECP identity signing is not configured."
        )
    if per_user_enabled and not active_connections:
        warnings.append(
            "Per-user Mautic execution is enabled but no Mautic user connections are active."
        )
    if per_user_enabled and remote and not remote.get("ready", True):
        warnings.append("Mautic reports the identity bridge is not ready.")

    return {
        "per_user_execution_enabled": per_user_enabled,
        "signing_configured": signing_configured,
        "key_id_configured": bool(str(getattr(settings, "ECP_MAUTIC_IDENTITY_KEY_ID", "") or "").strip()),
        "issuer": str(getattr(settings, "ECP_MAUTIC_IDENTITY_ISSUER", "") or "").strip() or None,
        "audience": str(getattr(settings, "ECP_MAUTIC_IDENTITY_AUDIENCE", "") or "").strip() or None,
        "active_connections": active_connections,
        "current_user_connected": actor_connected,
        "mautic_identity": remote or None,
        "status": "Healthy" if not warnings else "Degraded",
        "warnings": warnings,
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
        # Safe readiness flags reported by the plugin; never key material.
        "identity": data.get("identity") if isinstance(data.get("identity"), dict) else None,
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


def _webhook_status(request=None, *, config=None, marketing_bridge=None) -> dict:
    secret = str(getattr(settings, "MAUTIC_WEBHOOK_SECRET", "") or "")
    secret_configured = bool(secret)
    latest = NewsletterCampaignTrackingEvent.objects.filter(source="mautic").order_by("-created_at").first()
    path = reverse("newsletter-mautic-webhook")
    observations = webhook_observations()
    registration = _webhook_registration(path, secret, config, marketing_bridge)
    return {
        "receiver": "Ready" if secret_configured else "Not Configured",
        "endpoint_configured": secret_configured,
        "endpoint_path": path,
        "endpoint_url": request.build_absolute_uri(path) if request is not None else path,
        "registration": registration.pop("status"),
        "last_received_at": latest.created_at if latest else None,
        "last_processing_status": "Received" if latest else "Never Received",
        "supported_event_types": sorted(EVENT_TYPE_MAP.keys()),
        # B15: what Mautic is configured to do, and what deliveries showed.
        **registration,
        "deliveries": {
            "observed": observations.get("available", False),
            "last_accepted": observations.get("accepted"),
            "last_rejected": observations.get("rejected"),
            "last_failed": observations.get("failed"),
        },
    }


def _is_private_host(host: str) -> bool:
    if not host or host == "localhost" or host.endswith(".local") or host.endswith(".internal"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def _webhook_registration(path, secret, config, marketing_bridge) -> dict:
    """Whether Mautic has a webhook pointing at this receiver, read from
    Mautic's own webhook list. Read-only; the secret is compared, never
    returned. Anything that cannot be read is Not Verifiable, never assumed."""
    result = {
        "status": "Not Verifiable",
        "registration_detail": "",
        "registered_events": [],
        "missing_events": [],
        "secret_matches": None,
        "delivery_host": None,
        "delivery_host_private": None,
        "matching_hooks": 0,
    }
    if not (config or {}).get("configured"):
        result["registration_detail"] = "Mautic is not configured."
        return result
    if not (marketing_bridge or {}).get("available"):
        result["registration_detail"] = "Mautic could not be reached."
        return result
    try:
        timeout = float(getattr(settings, "NEWSLETTER_SEND_EVIDENCE_TIMEOUT_SECONDS", 5))
        hooks = MauticClient().list_webhooks(timeout=timeout)
    except (PermanentMauticError, TemporaryMauticError) as exc:
        result["registration_detail"] = (
            "Mautic does not allow this account to read webhooks."
            if "HTTP 403" in str(exc) else "Mautic's webhook list could not be read."
        )
        return result

    wanted = path.rstrip("/")
    matches = [
        hook for hook in hooks
        if isinstance(hook, dict) and urlparse(str(hook.get("webhookUrl") or "")).path.rstrip("/") == wanted
    ]
    result["matching_hooks"] = len(matches)
    if not matches:
        result.update(status="Not Registered", registration_detail="No Mautic webhook points at this receiver.")
        return result

    published = [hook for hook in matches if hook.get("isPublished") is True]
    hook = (published or matches)[0]
    triggers = hook.get("triggers") or []
    subscribed = {
        str(trigger.get("eventType") if isinstance(trigger, dict) else trigger)
        for trigger in (triggers.values() if isinstance(triggers, dict) else triggers)
    }
    supported = set(EVENT_TYPE_MAP)
    host = urlparse(str(hook.get("webhookUrl") or "")).hostname or ""
    hook_secret = str(hook.get("secret") or "")
    result.update(
        registered_events=sorted(subscribed & supported),
        missing_events=sorted(supported - subscribed),
        secret_matches=(
            hmac.compare_digest(hook_secret.encode(), secret.encode())
            if hook_secret and secret else None
        ),
        delivery_host=host or None,
        delivery_host_private=_is_private_host(host) if host else None,
    )
    if published:
        result.update(status="Registered", registration_detail=(
            "A published Mautic webhook points at this receiver."
            if len(published) == 1 else "Several published Mautic webhooks point at this receiver."
        ))
    else:
        result.update(status="Disabled in Mautic", registration_detail=(
            "A Mautic webhook points at this receiver but is unpublished; Mautic unpublishes "
            "webhooks itself after repeated delivery failures."
        ))
    return result


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


def _redis_status() -> dict:
    """Can this process reach the Celery broker (Redis)? Never returns the URL.

    Pings CELERY_BROKER_URL itself, not the Django cache, so it says nothing
    about the cache and the cache says nothing about the broker.
    """
    url = str(getattr(settings, "CELERY_BROKER_URL", "") or "")
    if not url:
        return {"status": DISABLED, "reason": "not_configured"}
    if not background_health_enabled():
        return {"status": NOT_VERIFIED, "reason": "probes_disabled"}
    if urlparse(url).scheme not in {"redis", "rediss"}:
        return {"status": NOT_VERIFIED, "reason": "non_redis_broker"}
    try:
        import redis

        client = redis.Redis.from_url(
            url,
            socket_connect_timeout=BROKER_PROBE_TIMEOUT_SECONDS,
            socket_timeout=BROKER_PROBE_TIMEOUT_SECONDS,
        )
        try:
            client.ping()
        finally:
            client.close()
    except Exception as exc:
        logger.warning("Redis broker probe failed: %s", type(exc).__name__)
        return {"status": DEGRADED, "reason": "unreachable"}
    return {"status": HEALTHY, "reason": ""}


def _ping_workers() -> list:
    """Broadcast one Celery ``ping`` over a dedicated, non-retrying connection.

    The pooled connection ``control.ping`` would otherwise use carries the
    worker settings (broker_connection_timeout, unlimited retries); this one is
    separate, so normal workers and producers are unaffected. ``ping`` is a
    control broadcast: it runs no task and touches no task queue.
    """
    from ecp_backend.celery import app

    options = dict(app.conf.broker_transport_options or {})
    options.update(
        max_retries=0,
        socket_connect_timeout=WORKER_PROBE_CONNECT_TIMEOUT_SECONDS,
        socket_timeout=WORKER_PROBE_SOCKET_TIMEOUT_SECONDS,
        retry_on_timeout=False,
    )
    connection = app.connection_for_write(
        url=str(settings.CELERY_BROKER_URL),
        connect_timeout=WORKER_PROBE_CONNECT_TIMEOUT_SECONDS,
        transport_options=options,
    )
    try:
        connection.ensure_connection(max_retries=0)
        return app.control.ping(
            timeout=WORKER_PROBE_REPLY_TIMEOUT_SECONDS, connection=connection
        ) or []
    finally:
        connection.release()


def _worker_status(broker=None) -> dict:
    """Do any Celery workers answer a broadcast ping right now?

    Proves a worker is consuming from the broker; says nothing about Beat.
    Only the number of replies is reported, never worker host names. The ping
    is skipped when the broker probe already showed the broker unreachable, and
    otherwise never holds the request longer than WORKER_PROBE_DEADLINE_SECONDS.
    """
    if not str(getattr(settings, "CELERY_BROKER_URL", "") or ""):
        return {"status": DISABLED, "reason": "not_configured", "responding": None}
    if not background_health_enabled():
        return {"status": NOT_VERIFIED, "reason": "probes_disabled", "responding": None}
    if broker is not None and broker.get("status") == DEGRADED:
        # Worker liveness cannot be observed through a broker this process
        # cannot reach; do not spend another connection proving it again.
        return {"status": NOT_VERIFIED, "reason": "broker_unreachable", "responding": None}
    if not _worker_probe_lock.acquire(blocking=False):
        return {"status": NOT_VERIFIED, "reason": "probe_in_progress", "responding": None}

    outcome = {}

    def probe():
        try:
            outcome["replies"] = _ping_workers()
        except Exception as exc:
            outcome["error"] = type(exc).__name__
        finally:
            _worker_probe_lock.release()

    thread = threading.Thread(target=probe, name="newsletter-worker-probe", daemon=True)
    thread.start()
    thread.join(WORKER_PROBE_DEADLINE_SECONDS)
    if thread.is_alive():
        logger.warning(
            "Celery worker ping exceeded %.1fs; reported as not verified",
            WORKER_PROBE_DEADLINE_SECONDS,
        )
        return {"status": NOT_VERIFIED, "reason": "probe_timeout", "responding": None}
    if "error" in outcome:
        logger.warning("Celery worker ping failed: %s", outcome["error"])
        return {"status": NOT_VERIFIED, "reason": "ping_failed", "responding": None}
    replies = outcome.get("replies") or []
    if not replies:
        return {"status": DEGRADED, "reason": "no_worker_replied", "responding": 0}
    return {"status": HEALTHY, "reason": "", "responding": len(replies)}


def _worker_label(worker) -> str:
    if worker["status"] == HEALTHY:
        return f"Healthy ({worker['responding']} responding)"
    if worker["status"] == DEGRADED:
        return "No worker responded"
    return "Not Verifiable"


def _background_processing_status(worker=None) -> dict:
    beat_schedule = getattr(settings, "CELERY_BEAT_SCHEDULE", {}) or {}
    scheduled_tasks = {
        item.get("task") for item in beat_schedule.values() if isinstance(item, dict)
    }
    return {
        "configuration": "Enabled" if bool(getattr(settings, "CELERY_BROKER_URL", "")) else "Not Configured",
        "live_worker_status": _worker_label(worker) if worker else "Not Verifiable",
        "newsletter_sync_scheduled": "newsletter.dispatch_due_sync_events" in scheduled_tasks,
        "native_broadcast_reconciliation_scheduled": (
            "newsletter.reconcile_native_scheduled_campaigns" in scheduled_tasks
        ),
    }


def _broadcast_send_status() -> dict:
    """ECP-owned sends still SENDING past the processing timeout.

    Covers a lost Mautic response and a worker that died after the provider
    boundary. Neither is ever retried, so an operator has to confirm the
    outcome in Mautic. Database reads only.
    """
    timeout = max(1, int(getattr(settings, "MAUTIC_SYNC_PROCESSING_TIMEOUT_SECONDS", 600)))
    sending = NewsletterCampaign.objects.filter(status=NewsletterCampaign.Status.SENDING)
    return {
        "sending": sending.count(),
        "needs_review": sending.filter(
            send_started_at__lte=timezone.now() - timedelta(seconds=timeout)
        ).count(),
    }


def _overdue_ecp_schedules(now) -> int:
    """ECP-owned schedules past due by longer than the dispatch task's stale
    window, i.e. later than the scheduler could still legitimately pick them up."""
    window = task_stale_after_seconds("newsletter.dispatch_due_scheduled_campaigns")
    if window is None:
        return 0
    return (
        NewsletterCampaign.objects.filter(
            status=NewsletterCampaign.Status.SCHEDULED,
            scheduled_at__lte=now - timedelta(seconds=window),
        )
        .exclude(schedule_owner=NewsletterCampaign.ScheduleOwner.MAUTIC)
        .count()
    )


def _mautic_background_evidence(config: dict, marketing_bridge: dict) -> dict:
    """Mautic cron/worker evidence for scheduler monitoring. Skips the request
    when Mautic is not configured or the bridge already proved unreachable, so
    an outage costs one timeout, not two."""
    if not config["configured"]:
        return {"mautic_report": None, "mautic_error": "not_configured"}
    if not marketing_bridge.get("available"):
        return {"mautic_report": None, "mautic_error": "mautic_unavailable"}
    report, error = fetch_mautic_background_report(marketing_bridge, client_factory=MauticClient)
    return {"mautic_report": report, "mautic_error": error}


def _health_summary(
    redis_probe, worker, scheduled_processing, broadcast_sends, native, *, now, beat=None
) -> dict:
    """One status per signal, each meaning exactly what its evidence proves."""
    sync_enabled = bool(getattr(settings, "MAUTIC_SYNC_ENABLED", False))
    warnings = []

    if redis_probe["status"] == DEGRADED:
        warnings.append("Redis broker is unreachable from the web process.")
    if worker["status"] == DEGRADED:
        warnings.append("No Celery worker answered a ping; background tasks are not being processed.")
    elif worker.get("reason") in {"probe_timeout", "ping_failed"}:
        warnings.append("The Celery worker check did not complete; worker status is not verified.")

    processing_status = scheduled_processing["status"]
    if processing_status == STALE:
        warnings.append("Scheduled newsletter tasks have not run recently; check Celery Beat and workers.")
    elif processing_status == DEGRADED:
        warnings.append("The latest run of a scheduled newsletter task failed.")
    elif processing_status == NOT_VERIFIED and scheduled_processing["reason"] == "no_run_recorded":
        warnings.append(
            "No scheduled newsletter task run has been recorded; Celery Beat or a worker may not be running."
        )

    overdue = _overdue_ecp_schedules(now) if sync_enabled else 0
    if overdue:
        warnings.append("ECP-scheduled broadcasts are overdue and have not been dispatched.")

    def level(problem, *, enabled=True):
        if not enabled:
            return DISABLED
        return DEGRADED if problem else HEALTHY

    components = {
        "redis": redis_probe,
        "celery_worker": worker,
        # Beat's own publish records (scheduler_monitoring), when available.
        "celery_beat": beat or {
            "status": NOT_VERIFIED,
            "reason": "no_independent_signal",
            "detail": (
                "Celery Beat keeps no state ECP can read. scheduled_processing shows "
                "whether Beat-scheduled tasks are reaching a worker."
            ),
        },
        "scheduled_processing": scheduled_processing,
        "ecp_scheduled_broadcasts": {
            "status": level(overdue, enabled=sync_enabled),
            "overdue": overdue,
        },
        "send_now_outcomes": {
            "status": level(broadcast_sends["needs_review"]),
            "sending": broadcast_sends["sending"],
            "needs_review": broadcast_sends["needs_review"],
        },
        "native_reconciliation": {
            "status": level(native["needs_attention"], enabled=sync_enabled),
            "due": native["due"],
            "needs_attention": native["needs_attention"],
        },
    }
    return {"components": components, "warnings": warnings}


def _native_broadcast_status() -> dict:
    """ECP-side view of natively scheduled broadcasts. Database reads only."""
    native = NewsletterCampaign.objects.filter(
        status=NewsletterCampaign.Status.SCHEDULED,
        schedule_owner=NewsletterCampaign.ScheduleOwner.MAUTIC,
    )
    attention = native.exclude(last_error="").count()
    return {
        "scheduled": native.count(),
        "due": native.filter(scheduled_at__lte=timezone.now()).count(),
        "needs_attention": attention,
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
    if webhook["registration"] in ("Not Registered", "Disabled in Mautic"):
        warnings.append(f"Mautic webhook: {webhook['registration']}.")
    if webhook.get("secret_matches") is False:
        warnings.append("The Mautic webhook secret does not match ECP's; deliveries will be rejected.")
    if webhook.get("missing_events") and webhook["registration"] == "Registered":
        warnings.append("The Mautic webhook is not subscribed to every supported event.")
    if webhook.get("delivery_host_private"):
        warnings.append(
            "The Mautic webhook delivers to a private address, which Mautic refuses unless it is "
            "allowlisted in webhook_allowed_private_addresses."
        )
    if webhook["last_received_at"] is None:
        warnings.append("Webhook receiver has not recorded a Mautic event yet.")
    if sync.get("current_warning"):
        warnings.append("Newsletter sync has failed or retrying events.")
    return warnings


def _truncate(value, limit=240) -> str:
    text = str(value or "")
    return text if len(text) <= limit else f"{text[:limit]}..."
