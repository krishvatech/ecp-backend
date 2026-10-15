"""Independent alerting for Marketing Hub background health (B14).

Turns one B10 scheduler-monitoring report (``collect_scheduler_monitoring``)
into CloudWatch metrics. No second health model: every value is read from
the report's own component statuses. CloudWatch alarms then do the
alerting, deduplication and recovery (an alarm notifies only when its state
changes), and a missing heartbeat metric shows that the monitor itself
stopped. See deploy/monitoring/README.md.

Metrics (namespace ``HEALTH_ALERTING_NAMESPACE``), all with an
``Environment`` dimension and none with an instance id, so samples from
several backend instances fold into one series and one alarm:

* ``MonitorSample`` = 1 on every completed observation (heartbeat).
* ``OverallStatusCode`` = the check_background_health exit code (0-3).
* Per component (``Component`` dimension), each 0 or 1:
  ``ComponentUnhealthy``; ``ComponentDegraded``, Warning *or* Unhealthy, so
  a warning that escalates keeps its alarm instead of reporting a false
  recovery; and ``ComponentUnknown``. A Disabled component reports 0
  everywhere: intentionally not in use is not a fault.

Values describe shared state (Redis, Beat evidence, Mautic), not instances,
so the alarms use the Maximum statistic: two instances observing the same
outage give one alarm, never two Beat schedulers.
"""

from __future__ import annotations

import logging

from django.conf import settings

from .scheduler_monitoring import DISABLED, EXIT_CODES, HEALTHY, UNHEALTHY, UNKNOWN, WARNING

logger = logging.getLogger(__name__)

DEFAULT_NAMESPACE = "ECP/MarketingHub"
COMPONENTS = ("celery_beat", "scheduled_tasks", "celery_worker", "redis_broker", "mautic_cron", "mautic_worker")

#: Exit code of publish_background_health when no sample could be produced
#: or published: a monitoring failure, distinct from every health result.
MONITOR_FAILED_EXIT_CODE = 4


class PublishError(Exception):
    """Metrics could not be delivered to the alerting backend."""


def alerting_namespace() -> str:
    return str(getattr(settings, "HEALTH_ALERTING_NAMESPACE", "") or DEFAULT_NAMESPACE)


def alerting_environment(value=None) -> str:
    value = str(value or getattr(settings, "HEALTH_ALERTING_ENVIRONMENT", "") or "development")
    # A dimension value: keep it short and plain.
    return "".join(ch for ch in value if ch.isalnum() or ch in "-_.")[:64] or "development"


def metric_data(report: dict, *, environment: str) -> list[dict]:
    """CloudWatch MetricData for one report. Pure; reads only statuses."""
    timestamp = report.get("observed_at")
    base = [{"Name": "Environment", "Value": environment}]

    def datum(name, value, component=None):
        dimensions = list(base)
        if component:
            dimensions.append({"Name": "Component", "Value": component})
        item = {"MetricName": name, "Dimensions": dimensions, "Value": float(value), "Unit": "Count"}
        if timestamp:
            item["Timestamp"] = timestamp
        return item

    components = report.get("components") or {}
    data = [
        datum("MonitorSample", 1),
        datum("OverallStatusCode", EXIT_CODES.get(report.get("status"), EXIT_CODES[UNKNOWN])),
    ]
    for key in COMPONENTS:
        status = (components.get(key) or {}).get("status", UNKNOWN)
        if status == DISABLED:
            status = HEALTHY
        data.append(datum("ComponentUnhealthy", status == UNHEALTHY, key))
        data.append(datum("ComponentDegraded", status in (WARNING, UNHEALTHY), key))
        data.append(datum("ComponentUnknown", status == UNKNOWN, key))
    return data


def summary(report: dict) -> dict:
    """The part of a report worth printing to SSM output: statuses and
    reasons only (no hosts, URLs or credentials)."""
    components = report.get("components") or {}
    return {
        "status": report.get("status"),
        "observed_at": report.get("observed_at"),
        "components": {
            key: {
                "status": (components.get(key) or {}).get("status"),
                "reason": (components.get(key) or {}).get("reason", ""),
            }
            for key in COMPONENTS
        },
    }


def publish_cloudwatch(data: list[dict], *, namespace: str, client=None) -> None:
    """Send metric data with bounded time and no long retry loop."""
    try:
        if client is None:
            import boto3
            from botocore.config import Config

            region = getattr(settings, "HEALTH_ALERTING_AWS_REGION", "") or None
            client = boto3.client(
                "cloudwatch",
                region_name=region,
                config=Config(connect_timeout=3, read_timeout=5, retries={"max_attempts": 2, "mode": "standard"}),
            )
        # PutMetricData accepts up to 1000 values per call; this sends 20.
        client.put_metric_data(Namespace=namespace, MetricData=data)
    except Exception as exc:
        # The type only: AWS errors can carry account or request details.
        raise PublishError(type(exc).__name__) from exc


__all__ = [
    "COMPONENTS",
    "MONITOR_FAILED_EXIT_CODE",
    "PublishError",
    "alerting_environment",
    "alerting_namespace",
    "metric_data",
    "publish_cloudwatch",
    "summary",
]
