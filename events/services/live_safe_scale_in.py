"""Safe scale-in planner and execution helpers for live-meeting instances.

The planner half of this module (build_safe_scale_in_plan and the describe_*
helpers) is strictly read-only: it only calculates and reports what a safe
scale-in would do.

The execution half (deregister_instance_from_target_groups,
terminate_instance_decrement_desired, execute_safe_scale_in_one_step,
continue_safe_scale_in_draining_instances) DOES mutate AWS/Redis, but only ever
when called explicitly with dry_run=False. Nothing in this module runs
automatically: no Celery task, scheduler, or other module invokes these
functions yet. The default for every execution entrypoint is dry_run=True.

Every function is defensive and never raises into its caller; failures are
captured in the returned dict and logged.
"""

import logging

import boto3
from django.conf import settings

from events.services.live_meeting_capacity import (
    calculate_required_capacity,
    get_current_asg_capacity,
)
from events.services.live_instance_state import (
    get_instance_state,
    is_instance_safe_to_drain,
    mark_instance_draining,
)

logger = logging.getLogger(__name__)


def get_asg_instances():
    """Return the ASG's instances as a list of plain dicts. Read-only.

    Each dict has: instance_id, lifecycle_state, health_status,
    protected_from_scale_in. Returns an empty list if the ASG is not found or
    on any error (never raises).
    """
    asg_name = getattr(settings, "LIVE_MEETING_ASG_NAME", None)
    region = getattr(settings, "LIVE_MEETING_ASG_REGION", None)

    if not asg_name:
        logger.warning("live_safe_scale_in: LIVE_MEETING_ASG_NAME is not configured")
        return []

    try:
        client = boto3.client("autoscaling", region_name=region)
        resp = client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        groups = resp.get("AutoScalingGroups", []) or []
        if not groups:
            logger.warning(
                "live_safe_scale_in: ASG not found name=%s region=%s", asg_name, region
            )
            return []

        instances = []
        for instance in groups[0].get("Instances", []) or []:
            instances.append(
                {
                    "instance_id": instance.get("InstanceId"),
                    "lifecycle_state": instance.get("LifecycleState"),
                    "health_status": instance.get("HealthStatus"),
                    "protected_from_scale_in": instance.get("ProtectedFromScaleIn"),
                }
            )
        return instances
    except Exception:
        logger.warning(
            "live_safe_scale_in: failed describing ASG name=%s region=%s",
            asg_name,
            region,
            exc_info=True,
        )
        return []


def get_asg_target_group_arns():
    """Return the ASG's attached ALB target group ARNs. Read-only.

    Returns an empty list if the ASG is not found, has no target groups, or on
    any error (never raises).
    """
    asg_name = getattr(settings, "LIVE_MEETING_ASG_NAME", None)
    region = getattr(settings, "LIVE_MEETING_ASG_REGION", None)

    if not asg_name:
        logger.warning("live_safe_scale_in: LIVE_MEETING_ASG_NAME is not configured")
        return []

    try:
        client = boto3.client("autoscaling", region_name=region)
        resp = client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        groups = resp.get("AutoScalingGroups", []) or []
        if not groups:
            logger.warning(
                "live_safe_scale_in: ASG not found name=%s region=%s", asg_name, region
            )
            return []
        return list(groups[0].get("TargetGroupARNs", []) or [])
    except Exception:
        logger.warning(
            "live_safe_scale_in: failed reading target groups for ASG name=%s region=%s",
            asg_name,
            region,
            exc_info=True,
        )
        return []


def get_alb_target_health(instance_id, target_group_arns=None):
    """Return the instance's health across the ASG's ALB target groups. Read-only.

    For each target group ARN, calls describe_target_health for this instance and
    collects target_group_arn, state, reason, description, and port. Defensive:
    never raises. If a target group lookup fails or the instance is not registered,
    a clear error/empty entry is included instead.
    """
    if target_group_arns is None:
        target_group_arns = get_asg_target_group_arns()

    results = []
    region = getattr(settings, "LIVE_MEETING_ASG_REGION", None)

    if not target_group_arns:
        return results

    try:
        client = boto3.client("elbv2", region_name=region)
    except Exception:
        logger.warning(
            "live_safe_scale_in: failed creating elbv2 client region=%s", region, exc_info=True
        )
        for arn in target_group_arns:
            results.append(
                {
                    "target_group_arn": arn,
                    "state": None,
                    "reason": "error",
                    "description": "failed creating elbv2 client",
                    "port": None,
                }
            )
        return results

    for arn in target_group_arns:
        try:
            resp = client.describe_target_health(
                TargetGroupArn=arn,
                Targets=[{"Id": instance_id}],
            )
            descriptions = resp.get("TargetHealthDescriptions", []) or []
            if not descriptions:
                results.append(
                    {
                        "target_group_arn": arn,
                        "state": None,
                        "reason": "not_registered",
                        "description": "instance not registered in target group",
                        "port": None,
                    }
                )
                continue

            for desc in descriptions:
                health = desc.get("TargetHealth", {}) or {}
                target = desc.get("Target", {}) or {}
                results.append(
                    {
                        "target_group_arn": arn,
                        "state": health.get("State"),
                        "reason": health.get("Reason"),
                        "description": health.get("Description"),
                        "port": target.get("Port"),
                    }
                )
        except Exception as exc:
            logger.warning(
                "live_safe_scale_in: describe_target_health failed instance=%s arn=%s",
                instance_id,
                arn,
                exc_info=True,
            )
            results.append(
                {
                    "target_group_arn": arn,
                    "state": None,
                    "reason": "error",
                    "description": "describe_target_health failed: {0}".format(exc),
                    "port": None,
                }
            )

    return results


def _safe_required():
    try:
        return calculate_required_capacity()
    except Exception:
        logger.warning("live_safe_scale_in: calculate_required_capacity failed", exc_info=True)
        return None


def _safe_current():
    try:
        return get_current_asg_capacity()
    except Exception:
        logger.warning("live_safe_scale_in: get_current_asg_capacity failed", exc_info=True)
        return None


def build_safe_scale_in_plan(idle_seconds=None):
    """Compute (but never execute) a safe scale-in plan.

    Returns a dict describing current vs required capacity, every instance's
    drain-safety state, the safe candidates, and which candidates *would* be
    terminated. This function performs no mutations.
    """
    if idle_seconds is None:
        idle_seconds = int(getattr(settings, "LIVE_MEETING_DRAIN_IDLE_SECONDS", 300))

    one_at_a_time = bool(getattr(settings, "LIVE_MEETING_SCALE_IN_ONE_INSTANCE_AT_A_TIME", True))

    required = _safe_required()
    current = _safe_current()
    asg_instances = get_asg_instances()
    target_group_arns = get_asg_target_group_arns()

    current_desired = 0
    if isinstance(current, dict):
        try:
            current_desired = int(current.get("desired", 0))
        except (TypeError, ValueError):
            current_desired = 0

    required_desired = 0
    if isinstance(required, dict):
        try:
            required_desired = int(required.get("desired_instances", 0))
        except (TypeError, ValueError):
            required_desired = 0

    over_capacity = max(0, current_desired - required_desired)

    instances = []
    safe_candidates = []
    for asg_instance in asg_instances:
        instance_id = asg_instance.get("instance_id")
        lifecycle_state = asg_instance.get("lifecycle_state")
        health_status = asg_instance.get("health_status")

        try:
            state = get_instance_state(instance_id)
        except Exception:
            logger.warning(
                "live_safe_scale_in: get_instance_state failed for %s", instance_id, exc_info=True
            )
            state = {}

        try:
            safety = is_instance_safe_to_drain(instance_id, idle_seconds=idle_seconds)
        except Exception:
            logger.warning(
                "live_safe_scale_in: is_instance_safe_to_drain failed for %s",
                instance_id,
                exc_info=True,
            )
            safety = {"safe": False, "reasons": ["error evaluating drain safety"]}

        safe_to_drain = bool(safety.get("safe", False))
        reasons = safety.get("reasons", [])

        entry = {
            "instance_id": instance_id,
            "lifecycle_state": lifecycle_state,
            "health_status": health_status,
            "protected_from_scale_in": asg_instance.get("protected_from_scale_in"),
            "safe_to_drain": safe_to_drain,
            "reasons": reasons,
            "state": state,
            "alb_target_health": get_alb_target_health(instance_id, target_group_arns),
        }
        instances.append(entry)

        if safe_to_drain and lifecycle_state == "InService" and health_status == "Healthy":
            safe_candidates.append(entry)

    # Only plan terminations when actually over capacity. Within that, one-at-a-time
    # mode picks a single candidate; otherwise pick up to `over_capacity` of them.
    if over_capacity > 0 and safe_candidates:
        if one_at_a_time:
            planned_terminations = safe_candidates[:1]
        else:
            planned_terminations = safe_candidates[:over_capacity]
    else:
        planned_terminations = []

    return {
        "mode": "dry_run",
        "current": current,
        "required": required,
        "over_capacity": over_capacity,
        "target_group_arns": target_group_arns,
        "instances": instances,
        "safe_candidates": safe_candidates,
        "planned_terminations": planned_terminations,
        "can_scale_in": len(planned_terminations) > 0,
    }


# ---------------------------------------------------------------------------
# Execution helpers
#
# Everything below this line can mutate AWS / Redis. None of it runs
# automatically: these functions are only ever reached via an explicit call, and
# every entrypoint defaults to dry_run=True. No Celery task or other module wires
# these in yet.
# ---------------------------------------------------------------------------

# The only ALB target state we accept as fully drained for FINAL termination.
# "draining" still has in-flight connections and "unavailable" is ambiguous, so
# neither is safe to terminate on — we require the target to be fully "unused".
_ALB_TERMINATION_READY_STATE = "unused"


def all_alb_targets_unused_or_draining_done(instance_id, target_group_arns=None):
    """Report whether an instance is fully drained out of every ALB target group.

    Read-only. Returns ``{"ready": bool, "states": [...]}``. Final termination
    readiness is strict: ``ready`` is True only when the states list is non-empty
    and EVERY target-group state is exactly "unused". A "draining" target still
    has in-flight connections and "unavailable" is ambiguous, so neither counts as
    ready. Never raises.
    """
    try:
        health = get_alb_target_health(instance_id, target_group_arns)
    except Exception:
        logger.warning(
            "live_safe_scale_in: ALB health read failed for %s", instance_id, exc_info=True
        )
        return {"ready": False, "states": []}

    states = [entry.get("state") for entry in health]
    ready = bool(states) and all(state == _ALB_TERMINATION_READY_STATE for state in states)
    return {"ready": ready, "states": states}


def _redis_idle(instance_id):
    """Return (idle, state): idle is True when the instance has no active
    sessions and no active events. Never raises.

    Used as the *post-drain* safety check. We can't reuse is_instance_safe_to_drain
    here because that treats a set draining flag as unsafe, and by this point we
    have intentionally marked the instance draining ourselves.
    """
    try:
        state = get_instance_state(instance_id)
    except Exception:
        logger.warning(
            "live_safe_scale_in: get_instance_state failed for %s", instance_id, exc_info=True
        )
        return False, {}

    active_events = state.get("active_events") or []
    try:
        idle = int(state.get("active_sessions", 0) or 0) == 0 and not active_events
    except (TypeError, ValueError):
        idle = False
    return idle, state


def _desired_ints(current, required):
    """Extract (current_desired, required_desired) as ints, or None when missing."""
    current_desired = None
    if isinstance(current, dict):
        try:
            current_desired = int(current.get("desired"))
        except (TypeError, ValueError):
            current_desired = None

    required_desired = None
    if isinstance(required, dict):
        try:
            required_desired = int(required.get("desired_instances"))
        except (TypeError, ValueError):
            required_desired = None

    return current_desired, required_desired


def deregister_instance_from_target_groups(instance_id, target_group_arns=None):
    """Deregister an instance from every ASG target group. MUTATION.

    Only call this from an explicit execution function. Never raises; per-target
    errors are captured in the returned dict.
    """
    if target_group_arns is None:
        target_group_arns = get_asg_target_group_arns()

    region = getattr(settings, "LIVE_MEETING_ASG_REGION", None)
    results = []

    if not target_group_arns:
        return {"instance_id": instance_id, "results": results}

    try:
        client = boto3.client("elbv2", region_name=region)
    except Exception:
        logger.warning(
            "live_safe_scale_in: failed creating elbv2 client region=%s", region, exc_info=True
        )
        return {
            "instance_id": instance_id,
            "error": "failed creating elbv2 client",
            "results": results,
        }

    for arn in target_group_arns:
        try:
            client.deregister_targets(TargetGroupArn=arn, Targets=[{"Id": instance_id}])
            logger.warning(
                "live_safe_scale_in: deregistered instance=%s from target group=%s",
                instance_id,
                arn,
            )
            results.append({"target_group_arn": arn, "deregistered": True})
        except Exception as exc:
            logger.warning(
                "live_safe_scale_in: deregister_targets failed instance=%s arn=%s",
                instance_id,
                arn,
                exc_info=True,
            )
            results.append(
                {"target_group_arn": arn, "deregistered": False, "error": str(exc)}
            )

    return {"instance_id": instance_id, "results": results}


def terminate_instance_decrement_desired(instance_id):
    """Terminate an instance and decrement the ASG desired capacity. MUTATION.

    Only call this from an explicit execution function. Never raises; errors are
    captured in the returned dict.
    """
    region = getattr(settings, "LIVE_MEETING_ASG_REGION", None)

    try:
        client = boto3.client("autoscaling", region_name=region)
        resp = client.terminate_instance_in_auto_scaling_group(
            InstanceId=instance_id,
            ShouldDecrementDesiredCapacity=True,
        )
        activity = resp.get("Activity", {}) or {}
        logger.warning(
            "live_safe_scale_in: terminated instance=%s (decrement desired) activity=%s",
            instance_id,
            activity.get("ActivityId"),
        )
        return {
            "instance_id": instance_id,
            "terminated": True,
            "activity_id": activity.get("ActivityId"),
            "status": activity.get("StatusCode"),
        }
    except Exception as exc:
        logger.warning(
            "live_safe_scale_in: terminate_instance_in_auto_scaling_group failed instance=%s",
            instance_id,
            exc_info=True,
        )
        return {"instance_id": instance_id, "terminated": False, "error": str(exc)}


def execute_safe_scale_in_one_step(reason="manual", dry_run=True, idle_seconds=None):
    """Controlled single-step safe scale-in. Defaults to dry_run=True.

    Picks the first planned termination from a freshly built plan, re-validates
    safety, and (only when dry_run=False) marks the instance draining, deregisters
    it from the ALB, then terminates it once it has drained out. This function
    never blocks waiting for draining to finish — if the target has not drained
    yet it returns an "instance_draining_wait_required" result so a later run
    (manual or via continue_safe_scale_in_draining_instances) can finish the job.
    Never raises.
    """
    # Service-level guard: refuse any real mutation when the feature flag is off,
    # even if a caller (e.g. a future Celery task) invokes this with dry_run=False.
    if not dry_run and not getattr(settings, "LIVE_MEETING_SAFE_SCALE_IN_ENABLED", False):
        return {
            "changed": False,
            "reason": "safe_scale_in_disabled",
            "message": "LIVE_MEETING_SAFE_SCALE_IN_ENABLED is False",
        }

    plan = build_safe_scale_in_plan(idle_seconds=idle_seconds)
    planned = plan.get("planned_terminations", [])
    if not planned:
        return {"changed": False, "reason": "no_planned_terminations", "plan": plan}

    candidate = planned[0]
    instance_id = candidate.get("instance_id")
    target_group_arns = plan.get("target_group_arns", [])

    # Re-check capacity with a fresh read before mutating anything.
    current = _safe_current()
    required = _safe_required()
    current_desired, required_desired = _desired_ints(current, required)
    if current_desired is None or required_desired is None or current_desired <= required_desired:
        return {
            "changed": False,
            "reason": "not_over_capacity",
            "instance_id": instance_id,
            "current": current,
            "required": required,
            "plan": plan,
        }

    # Re-check drain safety (instance is still a fresh, non-draining candidate here).
    try:
        safety = is_instance_safe_to_drain(instance_id, idle_seconds=idle_seconds)
    except Exception:
        safety = {"safe": False, "reasons": ["error evaluating drain safety"]}
    if not safety.get("safe"):
        return {
            "changed": False,
            "reason": "not_safe_to_drain",
            "instance_id": instance_id,
            "safety": safety,
            "plan": plan,
        }

    if candidate.get("lifecycle_state") != "InService":
        return {
            "changed": False,
            "reason": "not_in_service",
            "instance_id": instance_id,
            "plan": plan,
        }
    if candidate.get("health_status") != "Healthy":
        return {
            "changed": False,
            "reason": "not_healthy",
            "instance_id": instance_id,
            "plan": plan,
        }

    if dry_run:
        return {
            "changed": False,
            "dry_run": True,
            "would_drain_instance": instance_id,
            "plan": plan,
        }

    # ---- Execution (dry_run=False) ----
    drain_result = mark_instance_draining(instance_id, True)
    deregister_result = deregister_instance_from_target_groups(instance_id, target_group_arns)

    # Re-read ALB health immediately (no long blocking wait here).
    alb_ready = all_alb_targets_unused_or_draining_done(instance_id, target_group_arns)
    target_health = get_alb_target_health(instance_id, target_group_arns)

    if not alb_ready.get("ready"):
        return {
            "changed": False,
            "reason": "instance_draining_wait_required",
            "instance_id": instance_id,
            "draining": drain_result,
            "deregister": deregister_result,
            "target_health": target_health,
        }

    # ALB has drained out. Final Redis idleness check (sessions/events) before kill.
    idle, state = _redis_idle(instance_id)
    if not idle:
        return {
            "changed": False,
            "reason": "not_safe_after_drain",
            "instance_id": instance_id,
            "draining": drain_result,
            "deregister": deregister_result,
            "target_health": target_health,
            "state": state,
        }

    terminate_result = terminate_instance_decrement_desired(instance_id)
    return {
        "changed": bool(terminate_result.get("terminated")),
        "instance_id": instance_id,
        "draining": drain_result,
        "deregister": deregister_result,
        "target_health": target_health,
        "terminate": terminate_result,
    }


def continue_safe_scale_in_draining_instances(reason="manual", idle_seconds=None, dry_run=True):
    """Advance at most one already-draining instance toward termination.

    Scans the ASG for an instance whose Redis state says draining=True, then for
    that single instance checks ALB target health and Redis idleness. When
    dry_run=False and the ALB target is "unused" and Redis is idle, it terminates
    the exact instance (decrementing desired). Processes only one instance per
    call. Never raises.
    """
    # Service-level guard: refuse any real mutation when the feature flag is off,
    # even if a caller (e.g. a future Celery task) invokes this with dry_run=False.
    if not dry_run and not getattr(settings, "LIVE_MEETING_SAFE_SCALE_IN_ENABLED", False):
        return {
            "changed": False,
            "reason": "safe_scale_in_disabled",
            "message": "LIVE_MEETING_SAFE_SCALE_IN_ENABLED is False",
        }

    if idle_seconds is None:
        idle_seconds = int(getattr(settings, "LIVE_MEETING_DRAIN_IDLE_SECONDS", 300))

    target_group_arns = get_asg_target_group_arns()
    asg_instances = get_asg_instances()

    for asg_instance in asg_instances:
        instance_id = asg_instance.get("instance_id")

        try:
            state = get_instance_state(instance_id)
        except Exception:
            logger.warning(
                "live_safe_scale_in: get_instance_state failed for %s", instance_id, exc_info=True
            )
            continue

        if not state.get("draining"):
            continue

        # Found a draining instance — process exactly this one and return.
        idle, _ = _redis_idle(instance_id)
        alb = all_alb_targets_unused_or_draining_done(instance_id, target_group_arns)
        target_health = get_alb_target_health(instance_id, target_group_arns)

        states = alb.get("states", [])
        alb_unused = bool(states) and all(s == "unused" for s in states)

        report = {
            "instance_id": instance_id,
            "lifecycle_state": asg_instance.get("lifecycle_state"),
            "health_status": asg_instance.get("health_status"),
            "redis_idle": idle,
            "alb_ready": alb.get("ready"),
            "alb_unused": alb_unused,
            "target_health": target_health,
        }

        # Fresh capacity re-check: never terminate unless the ASG is still over
        # capacity right now, even if this instance has fully drained.
        current = _safe_current()
        required = _safe_required()
        current_desired, required_desired = _desired_ints(current, required)
        over_capacity = (
            current_desired > required_desired
            if (current_desired is not None and required_desired is not None)
            else None
        )

        if dry_run:
            would_terminate = bool(idle and alb_unused and over_capacity)
            return {
                "changed": False,
                "dry_run": True,
                "would_terminate_instance": instance_id if would_terminate else None,
                "current": current,
                "required": required,
                "over_capacity": over_capacity,
                "current_desired": current_desired,
                "required_desired": required_desired,
                "instance": report,
            }

        if idle and alb_unused:
            if current_desired is None or required_desired is None:
                return {
                    "changed": False,
                    "reason": "capacity_unknown",
                    "instance_id": instance_id,
                    "current": current,
                    "required": required,
                    "instance": report,
                }

            if current_desired <= required_desired:
                return {
                    "changed": False,
                    "reason": "not_over_capacity",
                    "instance_id": instance_id,
                    "current": current,
                    "required": required,
                    "instance": report,
                }

            terminate_result = terminate_instance_decrement_desired(instance_id)
            return {
                "changed": bool(terminate_result.get("terminated")),
                "instance_id": instance_id,
                "current": current,
                "required": required,
                "instance": report,
                "terminate": terminate_result,
            }

        return {
            "changed": False,
            "reason": "instance_draining_wait_required",
            "instance_id": instance_id,
            "instance": report,
        }

    return {"changed": False, "reason": "no_draining_instances"}
