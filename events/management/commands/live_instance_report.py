"""
Read-only management command to report safe scale-in state for live-meeting
instances.

For each instance in the configured Auto Scaling Group it combines the ASG view
(lifecycle/health/scale-in protection) with the Redis-backed live-instance state
(heartbeat, active sessions/events, drain safety).

This command is strictly READ-ONLY: it only calls describe_auto_scaling_groups
and reads cache state. It never drains, terminates, or changes desired capacity.

Usage:
    python manage.py live_instance_report
    python manage.py live_instance_report --idle-seconds=600
    python manage.py live_instance_report --json
"""

import json

import boto3
from django.conf import settings
from django.core.management.base import BaseCommand

from events.services.live_instance_state import (
    get_instance_state,
    is_instance_safe_to_drain,
)


class Command(BaseCommand):
    help = "Read-only report of safe scale-in state for live-meeting ASG instances."

    def add_arguments(self, parser):
        parser.add_argument(
            "--idle-seconds",
            type=int,
            default=int(getattr(settings, "LIVE_MEETING_DRAIN_IDLE_SECONDS", 300)),
            help=(
                "Idle threshold (seconds) used to judge drain safety. "
                "Defaults to settings.LIVE_MEETING_DRAIN_IDLE_SECONDS."
            ),
        )
        parser.add_argument(
            "--json",
            action="store_true",
            dest="as_json",
            help="Print a JSON list of instance states instead of a text table.",
        )

    def handle(self, *args, **options):
        idle_seconds = options["idle_seconds"]
        as_json = options["as_json"]

        asg_name = getattr(settings, "LIVE_MEETING_ASG_NAME", None)
        region = getattr(settings, "LIVE_MEETING_ASG_REGION", None)

        if not asg_name:
            self.stderr.write(
                self.style.ERROR("LIVE_MEETING_ASG_NAME is not configured; nothing to report.")
            )
            return

        # ------------------------------------------------------------------
        # Read the ASG (read-only). Handle every failure mode gracefully.
        # ------------------------------------------------------------------
        asg_instances = []
        try:
            client = boto3.client("autoscaling", region_name=region)
            resp = client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
            groups = resp.get("AutoScalingGroups", []) or []
            if not groups:
                self.stderr.write(
                    self.style.ERROR(
                        "Auto Scaling Group '{0}' not found in region '{1}'.".format(
                            asg_name, region
                        )
                    )
                )
                return
            asg_instances = groups[0].get("Instances", []) or []
        except Exception as exc:
            self.stderr.write(
                self.style.ERROR(
                    "Failed to describe ASG '{0}' in region '{1}': {2}".format(
                        asg_name, region, exc
                    )
                )
            )
            return

        # ------------------------------------------------------------------
        # Combine ASG view with Redis live-instance state for each instance.
        # ------------------------------------------------------------------
        rows = []
        for asg_instance in asg_instances:
            instance_id = asg_instance.get("InstanceId")
            row = {
                "instance_id": instance_id,
                "lifecycle_state": asg_instance.get("LifecycleState"),
                "health_status": asg_instance.get("HealthStatus"),
                "protected_from_scale_in": asg_instance.get("ProtectedFromScaleIn"),
                "heartbeat": None,
                "heartbeat_age_seconds": None,
                "draining": False,
                "active_sessions": 0,
                "active_events": [],
                "event_active_sessions": {},
                "last_active_at": None,
                "safe_to_drain": False,
                "reasons": [],
            }

            try:
                state = get_instance_state(instance_id)
                row["heartbeat"] = state.get("heartbeat")
                row["heartbeat_age_seconds"] = state.get("heartbeat_age_seconds")
                row["draining"] = state.get("draining")
                row["active_sessions"] = state.get("active_sessions")
                row["active_events"] = state.get("active_events")
                row["event_active_sessions"] = state.get("event_active_sessions", {})
                row["last_active_at"] = state.get("last_active_at")

                safety = is_instance_safe_to_drain(instance_id, idle_seconds=idle_seconds)
                row["safe_to_drain"] = safety.get("safe", False)
                row["reasons"] = safety.get("reasons", [])
            except Exception as exc:
                # get_*/is_* helpers are already defensive, but stay safe here too.
                row["reasons"] = ["error reading instance state: {0}".format(exc)]

            rows.append(row)

        # ------------------------------------------------------------------
        # Output.
        # ------------------------------------------------------------------
        if as_json:
            self.stdout.write(json.dumps(rows, indent=2, default=str))
            return

        self._print_text_report(asg_name, region, idle_seconds, rows)

    def _print_text_report(self, asg_name, region, idle_seconds, rows):
        self.stdout.write("Live instance report")
        self.stdout.write("  ASG:          {0}".format(asg_name))
        self.stdout.write("  Region:       {0}".format(region))
        self.stdout.write("  Idle seconds: {0}".format(idle_seconds))
        self.stdout.write("  Instances:    {0}".format(len(rows)))
        self.stdout.write("")

        if not rows:
            self.stdout.write("No instances found in the ASG.")
            return

        for row in rows:
            safe = row.get("safe_to_drain")
            header = "Instance {0}".format(row.get("instance_id"))
            if safe:
                self.stdout.write(self.style.SUCCESS(header + "  [SAFE TO DRAIN]"))
            else:
                self.stdout.write(self.style.WARNING(header + "  [NOT SAFE TO DRAIN]"))

            self.stdout.write("  LifecycleState:        {0}".format(row.get("lifecycle_state")))
            self.stdout.write("  HealthStatus:          {0}".format(row.get("health_status")))
            self.stdout.write(
                "  ProtectedFromScaleIn:  {0}".format(row.get("protected_from_scale_in"))
            )
            self.stdout.write("  Heartbeat:             {0}".format(row.get("heartbeat")))
            self.stdout.write(
                "  HeartbeatAgeSeconds:   {0}".format(row.get("heartbeat_age_seconds"))
            )
            self.stdout.write("  Draining:              {0}".format(row.get("draining")))
            self.stdout.write("  ActiveSessions:        {0}".format(row.get("active_sessions")))
            self.stdout.write("  ActiveEvents:          {0}".format(row.get("active_events")))
            self.stdout.write(
                "  EventActiveSessions:   {0}".format(row.get("event_active_sessions"))
            )
            self.stdout.write("  LastActiveAt:          {0}".format(row.get("last_active_at")))
            self.stdout.write("  SafeToDrain:           {0}".format(safe))
            reasons = row.get("reasons") or []
            if reasons:
                self.stdout.write("  Reasons:")
                for reason in reasons:
                    self.stdout.write("    - {0}".format(reason))
            else:
                self.stdout.write("  Reasons:               (none)")
            self.stdout.write("")
