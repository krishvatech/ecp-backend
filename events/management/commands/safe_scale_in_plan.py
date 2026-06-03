"""
Read-only management command that reports a safe scale-in plan.

It calls build_safe_scale_in_plan() and prints what *would* happen. It never
mutates AWS, the ASG, ALB, Redis, or any instance.

Usage:
    python manage.py safe_scale_in_plan
    python manage.py safe_scale_in_plan --idle-seconds=600
    python manage.py safe_scale_in_plan --json
"""

import json

from django.conf import settings
from django.core.management.base import BaseCommand

from events.services.live_safe_scale_in import build_safe_scale_in_plan


class Command(BaseCommand):
    help = "Read-only report of a safe scale-in plan (dry run only; no mutations)."

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
            help="Print the full plan as JSON instead of a text report.",
        )

    def handle(self, *args, **options):
        idle_seconds = options["idle_seconds"]
        as_json = options["as_json"]

        plan = build_safe_scale_in_plan(idle_seconds=idle_seconds)

        if as_json:
            self.stdout.write(json.dumps(plan, indent=2, default=str))
            return

        self._print_text_report(idle_seconds, plan)

    def _print_text_report(self, idle_seconds, plan):
        current = plan.get("current") or {}
        required = plan.get("required") or {}

        current_desired = current.get("desired") if isinstance(current, dict) else None
        required_desired = (
            required.get("desired_instances") if isinstance(required, dict) else None
        )

        self.stdout.write("Safe scale-in plan (DRY RUN — no changes made)")
        self.stdout.write("  Mode:               {0}".format(plan.get("mode")))
        self.stdout.write("  Idle seconds:       {0}".format(idle_seconds))
        self.stdout.write("  Current desired:    {0}".format(current_desired))
        self.stdout.write("  Required desired:   {0}".format(required_desired))
        self.stdout.write("  Over capacity:      {0}".format(plan.get("over_capacity")))
        self.stdout.write("  Can scale in:       {0}".format(plan.get("can_scale_in")))
        self.stdout.write("  Target groups:      {0}".format(len(plan.get("target_group_arns", []))))
        self.stdout.write("")

        instances = plan.get("instances", [])
        self.stdout.write("Instances ({0}):".format(len(instances)))
        if not instances:
            self.stdout.write("  (none)")
        for entry in instances:
            safe = entry.get("safe_to_drain")
            marker = "SAFE" if safe else "NOT SAFE"
            line = "  - {0}  [{1}]  lifecycle={2} health={3} protected={4}".format(
                entry.get("instance_id"),
                marker,
                entry.get("lifecycle_state"),
                entry.get("health_status"),
                entry.get("protected_from_scale_in"),
            )
            if safe:
                self.stdout.write(self.style.SUCCESS(line))
            else:
                self.stdout.write(self.style.WARNING(line))
                reasons = entry.get("reasons") or []
                for reason in reasons:
                    self.stdout.write("      reason: {0}".format(reason))

            for health in entry.get("alb_target_health") or []:
                self.stdout.write(
                    "      alb: state={0} reason={1} port={2}".format(
                        health.get("state"),
                        health.get("reason"),
                        health.get("port"),
                    )
                )
        self.stdout.write("")

        safe_candidates = plan.get("safe_candidates", [])
        self.stdout.write("Safe candidates ({0}):".format(len(safe_candidates)))
        if not safe_candidates:
            self.stdout.write("  (none)")
        for entry in safe_candidates:
            self.stdout.write("  - {0}".format(entry.get("instance_id")))
        self.stdout.write("")

        planned = plan.get("planned_terminations", [])
        self.stdout.write("Planned terminations ({0}):".format(len(planned)))
        if not planned:
            self.stdout.write("  (none — nothing would be terminated)")
        for entry in planned:
            self.stdout.write(
                self.style.WARNING("  - {0} (would be drained/terminated)".format(
                    entry.get("instance_id")
                ))
            )
