"""
Manual command to run the safe scale-in execution functions.

SAFETY: this command is dry-run by default. It only mutates AWS/Redis when
``--execute`` is passed explicitly. Nothing here runs automatically — there is no
Celery task or scheduler wiring; a human must invoke it.

Usage:
    # Dry run (default) — initiate-step planner, no mutations:
    python manage.py safe_scale_in_execute

    # Dry run of the continue-draining step:
    python manage.py safe_scale_in_execute --continue-draining

    # Real execution of one initiate step (may drain/deregister/terminate ONE instance):
    python manage.py safe_scale_in_execute --execute

    # Real execution of the continue-draining step:
    python manage.py safe_scale_in_execute --continue-draining --execute
"""

import json

from django.conf import settings
from django.core.management.base import BaseCommand

from events.services.live_safe_scale_in import (
    execute_safe_scale_in_one_step,
    continue_safe_scale_in_draining_instances,
)


class Command(BaseCommand):
    help = (
        "Run safe scale-in execution (dry-run by default; pass --execute to allow "
        "AWS/Redis mutations on a single instance)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--execute",
            action="store_true",
            help="Allow mutations (dry_run=False). Without this flag the command is dry-run only.",
        )
        parser.add_argument(
            "--continue-draining",
            action="store_true",
            dest="continue_draining",
            help="Advance an already-draining instance instead of initiating a new drain.",
        )
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
            "--reason",
            type=str,
            default="manual_command",
            help="Reason string recorded with the action. Default: manual_command.",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            dest="as_json",
            help="Print the full result as JSON.",
        )

    def handle(self, *args, **options):
        execute = options["execute"]
        continue_draining = options["continue_draining"]
        idle_seconds = options["idle_seconds"]
        reason = options["reason"]
        as_json = options["as_json"]

        dry_run = not execute

        if execute and not getattr(settings, "LIVE_MEETING_SAFE_SCALE_IN_ENABLED", False):
            self.stderr.write(
                self.style.ERROR(
                    "Blocked: --execute requires LIVE_MEETING_SAFE_SCALE_IN_ENABLED=True"
                )
            )
            return

        if dry_run:
            self.stdout.write(
                self.style.WARNING("DRY RUN ONLY — no AWS/Redis mutations will be made")
            )
        else:
            self.stdout.write(
                self.style.ERROR(
                    "EXECUTION MODE — this may mark draining, deregister ALB target, "
                    "or terminate one exact instance"
                )
            )

        if continue_draining:
            result = continue_safe_scale_in_draining_instances(
                reason=reason,
                dry_run=dry_run,
                idle_seconds=idle_seconds,
            )
        else:
            result = execute_safe_scale_in_one_step(
                reason=reason,
                dry_run=dry_run,
                idle_seconds=idle_seconds,
            )

        if as_json:
            self.stdout.write(json.dumps(result, indent=2, default=str))
            return

        self._print_text_result(result, dry_run)

    def _print_text_result(self, result, dry_run):
        self.stdout.write("")
        self.stdout.write("Safe scale-in execution result")
        self.stdout.write("  changed:    {0}".format(result.get("changed")))
        # Report the mode the command actually ran in; some early-return result
        # dicts (e.g. no_planned_terminations) don't carry a dry_run key.
        self.stdout.write("  dry_run:    {0}".format(result.get("dry_run", dry_run)))
        if "reason" in result:
            self.stdout.write("  reason:     {0}".format(result.get("reason")))

        # Instance identifiers that may be present depending on path/mode.
        for key in ("instance_id", "would_drain_instance", "would_terminate_instance"):
            if key in result and result.get(key) is not None:
                self.stdout.write("  {0}: {1}".format(key, result.get(key)))

        # Capacity summary, if present.
        current = result.get("current")
        required = result.get("required")
        current_desired = result.get("current_desired")
        required_desired = result.get("required_desired")
        if current_desired is None and isinstance(current, dict):
            current_desired = current.get("desired")
        if required_desired is None and isinstance(required, dict):
            required_desired = required.get("desired_instances")
        if current_desired is not None or required_desired is not None:
            self.stdout.write("  current desired:  {0}".format(current_desired))
            self.stdout.write("  required desired: {0}".format(required_desired))
        if result.get("over_capacity") is not None:
            self.stdout.write("  over_capacity:    {0}".format(result.get("over_capacity")))

        # Target health summary, if present (top-level or nested under "instance").
        target_health = result.get("target_health")
        if target_health is None and isinstance(result.get("instance"), dict):
            target_health = result["instance"].get("target_health")
        if target_health:
            self.stdout.write("  target health:")
            for entry in target_health:
                self.stdout.write(
                    "    - tg=...{0} state={1} reason={2} port={3}".format(
                        str(entry.get("target_group_arn"))[-12:],
                        entry.get("state"),
                        entry.get("reason"),
                        entry.get("port"),
                    )
                )
