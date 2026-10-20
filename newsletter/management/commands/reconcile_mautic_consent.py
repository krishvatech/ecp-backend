import json

from django.core.management.base import BaseCommand

from newsletter.consent_reconciliation import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_LIMIT,
    DEFAULT_MAX_CONSECUTIVE_ERRORS,
    DEFAULT_MAX_SECONDS,
    DEFAULT_TIMEOUT_SECONDS,
    IN_SYNC,
    MAX_LIMIT,
    Reconciler,
)


class Command(BaseCommand):
    help = (
        "Compare ECP's mirror of Mautic email suppression (MauticEmailSuppression) with "
        "live Mautic Do Not Contact state for linked members. Read-only unless --apply. "
        "--apply only adds or strengthens a suppression Mautic reports (re-checked under a "
        "row lock); it never lifts one. A suppression Mautic no longer reports, and every "
        "ambiguous case, is reported for manual review. Newsletter list "
        "choices are never read or changed. Output contains IDs only, no contact data."
    )

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Apply the safe corrections.")
        parser.add_argument("--user-id", action="append", type=int, dest="user_ids",
                            help="Only this ECP user (repeatable).")
        parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                            help=f"Linked members to check this run (max {MAX_LIMIT}).")
        parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
        parser.add_argument("--after-id", type=int, default=0,
                            help="Continue after this mapping id (the previous run's next_after_id).")
        parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS,
                            help="Seconds per Mautic request.")
        parser.add_argument("--max-seconds", type=float, default=DEFAULT_MAX_SECONDS,
                            help="Stop reading Mautic after this many seconds.")
        parser.add_argument("--max-errors", type=int, default=DEFAULT_MAX_CONSECUTIVE_ERRORS,
                            help="Stop reading Mautic after this many consecutive temporary errors.")
        parser.add_argument("--pause-ms", type=int, default=0,
                            help="Pause between Mautic requests (rate-limit protection).")
        parser.add_argument("--json", action="store_true", help="Print one JSON document.")
        parser.add_argument("--include-in-sync", action="store_true", help="List in-sync members too.")

    def handle(self, *args, **options):
        reconciler = Reconciler(
            apply=options["apply"],
            timeout=options["timeout"],
            max_seconds=options["max_seconds"],
            max_consecutive_errors=options["max_errors"],
            pause_seconds=max(0, options["pause_ms"]) / 1000,
        )
        summary = reconciler.run(
            limit=options["limit"],
            batch_size=options["batch_size"],
            after_id=options["after_id"],
            user_ids=options.get("user_ids"),
        )
        rows = [
            finding.as_dict()
            for finding in reconciler.findings
            if options["include_in_sync"] or finding.status != IN_SYNC
        ]
        if options["json"]:
            self.stdout.write(json.dumps({"summary": summary, "findings": rows}, indent=2, default=str))
            return

        self.stdout.write(f"{summary['mode'].upper()} consent reconciliation: {json.dumps(summary, default=str)}")
        for row in rows:
            line = (f"  user #{row['user_id']} contact #{row['contact_id'] or '-'} {row['status']} -> {row['action']}"
                    f" ecp={row['ecp_reason'] or 'none'} mautic={','.join(row['mautic_reasons']) or 'none'}")
            if row["outcome"]:
                line += f" [{row['outcome']}]"
            if row["detail"]:
                line += f" ({row['detail']})"
            self.stdout.write(line)
