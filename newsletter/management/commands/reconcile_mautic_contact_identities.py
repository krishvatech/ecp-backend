import json

from django.core.management.base import BaseCommand

from newsletter.contact_identity import DEFAULT_LIMIT, IdentityReconciler


class Command(BaseCommand):
    help = (
        "Check that each ECP member's Mautic contact link names a live contact. When Mautic "
        "merged the linked contact away, its retired ID resolves to the survivor; --apply "
        "re-points the link only when the survivor carries the member's email, no other "
        "member is linked to it and a second read agrees. Everything else is reported for "
        "manual review. Read-only unless --apply. Output contains IDs only."
    )

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Re-point verified merged links.")
        parser.add_argument("--user-id", action="append", type=int, dest="user_ids",
                            help="Only this ECP user (repeatable).")
        parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
        parser.add_argument("--json", action="store_true", help="Print one JSON document.")
        parser.add_argument("--include-current", action="store_true", help="List current links too.")

    def handle(self, *args, **options):
        reconciler = IdentityReconciler(apply=options["apply"])
        summary = reconciler.run(limit=options["limit"], user_ids=options["user_ids"])
        findings = [f.as_dict() for f in reconciler.findings
                    if options["include_current"] or f.status != "current"]
        if options["json"]:
            self.stdout.write(json.dumps({"summary": summary, "findings": findings}, indent=2))
            return
        self.stdout.write(f"{summary['mode'].upper()}: checked {summary['checked']} links; "
                          f"statuses {summary['statuses']}; outcomes {summary['outcomes']}")
        for finding in findings:
            self.stdout.write(
                f"user {finding['user_id']}: {finding['status']} -> {finding['action']}"
                f" (mapped {finding['mapped_contact_id']}"
                + (f", survivor {finding['survivor_contact_id']}" if finding["survivor_contact_id"] else "")
                + (f", {finding['outcome']}" if finding["outcome"] else "") + ")"
            )
