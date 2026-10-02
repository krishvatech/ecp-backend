import json

from django.core.management.base import BaseCommand, CommandError

from newsletter.mautic import MauticClient
from newsletter.mautic.exceptions import PermanentMauticError, TemporaryMauticError
from newsletter.mautic_campaign_canvas_audit import (
    LEGACY_ORPHAN_CANVAS,
    UNKNOWN,
    audit_campaign,
)


class Command(BaseCommand):
    help = (
        "Report Mautic campaigns frozen by an orphaned canvas node left by the old "
        "ECP Campaign Builder. Read-only: it only reads campaigns through Mautic's "
        "API and never writes. It has no apply mode; a repairable campaign is fixed "
        "by re-saving it in Mautic's own Campaign Builder (see each row's repair)."
    )

    page_size = 50

    def add_arguments(self, parser):
        parser.add_argument(
            "--campaign-id",
            action="append",
            dest="campaign_ids",
            help="Audit only this Mautic campaign ID (repeatable). Omit to audit all.",
        )
        parser.add_argument(
            "--json",
            action="store_true",
            help="Print one JSON document instead of a table.",
        )
        parser.add_argument(
            "--include-healthy",
            action="store_true",
            help="List healthy campaigns too (they are always counted).",
        )

    def handle(self, *args, **options):
        client = MauticClient()
        try:
            campaign_ids = options.get("campaign_ids") or self._all_campaign_ids(client)
            audits = [audit_campaign(client.get_campaign(cid)) for cid in campaign_ids]
        except (TemporaryMauticError, PermanentMauticError) as exc:
            raise CommandError(f"Mautic could not be read: {exc}") from exc

        summary = {}
        for audit in audits:
            summary[audit.classification] = summary.get(audit.classification, 0) + 1

        if options.get("json"):
            self.stdout.write(
                json.dumps(
                    {"mode": "read-only", "summary": summary, "campaigns": [a.as_dict() for a in audits]},
                    indent=2,
                    default=str,
                )
            )
            return

        self.stdout.write(f"READ-ONLY audit of {len(audits)} Mautic campaign(s): {summary}")
        for audit in audits:
            if not options.get("include_healthy") and audit.classification.startswith("HEALTHY"):
                continue
            style = (
                self.style.WARNING
                if audit.classification == LEGACY_ORPHAN_CANVAS
                else self.style.ERROR
                if audit.classification == UNKNOWN or audit.orphan_nodes
                else self.style.SUCCESS
            )
            self.stdout.write(
                style(
                    f"  #{audit.campaign_id} {audit.name[:60]!r} "
                    f"{'published' if audit.published else 'unpublished'} "
                    f"events={audit.event_count} {audit.classification}"
                )
            )
            self.stdout.write(
                f"      orphans={audit.orphan_nodes} ECP blocks Save={audit.blocks_ecp_save} "
                f"Mautic PATCH fails={audit.mautic_patch_fails} fingerprint={audit.fingerprint}"
            )
            for reason in audit.reasons:
                self.stdout.write(f"      - {reason}")
            if audit.repairable:
                self.stdout.write(f"      repair: {audit.proposed_repair}")
                self.stdout.write(f"      would change: {json.dumps(audit.would_change)}")
            elif audit.orphan_nodes:
                self.stdout.write("      repair: none proposed — review this campaign in Mautic first.")

    def _all_campaign_ids(self, client):
        ids, start = [], 0
        while True:
            data = client.list_campaigns(start=start, limit=self.page_size, minimal="true")
            rows = data.get("campaigns") or {}
            rows = list(rows.values()) if isinstance(rows, dict) else list(rows)
            ids.extend(str(row["id"]) for row in rows if isinstance(row, dict) and row.get("id"))
            start += self.page_size
            if not rows or start >= int(data.get("total") or 0):
                return sorted(set(ids), key=int)
