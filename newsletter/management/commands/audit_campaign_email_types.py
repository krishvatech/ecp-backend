import json

from django.core.management.base import BaseCommand, CommandError

from newsletter.campaign_email_types import (
    EMAIL_SEND_EVENT,
    STATE_INVALID,
    STATE_MARKETING,
    STATE_MISSING,
    STATE_TRANSACTIONAL,
    classify_email_type,
    runs_as_transactional,
)
from newsletter.mautic import MauticClient
from newsletter.mautic.exceptions import PermanentMauticError, TemporaryMauticError


def _collection(value):
    if isinstance(value, dict):
        value = list(value.values())
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _published(value):
    return value is True or str(value).strip().lower() in {"1", "true", "yes"}


class Command(BaseCommand):
    help = (
        "Report the email type of every Send email action in Mautic campaigns. "
        "An action without an email type runs in Mautic 7.1.3 as transactional: "
        "it ignores Do Not Contact and can repeat. Read-only: it only reads "
        "campaigns through Mautic's API, prints no contact data, and never "
        "updates, publishes, unpublishes or deletes anything."
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
            "--include-marketing",
            action="store_true",
            help="List marketing actions too (they are always counted).",
        )

    def handle(self, *args, **options):
        client = MauticClient()
        rows = []
        try:
            campaign_ids = options.get("campaign_ids") or self._all_campaign_ids(client)
            for campaign_id in campaign_ids:
                rows.extend(self._campaign_rows(client, campaign_id))
        except (TemporaryMauticError, PermanentMauticError) as exc:
            raise CommandError(f"Mautic could not be read: {exc}") from exc

        summary = {
            state: sum(1 for row in rows if row["email_type_state"] == state)
            for state in (STATE_MARKETING, STATE_TRANSACTIONAL, STATE_MISSING, STATE_INVALID)
        }
        summary["potentially_affected"] = sum(1 for row in rows if row["potentially_affected"])

        if options.get("json"):
            self.stdout.write(
                json.dumps(
                    {
                        "mode": "read-only",
                        "campaigns_scanned": len(campaign_ids),
                        "summary": summary,
                        "events": rows,
                    },
                    indent=2,
                    default=str,
                )
            )
            return

        self.stdout.write(
            f"READ-ONLY audit of Send email actions in {len(campaign_ids)} Mautic "
            f"campaign(s): {summary}"
        )
        for row in rows:
            if row["email_type_state"] == STATE_MARKETING and not options.get("include_marketing"):
                continue
            style = (
                self.style.SUCCESS
                if row["email_type_state"] == STATE_MARKETING
                else self.style.ERROR
                if row["campaign_published"] and row["potentially_affected"]
                else self.style.WARNING
            )
            self.stdout.write(
                style(
                    f"  campaign #{row['campaign_id']} {row['campaign_name'][:60]!r} "
                    f"{'published' if row['campaign_published'] else 'unpublished'} "
                    f"event #{row['event_id']} {row['event_name'][:40]!r} "
                    f"email_type={row['email_type']!r} ({row['email_type_state']})"
                )
            )
            self.stdout.write(f"      {row['note']}")

    def _campaign_rows(self, client, campaign_id):
        campaign = client.get_campaign(campaign_id)
        # The campaign endpoint keeps returning deleted events without saying so;
        # the builder plugin reports which ones are still in the workflow.
        try:
            states = client.get_campaign_event_states(campaign_id)
            active = {str(item) for item in (states.get("activeEventIds") or [])}
        except (TemporaryMauticError, PermanentMauticError):
            active = None

        rows = []
        for event in _collection(campaign.get("events")):
            if str(event.get("type") or "").strip() != EMAIL_SEND_EVENT:
                continue
            event_id = str(event.get("id") or "")
            if active is not None and event_id not in active:
                continue
            properties = event.get("properties")
            state = classify_email_type(properties)
            value = properties.get("email_type") if isinstance(properties, dict) else None
            affected = runs_as_transactional(state)
            rows.append(
                {
                    "campaign_id": str(campaign.get("id") or campaign_id),
                    "campaign_name": str(campaign.get("name") or ""),
                    "campaign_published": _published(campaign.get("isPublished")),
                    "event_id": event_id,
                    "event_name": str(event.get("name") or ""),
                    "email_type": value,
                    "email_type_state": state,
                    "potentially_affected": affected,
                    "active_events_verified": active is not None,
                    "note": self._note(state),
                }
            )
        return rows

    @staticmethod
    def _note(state):
        if state == STATE_MISSING:
            return (
                "No email type stored: Mautic sends it as transactional (ignores DNC, "
                "no repeat-send guard). Choose Marketing or Transactional explicitly."
            )
        if state == STATE_INVALID:
            return "Unsupported email type value: review this action in Mautic."
        if state == STATE_TRANSACTIONAL:
            return "Explicitly transactional: ignores DNC. Confirm this is intended."
        return "Marketing: respects DNC and sends each contact this email once."

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
