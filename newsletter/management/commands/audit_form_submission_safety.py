import json

from django.core.management.base import BaseCommand, CommandError

from newsletter.form_campaign_consent import (
    form_source_ids,
    segment_is_marked,
    subscription_list_consent_segment_ids,
    unmarked_gate_steps,
    unsafe_email_steps,
)
from newsletter.models import NewsletterCategory
from newsletter.form_views import _public_base_url, submit_address_status
from newsletter.mautic import MauticClient
from newsletter.mautic.exceptions import PermanentMauticError, TemporaryMauticError
from newsletter.mautic_campaign_duplicate import DuplicateBlocked, active_events


def _rows(data, key):
    rows = data.get(key) or {}
    rows = list(rows.values()) if isinstance(rows, dict) else list(rows)
    return [row for row in rows if isinstance(row, dict) and row.get("id")]


def _published(value):
    return value is True or str(value).strip().lower() in {"1", "true", "yes"}


class Command(BaseCommand):
    help = (
        "Report native Mautic Forms whose stored submit address is not Mautic's public "
        "address (site_url), and Campaigns with a Form source whose Send email steps are "
        "not behind a Subscription List consent check. Read-only: it only reads Forms and "
        "Campaigns through Mautic's API, prints no contact or submission data, and never "
        "saves, publishes, unpublishes or deletes anything. Repairs need separate approval."
    )

    page_size = 50

    def add_arguments(self, parser):
        parser.add_argument("--form-id", action="append", dest="form_ids", help="Only this Form ID (repeatable).")
        parser.add_argument(
            "--campaign-id", action="append", dest="campaign_ids", help="Only this Campaign ID (repeatable)."
        )
        parser.add_argument("--skip-forms", action="store_true", help="Do not check Forms.")
        parser.add_argument("--skip-campaigns", action="store_true", help="Do not check Campaigns.")
        parser.add_argument("--skip-lists", action="store_true", help="Do not check Subscription List consent markers.")
        parser.add_argument("--json", action="store_true", help="Print one JSON document instead of text.")

    def handle(self, *args, **options):
        client = MauticClient()
        report = {"mode": "read-only", "publicUrl": _public_base_url(), "forms": [], "campaigns": [], "subscriptionLists": []}
        try:
            if not options.get("skip_lists"):
                report["subscriptionLists"] = self._list_rows(client)
            if not options.get("skip_forms"):
                for form_id in options.get("form_ids") or self._ids(client.list_forms, "forms"):
                    report["forms"].append(self._form_row(client.get_form(form_id)))
            if not options.get("skip_campaigns"):
                segments = subscription_list_consent_segment_ids()
                for campaign_id in options.get("campaign_ids") or self._ids(client.list_campaigns, "campaigns"):
                    row = self._campaign_row(client, campaign_id, segments)
                    if row is not None:
                        report["campaigns"].append(row)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            raise CommandError(f"Mautic could not be read: {exc}") from exc

        report["summary"] = {
            "forms_checked": len(report["forms"]),
            "forms_mismatched": [row["id"] for row in report["forms"] if row["status"] == "mismatch"],
            "forms_unverified": [row["id"] for row in report["forms"] if row["status"] != "match" and row["status"] != "mismatch"],
            "form_sourced_campaigns": len(report["campaigns"]),
            "campaigns_with_unsafe_email": [row["id"] for row in report["campaigns"] if row["unsafeSteps"]],
            "subscription_lists_without_consent_marker": [row["slug"] for row in report["subscriptionLists"] if not row["marked"]],
        }
        if options.get("json"):
            self.stdout.write(json.dumps(report, indent=2, default=str))
            return
        self.stdout.write(f"READ-ONLY. Mautic public address: {report['publicUrl'] or 'unavailable'}")
        for row in report["forms"]:
            style = self.style.SUCCESS if row["status"] == "match" else self.style.ERROR if row["published"] else self.style.WARNING
            self.stdout.write(style(
                f"  form #{row['id']} {row['name'][:60]!r} {'published' if row['published'] else 'unpublished'} "
                f"submit={row['stored']} ({row['status']})"
            ))
        for row in report["campaigns"]:
            style = self.style.SUCCESS if not row["unsafeSteps"] else self.style.ERROR if row["published"] else self.style.WARNING
            self.stdout.write(style(
                f"  campaign #{row['id']} {row['name'][:60]!r} {'published' if row['published'] else 'unpublished'} "
                f"forms={row['forms']} unsafe email steps={[(s['id'], s['reason']) for s in row['unsafeSteps']]}"
            ))
        for row in report["subscriptionLists"]:
            style = self.style.SUCCESS if row["marked"] else self.style.ERROR
            self.stdout.write(style(f"  list {row['slug']!r} segment #{row['segment']} consent marker={'yes' if row['marked'] else 'MISSING'}"))
        self.stdout.write(f"Summary: {report['summary']}")

    def _ids(self, lister, key):
        ids, start = [], 0
        while True:
            data = lister(start=start, limit=self.page_size, minimal="true")
            rows = _rows(data, key)
            ids.extend(str(row["id"]) for row in rows)
            start += self.page_size
            if not rows or start >= int(data.get("total") or 0):
                return sorted(set(ids), key=int)

    @staticmethod
    def _form_row(form):
        status = submit_address_status(form)
        return {
            "id": str(form.get("id")),
            "name": str(form.get("name") or ""),
            "published": _published(form.get("isPublished")),
            "status": status["status"],
            "stored": status["stored"],
            "expected": status["expected"],
        }

    @staticmethod
    def _list_rows(client):
        """Active Subscription Lists whose Mautic segment the bridge plugin would
        not accept as consent evidence when it sends (no category marker)."""
        rows = []
        for category in NewsletterCategory.objects.filter(is_active=True, deletion_state="").exclude(mautic_segment_id="").order_by("slug"):
            try:
                marked = segment_is_marked(client.get_segment(category.mautic_segment_id))
            except (TemporaryMauticError, PermanentMauticError):
                marked = False
            rows.append({"slug": category.slug, "segment": category.mautic_segment_id, "marked": marked})
        return rows

    @staticmethod
    def _campaign_row(client, campaign_id, segments):
        campaign = client.get_campaign(campaign_id)
        forms = form_source_ids(campaign.get("forms"))
        if not forms:
            return None
        try:
            events = active_events(campaign, client.get_campaign_event_states(campaign_id).get("activeEventIds"))
            unsafe, verified = unsafe_email_steps(events, segments), True
            if not unsafe:
                unsafe = unmarked_gate_steps(events, reader=client.get_segment)
        except (DuplicateBlocked, TemporaryMauticError, PermanentMauticError):
            unsafe, verified = [{"id": "", "name": "Campaign", "reason": "unverifiable"}], False
        return {
            "id": str(campaign.get("id") or campaign_id),
            "name": str(campaign.get("name") or ""),
            "published": _published(campaign.get("isPublished")),
            "forms": forms,
            "segments": form_source_ids(campaign.get("lists")),
            "activeEventsVerified": verified,
            "unsafeSteps": unsafe,
            # What the bridge plugin's send-time check does to these steps.
            "runtimeEffect": "email steps refused at send time" if unsafe else "sends to current Subscription List members only",
        }
