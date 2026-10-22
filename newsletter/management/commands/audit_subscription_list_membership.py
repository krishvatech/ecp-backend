import json

from django.core.management.base import BaseCommand, CommandError

from newsletter.admin_views import _contacts_from_segment_response
from newsletter.mautic import MauticClient
from newsletter.mautic.exceptions import PermanentMauticError, TemporaryMauticError
from newsletter.models import MauticContactMapping, NewsletterCategory, NewsletterSubscription, NewsletterSyncEvent

# Classes of disagreement between ECP (authoritative) and Mautic's list segment.
STALE_WITHDRAWN = "stale_withdrawn"      # member withdrew in ECP; Mautic still lists them
NO_ECP_CONSENT = "no_ecp_consent"        # linked ECP member never subscribed to this list
UNLINKED = "unlinked"                    # Mautic contact not linked to any ECP member
INACTIVE_LIST = "inactive_list"          # list archived/deleted in ECP; segment still has members
MISSING = "missing_in_mautic"            # subscribed in ECP; not (yet) in Mautic's segment
MAPPING_STALE = "mapping_stale_after_merge"  # ECP link points at a merged-away contact (identity reconciliation)


class Command(BaseCommand):
    help = (
        "Compare each ECP Subscription List with its Mautic segment. ECP's NewsletterSubscription is the "
        "authority; Mautic's membership is what Campaigns and the bridge plugin can see. Reports members Mautic "
        "would still treat as subscribed after an ECP withdrawal that has not reached Mautic, contacts Mautic "
        "lists that no ECP member chose, and subscriptions Mautic has not received. Read-only: prints ids only "
        "(no email addresses) and changes nothing. Corrections go through ECP's own sync events and the "
        "existing identity/consent reconciliation commands."
    )

    page_size = 200

    def add_arguments(self, parser):
        parser.add_argument("--list", action="append", dest="slugs", help="Only this Subscription List slug (repeatable).")
        parser.add_argument("--json", action="store_true", help="Print one JSON document.")

    def handle(self, *args, **options):
        client = MauticClient()
        lists = NewsletterCategory.objects.exclude(mautic_segment_id="").order_by("slug")
        if options.get("slugs"):
            lists = lists.filter(slug__in=options["slugs"])
        report = {"mode": "read-only", "lists": []}
        try:
            for category in lists:
                report["lists"].append(self._compare(client, category))
        except (TemporaryMauticError, PermanentMauticError) as exc:
            raise CommandError(f"Mautic could not be read: {exc}") from exc

        if options.get("json"):
            self.stdout.write(json.dumps(report, indent=2, default=str))
            return
        self.stdout.write("READ-ONLY Subscription List membership audit (ECP is authoritative)")
        for row in report["lists"]:
            issues = {key: value for key, value in row["issues"].items() if value}
            style = self.style.SUCCESS if not issues else self.style.ERROR
            self.stdout.write(style(
                f"  {row['slug']!r} segment #{row['segment']} active={row['active']} mautic_members={row['mauticMembers']} "
                f"ecp_subscribed={row['ecpSubscribed']} issues={issues or 'none'}"
            ))

    def _members(self, client, segment_id):
        ids, start = [], 0
        while True:
            data = client.list_segment_contacts_via_bridge(segment_id, start=start, limit=self.page_size)
            rows = _contacts_from_segment_response(data)
            ids.extend(str(row.get("id")) for row in rows if row.get("id") is not None)
            start += self.page_size
            if not rows or start >= int(data.get("total") or 0):
                return set(ids)

    @staticmethod
    def _survivor(client, contact_id):
        """Mautic resolves a merged-away contact id to the contact that absorbed it."""
        try:
            contact = client.get_contact(contact_id)
        except (TemporaryMauticError, PermanentMauticError):
            return None
        resolved = contact.get("id") if isinstance(contact, dict) else None
        return str(resolved) if resolved is not None else None

    def _compare(self, client, category):
        members = self._members(client, category.mautic_segment_id)
        mappings = dict(MauticContactMapping.objects.filter(
            user_id__in=NewsletterSubscription.objects.filter(category=category).values("user_id")
        ).values_list("user_id", "mautic_contact_id"))
        # Every member linked to any ECP member (subscribed to this list or not).
        links = dict(MauticContactMapping.objects.filter(mautic_contact_id__in=members).values_list("mautic_contact_id", "user_id"))
        stale_links = []
        for user_id, contact_id in mappings.items():
            if contact_id in members:
                continue
            survivor = self._survivor(client, contact_id)
            if survivor and survivor != contact_id and survivor in members:
                links[survivor] = user_id
                stale_links.append({"contact": survivor, "mappedTo": contact_id, "user": user_id})
        subscriptions = dict(NewsletterSubscription.objects.filter(category=category).values_list("user_id", "is_subscribed"))
        pending = set(
            NewsletterSyncEvent.objects.filter(category=category)
            .exclude(status__in=["succeeded", "skipped", "failed"])
            .values_list("user_id", flat=True)
        )
        issues = {STALE_WITHDRAWN: [], NO_ECP_CONSENT: [], UNLINKED: [], INACTIVE_LIST: [], MISSING: [], MAPPING_STALE: stale_links}
        active = bool(category.is_active) and not category.deletion_state
        for contact_id in sorted(members, key=int):
            user_id = links.get(contact_id)
            entry = {"contact": contact_id, "user": user_id, "syncPending": str(user_id) in pending if user_id else False}
            if not active:
                issues[INACTIVE_LIST].append(entry)
            elif user_id is None:
                issues[UNLINKED].append(entry)
            elif user_id not in subscriptions:
                issues[NO_ECP_CONSENT].append(entry)
            elif not subscriptions[user_id]:
                issues[STALE_WITHDRAWN].append(entry)
        if active:
            linked_members = {links[c] for c in members if c in links}
            for user_id, subscribed in subscriptions.items():
                if subscribed and user_id not in linked_members:
                    issues[MISSING].append({"contact": mappings.get(user_id), "user": user_id, "syncPending": str(user_id) in pending})
        return {
            "slug": category.slug,
            "segment": category.mautic_segment_id,
            "active": active,
            "mauticMembers": len(members),
            "ecpSubscribed": sum(1 for value in subscriptions.values() if value),
            "issues": issues,
        }
