import copy
import itertools
import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter import mautic_campaign_duplicate as duplicate
from newsletter.mautic import PermanentMauticError
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.models import MauticIdentityAuditLog

User = get_user_model()

TIMING_DEFAULTS = {"triggerDate": None, "triggerInterval": 0, "triggerIntervalUnit": None, "triggerHour": None,
                   "triggerRestrictedStartHour": None, "triggerRestrictedStopHour": None, "triggerRestrictedDaysOfWeek": []}


def _event(event_id, name, provider, event_type, *, parent=None, path=None, properties=None, order=0, **timing):
    return {"id": event_id, "name": name, "description": None, "type": provider, "eventType": event_type, "order": order,
            "properties": properties if properties is not None else {}, "channel": None, "channelId": None, "children": [],
            "parent": {"id": parent} if parent else None, "decisionPath": path, "triggerMode": "immediate",
            **TIMING_DEFAULTS, **timing}


def source_campaign():
    """A campaign as Mautic's API returns it (shape captured from local Mautic 7.1.3):
    segment + form sources -> C1 (condition)
        yes -> A1 add Gold -> C2 Contact tags [Gold] --yes--> D1 (decision) yes -> A5 / no -> A6 (fixed date)
        no  -> A2 add Silver -> A3 add Bronze (3 days, 10:15, 08:00-17:00, Mon+Wed)
    Events are listed out of graph order on purpose."""
    tags = lambda name: {"add_tags": [name], "remove_tags": []}
    events = [
        _event(184, "A6 undecided", "lead.changetags", "action", parent=182, path="no", properties=tags("Lost"), order=9,
               triggerMode="date", triggerDate="2030-01-15T09:30:00+00:00"),
        _event(176, "C1 city is yes", "lead.field_value", "condition", properties={"field": "city", "operator": "=", "value": "yes"}, order=1),
        _event(177, "A1 tag gold", "lead.changetags", "action", parent=176, path="yes", properties=tags("Gold"), order=2),
        _event(178, "A2 tag silver", "lead.changetags", "action", parent=176, path="no", properties=tags("Silver"), order=3),
        _event(179, "A3 tag bronze", "lead.changetags", "action", parent=178, properties=tags("Bronze"), order=4,
               triggerMode="interval", triggerInterval=3, triggerIntervalUnit="d", triggerHour="10:15",
               triggerRestrictedStartHour="08:00", triggerRestrictedStopHour="17:00", triggerRestrictedDaysOfWeek=[1, 3]),
        _event(180, "C2 has gold", "lead.tags", "condition", parent=177, properties={"tags": ["Gold"]}, order=5),
        _event(182, "D1 visits page", "page.pagehit", "decision", parent=180, path="yes",
               properties={"pages": [], "url": "https://example.test/x"}, order=7, triggerMode=None),
        _event(183, "A5 decided", "lead.changetags", "action", parent=182, path="yes", properties=tags("Won"), order=8),
    ]
    graph = [("lists", "176", "leadsource"), ("forms", "176", "leadsource"), ("176", "177", "yes"), ("176", "178", "no"),
             ("178", "179", "bottom"), ("177", "180", "bottom"), ("180", "182", "yes"), ("182", "183", "yes"), ("182", "184", "no")]
    nodes = [{"id": n, "positionX": 100 + 10 * i, "positionY": 50 * i}
             for i, n in enumerate(["lists", "forms", "176", "177", "178", "179", "180", "182", "183", "184"])]
    return {
        "id": 88, "name": "Spring nurture", "description": "Authored text", "isPublished": True, "allowRestart": True,
        "republishBehavior": None, "category": None, "publishUp": "2026-09-01T00:00:00+00:00", "publishDown": "2026-12-31T00:00:00+00:00",
        "dateAdded": "2026-09-01T00:00:00+00:00", "dateModified": "2026-09-02T00:00:00+00:00", "createdBy": 1, "modifiedBy": 1,
        "lists": [{"id": 54, "name": "Seg", "alias": "seg"}], "forms": [{"id": 1, "name": "Signup"}],
        "events": events,
        "canvasSettings": {"nodes": nodes,
                           "connections": [{"sourceId": s, "targetId": t, "anchors": {"source": a, "target": "top"}} for s, t, a in graph]},
    }


def _tag_field(name):
    return {"name": name, "type": "Mautic\\LeadBundle\\Form\\Type\\TagType", "blockPrefixes": ["form", "choice", "entity", "lead_tag"],
            "label": name, "required": False, "multiple": True, "mapped": True, "renderable": True, "controlType": "field",
            "choiceKind": "entity", "choiceMode": "inline",
            "choices": [{"label": t, "value": t, "data": {"id": i}} for i, t in enumerate(["Gold", "Silver", "Bronze", "Won", "Lost"], start=20)]}


CAPABILITIES = {
    "actions": [{"key": "lead.changetags", "type": "lead.changetags", "eventType": "action",
                 "formSchema": {"available": True, "fields": [_tag_field("add_tags"), _tag_field("remove_tags")]}}],
    "conditions": [
        {"key": "lead.field_value", "type": "lead.field_value", "eventType": "condition", "formSchema": {"available": False, "fields": []}},
        {"key": "lead.tags", "type": "lead.tags", "eventType": "condition", "formSchema": {"available": True, "fields": [_tag_field("tags")]}},
    ],
    "decisions": [{"key": "page.pagehit", "type": "page.pagehit", "eventType": "decision", "formSchema": {"available": False, "fields": []}}],
}


def _form_encoded(value):
    """What ECP's form-encoded transport delivers: no empty lists, scalars as strings."""
    if isinstance(value, dict):
        return {k: _form_encoded(v) for k, v in value.items() if v != []}
    if isinstance(value, list):
        return [_form_encoded(v) for v in value]
    return value


class FakeMautic:
    """Mautic's campaign API semantics, not a mock of the code under test: a
    create assigns fresh event IDs, swaps each new_N canvas node in place and
    reads parents and YES/NO paths from the canvas connections (setEvents)."""

    def __init__(self, source=None, *, corrupt_copy=False, fail_delete=False, fail_create=False):
        self.campaigns = {}
        self.active = {}
        self.ids = itertools.count(500)
        self.event_ids = itertools.count(900)
        self.created, self.deleted, self.writes = [], [], []
        self.corrupt_copy, self.fail_delete, self.fail_create = corrupt_copy, fail_delete, fail_create
        if source:
            self.add(source)

    def add(self, campaign, active_ids=None):
        self.campaigns[str(campaign["id"])] = copy.deepcopy(campaign)
        self.active[str(campaign["id"])] = active_ids if active_ids is not None else [e["id"] for e in campaign["events"]]

    def get_campaign(self, campaign_id):
        if str(campaign_id) not in self.campaigns:
            raise PermanentMauticError("Mautic API request failed (HTTP 404): not found")
        return copy.deepcopy(self.campaigns[str(campaign_id)])

    def get_campaign_event_states(self, campaign_id):
        return {"activeEventIds": list(self.active[str(campaign_id)])}

    def get_campaign_builder_capabilities(self):
        return copy.deepcopy(CAPABILITIES)

    def create_campaign(self, payload):
        self.writes.append(("create", payload))
        if self.fail_create:
            raise PermanentMauticError("Mautic API request failed (HTTP 400): campaign: invalid")
        payload = _form_encoded(copy.deepcopy(payload))
        real = {e["id"]: next(self.event_ids) for e in payload["events"]}
        canvas = payload["canvasSettings"]
        incoming = {c["targetId"]: c for c in canvas["connections"]}
        events = []
        for e in payload["events"]:
            conn = incoming.get(e["id"])
            parent = real.get(conn["sourceId"]) if conn else None
            anchor = (conn or {}).get("anchors", {}).get("source")
            event = {**{k: None for k in TIMING_DEFAULTS}, "description": None, "channel": None, "channelId": None, "children": [],
                     **{k: v for k, v in e.items() if k not in ("id", "parent", "decisionPath")},
                     "id": real[e["id"]], "parent": {"id": parent} if parent else None,
                     "decisionPath": anchor if anchor in ("yes", "no") else None}
            event["triggerRestrictedDaysOfWeek"] = [str(d) for d in e.get("triggerRestrictedDaysOfWeek", [])]
            events.append(event)
        if self.corrupt_copy:
            events[-1]["properties"] = {"add_tags": ["24"]}
        new_id = next(self.ids)
        created = {
            "id": new_id, "name": payload["name"], "description": payload.get("description"), "isPublished": bool(payload.get("isPublished")),
            "allowRestart": bool(payload.get("allowRestart")), "republishBehavior": payload.get("republishBehavior"),
            "publishUp": payload.get("publishUp"), "publishDown": payload.get("publishDown"), "category": payload.get("category"),
            "lists": [{"id": s["id"]} for s in payload.get("lists", [])], "forms": [{"id": s["id"]} for s in payload.get("forms", [])],
            "events": events,
            "canvasSettings": {
                "nodes": [{**n, "id": str(real.get(n["id"], n["id"]))} for n in canvas["nodes"]],
                "connections": [{**c, "sourceId": str(real.get(c["sourceId"], c["sourceId"])), "targetId": str(real.get(c["targetId"], c["targetId"]))}
                                for c in canvas["connections"]],
            },
        }
        self.add(created)
        self.created.append(new_id)
        return copy.deepcopy(created)

    def delete_campaign(self, campaign_id):
        self.writes.append(("delete", campaign_id))
        if self.fail_delete:
            raise PermanentMauticError("Mautic API request failed (HTTP 500)")
        self.deleted.append(str(campaign_id))
        self.campaigns.pop(str(campaign_id), None)
        return {}


def _caps_index():
    from newsletter.native_campaign_views import _event_capability_rows, _event_key

    return {(r["eventType"], _event_key(r)): r for r in _event_capability_rows(CAPABILITIES)}


class DuplicateServiceTests(SimpleTestCase):
    def test_name_gets_the_broadcast_copy_suffix_within_mautics_limit(self):
        self.assertEqual(duplicate.duplicate_name("Spring nurture"), "Spring nurture Copy")
        long_name = "x" * 191
        self.assertEqual(len(duplicate.duplicate_name(long_name)), 191)
        self.assertTrue(duplicate.duplicate_name(long_name).endswith(" Copy"))

    def test_payload_remaps_every_id_parents_first_and_resets_runtime_state(self):
        source = source_campaign()
        payload, temp = duplicate.build_duplicate_payload(source, source["events"])

        order = [e["name"] for e in payload["events"]]
        for child, parent in (("A1 tag gold", "C1 city is yes"), ("A3 tag bronze", "A2 tag silver"), ("A6 undecided", "D1 visits page")):
            self.assertLess(order.index(parent), order.index(child), "parents are created first")
        sent = {e["name"]: e for e in payload["events"]}
        self.assertEqual(sent["A1 tag gold"]["parent"], temp["176"])
        self.assertEqual(sent["A1 tag gold"]["decisionPath"], "yes")
        self.assertEqual(sent["A6 undecided"]["parent"], temp["182"])
        self.assertEqual(sent["A6 undecided"]["decisionPath"], "no")
        self.assertNotIn("decisionPath", sent["A3 tag bronze"])
        self.assertEqual(sent["A1 tag gold"]["properties"], {"add_tags": ["Gold"], "remove_tags": []}, "tag names, verbatim")
        a3 = sent["A3 tag bronze"]
        self.assertEqual(
            {k: a3[k] for k in ("triggerMode", "triggerInterval", "triggerIntervalUnit", "triggerHour",
                                "triggerRestrictedStartHour", "triggerRestrictedStopHour", "triggerRestrictedDaysOfWeek")},
            {"triggerMode": "interval", "triggerInterval": 3, "triggerIntervalUnit": "d", "triggerHour": "10:15",
             "triggerRestrictedStartHour": "08:00", "triggerRestrictedStopHour": "17:00", "triggerRestrictedDaysOfWeek": [1, 3]},
        )
        self.assertEqual(sent["A6 undecided"]["triggerDate"], "2030-01-15T09:30:00+00:00")

        self.assertFalse(payload["isPublished"])
        self.assertTrue(payload["allowRestart"])
        self.assertEqual(payload["description"], "Authored text")
        self.assertNotIn("publishUp", payload)
        self.assertNotIn("publishDown", payload)
        self.assertEqual(payload["lists"], [{"id": 54}])
        self.assertEqual(payload["forms"], [{"id": 1}])

        # No source event ID survives anywhere in what is sent.
        source_ids = {str(e["id"]) for e in source["events"]}
        canvas = payload["canvasSettings"]
        referenced = {n["id"] for n in canvas["nodes"]} | {c["sourceId"] for c in canvas["connections"]} | {c["targetId"] for c in canvas["connections"]}
        referenced |= {e["id"] for e in payload["events"]} | {e.get("parent") for e in payload["events"]}
        self.assertEqual(referenced & source_ids, set())
        self.assertIn(("forms", temp["176"]), {(c["sourceId"], c["targetId"]) for c in canvas["connections"]})

    def test_a_sound_graph_has_no_blockers(self):
        source = source_campaign()
        self.assertEqual(duplicate.duplicate_blockers(source, source["events"], _caps_index()), [])

    def test_unsafe_graphs_are_refused_with_reasons(self):
        def blockers(mutate, active=None):
            source = source_campaign()
            mutate(source)
            events = source["events"] if active is None else [e for e in source["events"] if e["id"] in active]
            return " | ".join(duplicate.duplicate_blockers(source, events, _caps_index()))

        def frozen(c):
            c["canvasSettings"]["nodes"].insert(0, {"id": "node-1-trig", "nodeType": "trigger", "positionX": "1", "positionY": "1"})

        def frozen_segment_only(c):
            # Repairable per Phase 2C (one source): the refusal says how to repair.
            frozen(c)
            c["forms"] = []
            c["canvasSettings"]["nodes"] = [n for n in c["canvasSettings"]["nodes"] if n["id"] != "forms"]
            c["canvasSettings"]["connections"] = [x for x in c["canvasSettings"]["connections"] if x["sourceId"] != "forms"]

        def no_path(c):
            event = next(e for e in c["events"] if e["id"] == 177)
            event["decisionPath"] = None
            next(x for x in c["canvasSettings"]["connections"] if x["targetId"] == "177")["anchors"]["source"] = "bottom"

        def cycle(c):
            next(e for e in c["events"] if e["id"] == 176)["parent"] = {"id": 179}

        self.assertIn("Launch Campaign Builder, Close Builder, then Save & Close", blockers(frozen_segment_only))
        # Phase 2C's audit is strict about anything else frozen: refused, not repaired.
        self.assertIn("not safe to copy (UNSUPPORTED_OTHER_STRUCTURE)", blockers(frozen))
        self.assertIn("follows condition 176 without a YES/NO path", blockers(no_path))
        self.assertIn("parent cycle", blockers(cycle))
        self.assertIn("is not offered by this Mautic's Campaign Builder",
                      blockers(lambda c: next(e for e in c["events"] if e["id"] == 177).update(type="plugin.gone")))
        self.assertIn("is on the yes path but drawn from no",
                      blockers(lambda c: next(x for x in c["canvasSettings"]["connections"] if x["targetId"] == "177")["anchors"].update(source="no")))
        self.assertIn("invalid value for property add_tags",
                      blockers(lambda c: next(e for e in c["events"] if e["id"] == 177).update(properties={"add_tags": ["24"]})))
        # A soft-deleted parent: the API still returns it, the active list does not.
        self.assertIn("not an active event of this campaign",
                      blockers(lambda c: None, active={176, 177, 178, 179, 180, 183, 184}))

    def test_a_soft_deleted_leaf_is_simply_not_copied(self):
        # Mautic's campaign API still returns deleted events; only active ones are copied.
        source = source_campaign()
        events = duplicate.active_events(source, [176, 177, 178, 179, 180, 182, 183])
        self.assertEqual(duplicate.duplicate_blockers(source, events, _caps_index()), [])
        payload, temp = duplicate.build_duplicate_payload(source, events)
        self.assertNotIn("184", temp)
        self.assertNotIn("A6 undecided", [e["name"] for e in payload["events"]])
        self.assertFalse(any(c["targetId"] == "184" for c in payload["canvasSettings"]["connections"]))

    def test_verification_accepts_a_faithful_copy_and_catches_drift(self):
        fake = FakeMautic(source_campaign())
        source = fake.get_campaign(88)
        payload, temp = duplicate.build_duplicate_payload(source, source["events"])
        created = fake.create_campaign(payload)
        real = duplicate.created_event_ids(payload, created)
        mapping = {old: real[t] for old, t in temp.items()}
        copy_ = fake.get_campaign(created["id"])

        self.assertEqual(duplicate.verify_duplicate(source, source["events"], copy_, copy_["events"], mapping), [])

        drifted = copy.deepcopy(copy_)
        gold = next(e for e in drifted["events"] if e["name"] == "A1 tag gold")
        gold["decisionPath"] = "no"
        gold["triggerHour"] = "11:00"
        problems = duplicate.verify_duplicate(source, source["events"], drifted, drifted["events"], mapping)
        self.assertTrue(any("decisionPath differs" in p for p in problems))
        self.assertTrue(any("triggerHour differs" in p for p in problems))


class DuplicateViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(username="dup-staff", email="dup-staff@example.test", password="pw",
                                              is_staff=True, is_superuser=True)
        grant_marketing_access(self.staff)
        self.normal = User.objects.create_user(username="dup-normal", email="dup-normal@example.test", password="pw")
        self.url = reverse("newsletter-admin-mautic-campaign-duplicate", args=["88"])

    def _post(self, fake, user=None):
        self.client.force_authenticate(user=user or self.staff)
        with patch("newsletter.native_campaign_views.MauticClient", return_value=fake):
            return self.client.post(self.url, {}, format="json")

    def test_authentication_and_marketing_access_are_required(self):
        fake = FakeMautic(source_campaign())
        self.assertIn(self.client.post(self.url, {}, format="json").status_code, (401, 403))
        self.assertEqual(self._post(fake, user=self.normal).status_code, 403)
        self.assertEqual(fake.writes, [])

    def test_a_missing_source_is_404_and_writes_nothing(self):
        fake = FakeMautic()
        self.assertEqual(self._post(fake).status_code, 404)
        self.assertEqual(fake.writes, [])

    def test_the_copy_is_a_faithful_unpublished_independent_campaign(self):
        fake = FakeMautic(source_campaign())
        before = copy.deepcopy(fake.campaigns["88"])

        response = self._post(fake)

        self.assertEqual(response.status_code, 201, response.data)
        new_id = response.data["id"]
        self.assertEqual(response.data, {"id": new_id, "name": "Spring nurture Copy", "isPublished": False, "sourceId": "88"})
        self.assertEqual(fake.campaigns["88"], before, "the source is untouched")
        copy_ = fake.campaigns[new_id]
        self.assertFalse(copy_["isPublished"])
        self.assertIsNone(copy_["publishUp"])
        by_name = {e["name"]: e for e in copy_["events"]}
        self.assertEqual(by_name["A1 tag gold"]["parent"]["id"], by_name["C1 city is yes"]["id"])
        self.assertEqual(by_name["A6 undecided"]["parent"]["id"], by_name["D1 visits page"]["id"])
        self.assertEqual(by_name["A6 undecided"]["decisionPath"], "no")
        self.assertNotIn(by_name["A1 tag gold"]["id"], {e["id"] for e in before["events"]})
        self.assertEqual(by_name["C2 has gold"]["properties"], {"tags": ["Gold"]})
        self.assertEqual(fake.deleted, [])
        log = MauticIdentityAuditLog.objects.get()
        self.assertEqual((log.action, log.status, str(log.resource_id)),
                         ("campaign.create", "succeeded", str(new_id)))
        self.assertIn("duplicate of campaign 88", log.detail)

    def test_an_unsafe_source_is_refused_before_anything_is_created(self):
        source = source_campaign()
        source["canvasSettings"]["nodes"].insert(0, {"id": "node-1-trig", "nodeType": "trigger"})
        fake = FakeMautic(source)

        response = self._post(fake)

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["detail"], "This campaign cannot be duplicated safely.")
        self.assertTrue(response.data["reasons"])
        self.assertEqual(fake.writes, [])

    def test_a_copy_that_does_not_match_is_removed_and_reported(self):
        fake = FakeMautic(source_campaign(), corrupt_copy=True)

        response = self._post(fake)

        self.assertEqual(response.status_code, 502)
        self.assertIn("incomplete copy was removed", response.data["detail"])
        self.assertTrue(any("properties differs" in r for r in response.data["reasons"]))
        self.assertEqual(fake.deleted, [str(fake.created[0])])
        self.assertEqual(sorted(fake.campaigns), ["88"], "only the source remains")
        self.assertEqual(MauticIdentityAuditLog.objects.get().status, "failed")

    def test_a_copy_that_cannot_be_removed_is_named_for_manual_cleanup(self):
        fake = FakeMautic(source_campaign(), corrupt_copy=True, fail_delete=True)

        response = self._post(fake)

        self.assertEqual(response.status_code, 502)
        self.assertIn(f"Mautic campaign #{fake.created[0]}", response.data["detail"])
        self.assertIn("Delete it in Mautic", response.data["detail"])

    def test_a_create_mautic_refuses_leaves_nothing_behind(self):
        fake = FakeMautic(source_campaign(), fail_create=True)

        response = self._post(fake)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(sorted(fake.campaigns), ["88"])
        self.assertEqual(fake.deleted, [])
