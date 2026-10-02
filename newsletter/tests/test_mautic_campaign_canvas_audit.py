import copy
import json
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import SimpleTestCase

from newsletter.mautic_campaign_canvas_audit import (
    HEALTHY_CURRENT_ECP,
    HEALTHY_NATIVE,
    HEALTHY_NO_CANVAS,
    LEGACY_ORPHAN_CANVAS,
    UNKNOWN,
    UNSUPPORTED_OTHER_STRUCTURE,
    audit_campaign,
    campaign_fingerprint,
)


# Every timing key Mautic 7.1.3 returns on a campaign event (immediate defaults).
TIMING_DEFAULTS = {"triggerDate": None, "triggerInterval": 0, "triggerIntervalUnit": None, "triggerHour": None,
                   "triggerRestrictedStartHour": None, "triggerRestrictedStopHour": None, "triggerRestrictedDaysOfWeek": []}


def _events(base):
    """Trigger -> C (condition) -> yes: A1 / no: A2 -> A3 (interval 3 d), as Mautic's API returns them."""
    return [{"name": f"step {event['id']}", "description": None, "channel": None, "channelId": None, "order": index,
             "children": [], **TIMING_DEFAULTS, **event}
            for index, event in enumerate(_event_graph(base), start=1)]


def _event_graph(base):
    c, a1, a2, a3 = (str(base + offset) for offset in range(4))
    return [
        {"id": int(c), "type": "lead.field_value", "eventType": "condition", "parent": None, "decisionPath": None,
         "properties": {"field": "city", "operator": "=", "value": "yes-city"}, "triggerMode": "immediate"},
        {"id": int(a1), "type": "lead.changetags", "eventType": "action", "parent": {"id": int(c)}, "decisionPath": "yes",
         "properties": {"add_tags": ["phase2c-yes"]}, "triggerMode": "immediate"},
        {"id": int(a2), "type": "lead.changetags", "eventType": "action", "parent": {"id": int(c)}, "decisionPath": "no",
         "properties": {"add_tags": ["phase2c-no"]}, "triggerMode": "immediate"},
        {"id": int(a3), "type": "lead.changetags", "eventType": "action", "parent": {"id": int(a2)}, "decisionPath": None,
         "properties": {"add_tags": ["phase2c-after"]}, "triggerMode": "interval", "triggerInterval": 3, "triggerIntervalUnit": "d"},
    ]


def _provider_graph(base, *, native=False):
    c, a1, a2, a3 = (str(base + offset) for offset in range(4))
    pos = (lambda v: v) if native else str
    nodes = [{"id": node_id, "positionX": pos(x), "positionY": pos(y)}
             for node_id, x, y in (("lists", 380, 100), (c, 380, 260), (a1, 380, 420), (a2, 620, 420), (a3, 380, 580))]
    connections = [
        {"sourceId": "lists", "targetId": c, "anchors": {"source": "leadsource", "target": "top"}},
        {"sourceId": c, "targetId": a1, "anchors": {"source": "yes", "target": "top"}},
        {"sourceId": c, "targetId": a2, "anchors": {"source": "no", "target": "top"}},
        {"sourceId": a2, "targetId": a3, "anchors": {"source": "bottom", "target": "top"}},
    ]
    return nodes, connections


# What the pre-2A ECP builder sent (its own React Flow nodes and edges), stored by
# Mautic ahead of the provider graph — captured from a real local save.
LEGACY_NODE_IDS = ["node-1790900000001-trig01", "node-1790900000002-cond01", "node-1790900000003-acta01",
                   "node-1790900000004-actb01", "node-1790900000005-actc01"]


def _legacy_builder_part():
    t, c, a1, a2, a3 = LEGACY_NODE_IDS
    nodes = [{"id": t, "type": "trigger", "nodeType": "trigger", "position": {"x": "120", "y": "80"}, "eventId": "",
              "label": "Trigger", "positionX": "120", "positionY": "80"}]
    for node_id, node_type, event_id, x in ((c, "condition", "new_1", 120), (a1, "action", "new_2", 340),
                                            (a2, "action", "new_3", 560), (a3, "action", "new_4", 780)):
        nodes.append({"id": node_id, "type": node_type, "nodeType": node_type, "position": {"x": str(x), "y": "240"},
                      "eventId": event_id, "label": node_type.title(), "positionX": str(x), "positionY": "240"})
    edges = [(t, c), (c, a1), (c, a2), (a2, a3)]
    connections = [{"id": f"edge-{s}-{d}", "source": s, "target": d, "sourceId": s, "targetId": d,
                    "anchors": {"source": "bottom", "target": "top"}} for s, d in edges]
    return nodes, connections


def campaign(base=148, *, kind="legacy", published=False):
    events = _events(base)
    nodes, connections = _provider_graph(base, native=(kind == "native"))
    if kind == "legacy":
        legacy_nodes, legacy_connections = _legacy_builder_part()
        nodes, connections = legacy_nodes + nodes, legacy_connections + connections
    return {"id": 81, "name": "phase2c fixture", "description": "fixture", "isPublished": published,
            "publishUp": None, "publishDown": None, "allowRestart": False, "republishBehavior": None, "category": None,
            # Sources come back as whole segment/form objects.
            "lists": [{"id": 50, "name": "phase2c segment", "alias": "phase2c-seg"}], "forms": [],
            "dateAdded": "2026-10-02T04:00:00+00:00", "dateModified": "2026-10-02T04:00:00+00:00",
            "createdBy": 1, "modifiedBy": 1, "createdByUser": "admin", "modifiedByUser": "admin",
            "events": events, "canvasSettings": {"nodes": nodes, "connections": connections}}


class CampaignCanvasAuditTests(SimpleTestCase):
    def test_healthy_campaigns_are_left_alone(self):
        for kind, expected in (("native", HEALTHY_NATIVE), ("current", HEALTHY_CURRENT_ECP)):
            audit = audit_campaign(campaign(kind=kind))
            self.assertEqual(audit.classification, expected, kind)
            self.assertEqual(audit.orphan_nodes, [])
            self.assertFalse(audit.mautic_patch_fails)
            self.assertFalse(audit.blocks_ecp_save)
            self.assertFalse(audit.repairable)
            self.assertIsNone(audit.proposed_canvas)

    def test_a_campaign_without_canvas_is_not_frozen(self):
        data = campaign(kind="current")
        data["canvasSettings"] = []
        self.assertEqual(audit_campaign(data).classification, HEALTHY_NO_CANVAS)

    def test_the_legacy_orphan_is_detected_with_the_same_rule_as_mautic(self):
        audit = audit_campaign(campaign(kind="legacy"))

        self.assertEqual(audit.classification, LEGACY_ORPHAN_CANVAS)
        self.assertEqual(audit.orphan_nodes, ["node-1790900000001-trig01"])
        self.assertTrue(audit.mautic_patch_fails)
        self.assertTrue(audit.blocks_ecp_save)
        self.assertTrue(audit.repairable)
        self.assertEqual(audit.legacy_builder_nodes, sorted(LEGACY_NODE_IDS))
        self.assertEqual(audit.would_change["canvasSettings.connections.removed"], 4)
        self.assertEqual(audit.would_change["events"], "unchanged")

    def test_the_proposed_canvas_is_exactly_mautics_own_graph(self):
        audit = audit_campaign(campaign(kind="legacy"))
        healthy = campaign(kind="current")["canvasSettings"]

        self.assertEqual(audit.proposed_canvas, healthy)

    def test_applying_the_proposal_is_healthy_and_a_second_audit_is_a_no_op(self):
        data = campaign(kind="legacy")
        repaired = copy.deepcopy(data)
        repaired["canvasSettings"] = audit_campaign(data).proposed_canvas

        again = audit_campaign(repaired)
        self.assertEqual(again.classification, HEALTHY_CURRENT_ECP)
        self.assertFalse(again.repairable)
        self.assertEqual(again.orphan_nodes, [])
        # The repair touches the canvas only: events are byte-for-byte the same.
        self.assertEqual(json.dumps(repaired["events"], sort_keys=True), json.dumps(data["events"], sort_keys=True))
        self.assertEqual(repaired["isPublished"], data["isPublished"])

    def test_events_missing_from_mautics_graph_are_not_offered_a_repair(self):
        # Local campaign 6's shape: only the old builder's nodes, events not on the canvas.
        data = campaign(kind="legacy")
        legacy_nodes, _ = _legacy_builder_part()
        data["canvasSettings"] = {"nodes": legacy_nodes[:2], "connections": []}

        audit = audit_campaign(data)
        self.assertEqual(audit.classification, UNSUPPORTED_OTHER_STRUCTURE)
        self.assertFalse(audit.repairable)
        self.assertIn("event 148 is not on the canvas", audit.reasons)
        self.assertIsNone(audit.proposed_canvas)

    def test_a_graph_that_disagrees_with_the_events_is_not_offered_a_repair(self):
        # Mautic's own connection says NO where the event row says YES: re-saving
        # would change which contacts get the step, so nothing is proposed.
        data = campaign(kind="legacy")
        for connection in data["canvasSettings"]["connections"]:
            if connection["targetId"] == "149":
                connection["anchors"] = {"source": "no", "target": "top"}

        audit = audit_campaign(data)
        self.assertEqual(audit.classification, UNSUPPORTED_OTHER_STRUCTURE)
        self.assertFalse(audit.repairable)
        self.assertIn("event 149 is on the yes path but drawn from no", audit.reasons)

    def test_a_disconnected_event_is_not_treated_as_builder_debris(self):
        data = campaign(kind="current")
        data["canvasSettings"]["connections"] = [
            c for c in data["canvasSettings"]["connections"] if c["targetId"] != "151"
        ]
        audit = audit_campaign(data)
        self.assertEqual(audit.classification, UNSUPPORTED_OTHER_STRUCTURE)
        self.assertEqual(audit.orphan_nodes, ["151"])
        self.assertFalse(audit.repairable)

    def test_unrecognised_corruption_is_unknown_and_never_repaired(self):
        data = campaign(kind="legacy")
        data["canvasSettings"]["nodes"].append({"id": "mystery", "positionX": "1", "positionY": "1"})

        audit = audit_campaign(data)
        self.assertEqual(audit.classification, UNKNOWN)
        self.assertFalse(audit.repairable)
        self.assertIsNone(audit.proposed_canvas)

    def test_publish_state_is_reported_and_unchanged_by_the_proposal(self):
        audit = audit_campaign(campaign(kind="legacy", published=True))
        self.assertTrue(audit.published)
        self.assertTrue(audit.repairable)
        self.assertNotIn("isPublished", json.dumps(audit.would_change))

class CampaignFingerprintTests(SimpleTestCase):
    """The fingerprint is re-checked right before a manual repair: any change to
    what the repair must preserve has to show, and nothing else may."""

    def _changed(self, mutate):
        original = campaign(kind="legacy")
        changed = copy.deepcopy(original)
        mutate(changed)
        return campaign_fingerprint(original) != campaign_fingerprint(changed)

    def _event(self, data, index=3):
        return data["events"][index]

    def test_it_is_deterministic_and_ignores_order_and_audit_metadata(self):
        data = campaign(kind="legacy")
        self.assertEqual(campaign_fingerprint(data), campaign_fingerprint(copy.deepcopy(data)))

        for label, mutate in {
            "event order in the payload": lambda d: d["events"].reverse(),
            "canvas node order": lambda d: d["canvasSettings"]["nodes"].reverse(),
            "canvas connection order": lambda d: d["canvasSettings"]["connections"].reverse(),
            "dateModified": lambda d: d.update(dateModified="2026-10-03T00:00:00+00:00"),
            "modifiedBy": lambda d: d.update(modifiedBy=2, modifiedByUser="someone"),
            "a source's own name": lambda d: d["lists"][0].update(name="renamed segment"),
            "event children (derived from parents)": lambda d: self._event(d, 0).update(children=[{"id": 149}]),
        }.items():
            with self.subTest(label):
                self.assertFalse(self._changed(mutate), label)

        two_lists = copy.deepcopy(data)
        two_lists["lists"] = [{"id": 50}, {"id": 51}]
        swapped = copy.deepcopy(two_lists)
        swapped["lists"] = [{"id": 51}, {"id": 50}]
        self.assertEqual(campaign_fingerprint(two_lists), campaign_fingerprint(swapped))

        days = copy.deepcopy(data)
        self._event(days)["triggerRestrictedDaysOfWeek"] = [1, 3]
        days_swapped = copy.deepcopy(days)
        self._event(days_swapped)["triggerRestrictedDaysOfWeek"] = [3, 1]
        self.assertEqual(campaign_fingerprint(days), campaign_fingerprint(days_swapped))

    def test_campaign_level_changes_are_detected(self):
        for label, mutate in {
            "name": lambda d: d.update(name="renamed"),
            "description": lambda d: d.update(description="<p>fixture</p>"),
            "published state": lambda d: d.update(isPublished=True),
            "publish up": lambda d: d.update(publishUp="2030-01-01T00:00:00+00:00"),
            "publish down": lambda d: d.update(publishDown="2030-01-01T00:00:00+00:00"),
            "allow restart": lambda d: d.update(allowRestart=True),
            "republish behaviour": lambda d: d.update(republishBehavior="restart"),
            "category": lambda d: d.update(category={"id": 3}),
        }.items():
            with self.subTest(label):
                self.assertTrue(self._changed(mutate), label)

    def test_source_changes_are_detected_without_any_canvas_or_event_change(self):
        for label, mutate in {
            "segment replaced": lambda d: d.update(lists=[{"id": 51, "name": "phase2c segment"}]),
            "segment added": lambda d: d["lists"].append({"id": 51}),
            "segment removed": lambda d: d.update(lists=[]),
            "form added": lambda d: d.update(forms=[{"id": 7, "name": "signup"}]),
        }.items():
            with self.subTest(label):
                self.assertTrue(self._changed(mutate), label)

    def test_event_level_changes_are_detected(self):
        for label, mutate in {
            "name": lambda d: self._event(d).update(name="renamed step"),
            "description": lambda d: self._event(d).update(description="note"),
            "provider type": lambda d: self._event(d).update(type="lead.changepoints"),
            "event type": lambda d: self._event(d).update(eventType="condition"),
            "order": lambda d: self._event(d).update(order=9),
            "properties": lambda d: self._event(d).update(properties={"add_tags": ["4"]}),
            "parent": lambda d: self._event(d).update(parent={"id": 149}),
            "decision path": lambda d: self._event(d, 1).update(decisionPath="no"),
            "channel": lambda d: self._event(d).update(channel="email", channelId=23),
            "event added": lambda d: d["events"].append({**self._event(d), "id": 999}),
            "event removed": lambda d: d["events"].pop(),
            "canvas": lambda d: d["canvasSettings"]["nodes"][6].update(positionX="999"),
        }.items():
            with self.subTest(label):
                self.assertTrue(self._changed(mutate), label)

    def test_every_preserved_timing_setting_is_detected(self):
        # Phase 2A preserves hidden timing settings; a repair must not race them.
        for label, mutate in {
            "trigger mode": lambda d: self._event(d).update(triggerMode="date"),
            "interval": lambda d: self._event(d).update(triggerInterval=4),
            "interval unit": lambda d: self._event(d).update(triggerIntervalUnit="h"),
            "fixed date": lambda d: self._event(d).update(triggerDate="2030-01-15T09:30:00+00:00"),
            "hour": lambda d: self._event(d).update(triggerHour="10:15"),
            "restricted start hour": lambda d: self._event(d).update(triggerRestrictedStartHour="08:00"),
            "restricted stop hour": lambda d: self._event(d).update(triggerRestrictedStopHour="17:00"),
            "restricted days": lambda d: self._event(d).update(triggerRestrictedDaysOfWeek=[1, 3]),
        }.items():
            with self.subTest(label):
                self.assertTrue(self._changed(mutate), label)


class _ReadOnlyClient:
    """Only the two read calls exist: any write the command tried would raise."""

    calls = []

    def __init__(self, campaigns):
        self._campaigns = {str(c["id"]): c for c in campaigns}

    def list_campaigns(self, **params):
        self.calls.append(("list_campaigns", params))
        rows = [{"id": cid, "name": c["name"]} for cid, c in self._campaigns.items()]
        start, limit = int(params.get("start", 0)), int(params.get("limit", 50))
        return {"total": len(rows), "campaigns": rows[start:start + limit]}

    def get_campaign(self, campaign_id):
        self.calls.append(("get_campaign", str(campaign_id)))
        return copy.deepcopy(self._campaigns[str(campaign_id)])


class AuditCommandTests(SimpleTestCase):
    def _run(self, campaigns, *args):
        _ReadOnlyClient.calls = []
        client = _ReadOnlyClient(campaigns)
        out = StringIO()
        with patch(
            "newsletter.management.commands.audit_frozen_mautic_campaigns.MauticClient",
            return_value=client,
        ):
            call_command("audit_frozen_mautic_campaigns", *args, stdout=out)
        return out.getvalue(), _ReadOnlyClient.calls

    def _fleet(self):
        legacy = campaign(148, kind="legacy")
        healthy = {**campaign(156, kind="current"), "id": 83, "name": "healthy"}
        native = {**campaign(168, kind="native"), "id": 86, "name": "native"}
        return [legacy, healthy, native]

    def test_the_command_only_reads(self):
        output, calls = self._run(self._fleet(), "--json")

        self.assertEqual({name for name, _ in calls}, {"list_campaigns", "get_campaign"})
        report = json.loads(output)
        self.assertEqual(report["mode"], "read-only")
        self.assertEqual(
            report["summary"],
            {LEGACY_ORPHAN_CANVAS: 1, HEALTHY_CURRENT_ECP: 1, HEALTHY_NATIVE: 1},
        )
        legacy = next(c for c in report["campaigns"] if c["campaign_id"] == "81")
        self.assertTrue(legacy["repairable"])
        self.assertEqual(legacy["orphan_nodes"], ["node-1790900000001-trig01"])

    def test_one_campaign_can_be_audited_without_listing_all(self):
        output, calls = self._run(self._fleet(), "--campaign-id", "81")

        self.assertEqual(calls, [("get_campaign", "81")])
        self.assertIn("READ-ONLY audit of 1 Mautic campaign(s)", output)
        self.assertIn("LEGACY_ORPHAN_CANVAS", output)
        self.assertIn("repair: Native Mautic re-save", output)

    def test_the_table_hides_healthy_campaigns_unless_asked(self):
        output, _ = self._run(self._fleet())
        self.assertNotIn("'healthy'", output)
        output, _ = self._run(self._fleet(), "--include-healthy")
        self.assertIn("'healthy'", output)

    def test_there_is_no_apply_mode(self):
        with self.assertRaises(Exception):
            self._run(self._fleet(), "--apply")
