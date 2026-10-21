from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.form_actions import (
    ActionPolicyError,
    action_matches,
    normalize_action,
    parse_action_order,
    plan_action_update,
    plan_new_action,
    unexpected_changes,
)
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import MauticBridgeRejectedError, MauticIdentityConfigurationError
from newsletter.mautic.operations import (
    ASSERTABLE_OPERATIONS,
    FORM_ACTION_CREATE,
    FORM_ACTION_REORDER,
    FORM_ACTION_UPDATE,
)
from newsletter.models import MauticIdentityAuditLog, NewsletterCategory
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_admin_forms_api import PER_USER_ON, native_form
from newsletter.tests.test_mautic_template_client import MAUTIC_SETTINGS, response

User = get_user_model()
TAGS = {"5": "Lead", "6": "Webinar"}
TAG_ROWS = [{"id": 5, "tag": "Lead"}, {"id": 6, "tag": "Webinar"}]


def with_actions(actions, **overrides):
    return native_form(actions=actions, **overrides)


TAG_ACTION = {"id": 7, "name": "Tag", "description": None, "type": "lead.changetags", "order": 1,
              "properties": {"add_tags": ["Lead"], "remove_tags": []}}
POINTS_ACTION = {"id": 8, "name": "Score", "description": None, "type": "lead.pointschange", "order": 2,
                 "properties": {"operator": "plus", "points": 5, "group": 3}}


class ActionContractTests(SimpleTestCase):
    def test_action_operations_are_assertable_and_match_the_bridge(self):
        self.assertEqual((FORM_ACTION_CREATE, FORM_ACTION_UPDATE, FORM_ACTION_REORDER),
                         ("form.action.create", "form.action.update", "form.action.reorder"))
        for operation in (FORM_ACTION_CREATE, FORM_ACTION_UPDATE, FORM_ACTION_REORDER):
            self.assertIn(operation, ASSERTABLE_OPERATIONS)


class ActionRuleTests(SimpleTestCase):
    def test_new_tag_and_points_actions_become_native_settings(self):
        native, position = plan_new_action({"type": "lead.changetags", "name": " Tag ", "addTags": ["5", 6], "removeTags": []},
                                           with_actions([]), TAGS)
        self.assertEqual(native, {"type": "lead.changetags", "name": "Tag", "description": "",
                                  "properties": {"add_tags": ["5", "6"], "remove_tags": []}})
        native, _ = plan_new_action({"type": "lead.pointschange", "name": "Score", "operator": "minus", "points": "3"},
                                    with_actions([]), TAGS)
        self.assertEqual(native["properties"], {"operator": "minus", "points": 3})

    def test_unsafe_unsupported_and_invalid_actions_are_refused(self):
        cases = [
            ({"type": "lead.remove_do_not_contact", "name": "x"}, "form_action_prohibited"),
            ({"type": "email.send.lead", "name": "x"}, "form_action_prohibited"),
            ({"type": "lead.changelist", "name": "x"}, "form_action_deferred"),
            ({"type": "form.repost", "name": "x"}, "unsupported_form_action_type"),
            ({"type": "lead.updatelead", "name": "x"}, "unsupported_form_action_type"),
            ({"type": "email.send.user", "name": "x"}, "unsupported_form_action_type"),
            ({"name": "x"}, "unsupported_form_action_type"),
            ({"type": "lead.changetags", "name": "", "addTags": ["5"], "removeTags": []}, "invalid_form_action"),
            ({"type": "lead.changetags", "name": "x", "addTags": [], "removeTags": []}, "invalid_form_action"),
            ({"type": "lead.changetags", "name": "x", "addTags": ["5"], "removeTags": ["5"]}, "invalid_form_action"),
            ({"type": "lead.changetags", "name": "x", "addTags": ["999"], "removeTags": []}, "invalid_form_action"),
            ({"type": "lead.changetags", "name": "x", "addTags": ["Lead"], "removeTags": []}, "invalid_form_action"),
            ({"type": "lead.pointschange", "name": "x", "operator": "times", "points": 2}, "invalid_form_action"),
            ({"type": "lead.pointschange", "name": "x", "operator": "plus"}, "invalid_form_action"),
            ({"type": "lead.pointschange", "name": "x", "operator": "plus", "points": 0}, "invalid_form_action"),
            ({"type": "lead.pointschange", "name": "x", "operator": "plus", "points": 1.5}, "invalid_form_action"),
            ({"type": "lead.pointschange", "name": "x", "operator": "plus", "points": 10001}, "invalid_form_action"),
            ({"type": "lead.pointschange", "name": "x", "operator": "plus", "points": 1, "group": 3}, "unsupported_form_action_settings"),
            ({"type": "lead.changetags", "name": "x", "addTags": ["5"], "removeTags": [], "properties": {}}, "unsupported_form_action_settings"),
        ]
        for data, code in cases:
            with self.subTest(data=data), self.assertRaises(ActionPolicyError) as raised:
                plan_new_action(data, with_actions([]), TAGS)
            self.assertEqual(raised.exception.code, code)

    def test_stored_tag_names_map_back_to_ids_and_unknown_names_lock_the_lists(self):
        action = normalize_action(TAG_ACTION, TAGS)
        self.assertEqual((action["addTags"], action["settingsLocked"], action["editable"]),
                         ([{"name": "Lead", "id": "5"}], "", True))
        orphan = normalize_action({**TAG_ACTION, "properties": {"add_tags": ["Gone"], "remove_tags": []}}, TAGS)
        self.assertTrue(orphan["settingsLocked"])
        with self.assertRaises(ActionPolicyError) as raised:
            plan_action_update({"addTags": ["6"]}, {**TAG_ACTION, "properties": {"add_tags": ["Gone"], "remove_tags": []}}, TAGS)
        self.assertEqual(raised.exception.code, "form_action_settings_locked")
        # A rename of such an action is still possible: its tags are untouched.
        self.assertEqual(plan_action_update({"name": "Renamed"}, {**TAG_ACTION, "properties": {"add_tags": ["Gone"], "remove_tags": []}}, TAGS),
                         {"name": "Renamed"})

    def test_updates_send_only_changes(self):
        self.assertEqual(plan_action_update({"name": "Tag"}, TAG_ACTION, TAGS), {})
        self.assertEqual(plan_action_update({"addTags": ["5", "6"]}, TAG_ACTION, TAGS),
                         {"properties": {"add_tags": ["5", "6"], "remove_tags": []}})
        self.assertEqual(plan_action_update({"points": 7}, POINTS_ACTION, TAGS), {"properties": {"operator": "plus", "points": 7}})
        with self.assertRaises(ActionPolicyError):
            plan_action_update({"type": "lead.pointschange"}, TAG_ACTION, TAGS)

    def test_existing_unsafe_and_unmanaged_actions_are_read_only(self):
        for action in ({"id": 9, "type": "lead.remove_do_not_contact", "name": "Undo"},
                       {"id": 10, "type": "lead.changelist", "name": "Join", "properties": {"addToLists": [4]}},
                       {"id": 11, "type": "form.email", "name": "Notify"},
                       {**POINTS_ACTION, "properties": {"operator": "times", "points": 2}}):
            with self.subTest(type=action["type"]):
                normalized = normalize_action(action, TAGS)
                self.assertTrue(not normalized["editable"] or normalized["settingsLocked"])
        with self.assertRaises(ActionPolicyError):
            plan_action_update({"name": "x"}, {"id": 9, "type": "lead.remove_do_not_contact", "name": "Undo"}, TAGS)

    def test_order_and_read_back(self):
        form = with_actions([TAG_ACTION, POINTS_ACTION])
        self.assertEqual(parse_action_order({"order": [8, "7"]}, form), ["8", "7"])
        for order in (["7"], ["7", "7"], ["7", "8", "9"]):
            with self.assertRaises(ActionPolicyError):
                parse_action_order({"order": order}, form)
        after = with_actions([TAG_ACTION, {**POINTS_ACTION, "name": "Changed"}], postAction="return")
        problems = unexpected_changes(form, after, target_id="7", expected_order=["7", "8"])
        self.assertIn("action 8 changed", problems)
        self.assertIn("postAction changed", problems)
        self.assertTrue(action_matches(TAG_ACTION, {"type": "lead.changetags", "properties": {"add_tags": ["5"], "remove_tags": []}}, TAGS))
        self.assertFalse(action_matches(TAG_ACTION, {"type": "lead.changetags", "properties": {"add_tags": ["6"], "remove_tags": []}}, TAGS))


@override_settings(**MAUTIC_SETTINGS)
class ActionClientTests(SimpleTestCase):
    def test_action_writes_refuse_the_service_account(self):
        session = Mock()
        client = MauticClient(session=session)
        for call in (lambda: client.create_form_action(1, {}), lambda: client.update_form_action(1, 2, {}),
                     lambda: client.reorder_form_actions(1, [2])):
            with self.assertRaises(MauticIdentityConfigurationError):
                call()
        session.request.assert_not_called()

    def test_action_writes_and_reads_use_their_routes(self):
        session = Mock()
        session.request.return_value = response(200, {"form": {"id": 31}, "usage": {}, "submissions": [], "submission": {"id": 4}})
        provider = Mock(return_value="signed.jwt")
        client = MauticClient(session=session, assertion_provider=provider)
        client.create_form_action(31, {"type": "lead.changetags"}, 1)
        client.update_form_action(31, 7, {"name": "x"})
        client.reorder_form_actions(31, ["8", "7"])
        client.get_form_usage(31)
        client.list_form_submissions(31, start=25, limit=25)
        client.get_form_submission(31, 4)
        calls = [(c.args[0], c.args[1].split("/api/")[1]) for c in session.request.call_args_list]
        self.assertEqual(calls, [
            ("POST", "ecp/bridge/forms/31/actions/new"), ("PATCH", "ecp/bridge/forms/31/actions/7/edit"),
            ("POST", "ecp/bridge/forms/31/actions/reorder"), ("GET", "ecp/bridge/forms/31/usage"),
            ("GET", "forms/31/submissions"), ("GET", "forms/31/submissions/4"),
        ])
        self.assertEqual([c.args[0] for c in provider.call_args_list], [FORM_ACTION_CREATE, FORM_ACTION_UPDATE, FORM_ACTION_REORDER])
        self.assertEqual(session.request.call_args_list[4].kwargs["params"], {"start": 25, "limit": 25, "orderBy": "s.id", "orderByDir": "DESC"})


class _ApiBase(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="actions-admin", email="actions-admin@example.test", password="x")
        grant_marketing_access(self.admin, mautic_user_id=6)
        self.api.force_authenticate(self.admin)
        self.service = Mock(name="service")
        self.service._uses_asserted_user.return_value = False
        self.service.list_tags.return_value = {"tags": TAG_ROWS}
        self.asserted = Mock(name="asserted")
        self.asserted._uses_asserted_user.return_value = True
        self.asserted.last_assertion_jti = "jti"

        def factory(*args, **kwargs):
            if kwargs.get("assertion_provider") is not None:
                self.asserted.execution_identity = kwargs["execution_identity"]
                return self.asserted
            return self.service

        patcher = patch("newsletter.form_views.MauticClient", side_effect=factory)
        patcher.start()
        self.addCleanup(patcher.stop)

    def assert_no_writes(self):
        for name in ("create_form_action", "update_form_action", "reorder_form_actions"):
            getattr(self.asserted, name).assert_not_called()


@override_settings(**PER_USER_ON)
class ActionApiTests(_ApiBase):
    def setUp(self):
        super().setUp()
        self.before = with_actions([TAG_ACTION, POINTS_ACTION])
        self.list_url = reverse("newsletter-admin-form-action-list", args=["31"])

    def test_add_tag_action_as_the_admin_and_verify_read_back(self):
        new = {"id": 12, "name": "Webinar", "description": "", "type": "lead.changetags", "order": 3,
               "properties": {"add_tags": ["Webinar"], "remove_tags": []}}
        self.service.get_form.side_effect = [self.before, with_actions([TAG_ACTION, POINTS_ACTION, new])]
        self.asserted.create_form_action.return_value = with_actions([TAG_ACTION, POINTS_ACTION, new])

        response = self.api.post(self.list_url, {"type": "lead.changetags", "name": "Webinar", "addTags": ["6"], "removeTags": []}, format="json")

        self.assertEqual(response.status_code, 201, response.json())
        self.assertEqual(response.json()["actionId"], "12")
        self.asserted.create_form_action.assert_called_once_with(
            "31", {"type": "lead.changetags", "name": "Webinar", "description": "", "properties": {"add_tags": ["6"], "remove_tags": []}}, None)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual((entry.action, entry.resource, entry.resource_id, entry.mautic_user_id, entry.status),
                         (FORM_ACTION_CREATE, "form_action", "31:12", 6, "succeeded"))

    def test_read_back_with_changed_fields_is_not_success(self):
        new = {"id": 12, "name": "W", "type": "lead.changetags", "order": 3, "properties": {"add_tags": ["Webinar"], "remove_tags": []}}
        changed = with_actions([TAG_ACTION, POINTS_ACTION, new], fields=[])
        self.service.get_form.side_effect = [self.before, changed]
        self.asserted.create_form_action.return_value = changed
        response = self.api.post(self.list_url, {"type": "lead.changetags", "name": "W", "addTags": ["6"], "removeTags": []}, format="json")
        self.assertEqual((response.status_code, response.json()["code"]), (409, "form_action_write_mismatch"))

    def test_unsafe_actions_never_reach_mautic(self):
        self.service.get_form.return_value = self.before
        for data in ({"type": "lead.remove_do_not_contact", "name": "x"}, {"type": "email.send.lead", "name": "x"},
                     {"type": "lead.changelist", "name": "x"}, {"type": "plugin.leadpush", "name": "x"}):
            with self.subTest(data=data):
                self.assertEqual(self.api.post(self.list_url, data, format="json").status_code, 400)
        self.assert_no_writes()
        self.assertFalse(MauticIdentityAuditLog.objects.exists())

    def test_update_points_keeps_the_group_through_the_bridge(self):
        after = with_actions([TAG_ACTION, {**POINTS_ACTION, "properties": {"operator": "plus", "points": 9, "group": 3}}])
        self.service.get_form.side_effect = [self.before, after]
        self.asserted.update_form_action.return_value = after
        response = self.api.patch(reverse("newsletter-admin-form-action-detail", args=["31", "8"]), {"points": 9}, format="json")
        self.assertEqual(response.status_code, 200, response.json())
        self.asserted.update_form_action.assert_called_once_with("31", "8", {"properties": {"operator": "plus", "points": 9}})

    def test_rename_must_not_touch_settings(self):
        after = with_actions([{**TAG_ACTION, "name": "Renamed", "properties": {"add_tags": [], "remove_tags": []}}, POINTS_ACTION])
        self.service.get_form.side_effect = [self.before, after]
        self.asserted.update_form_action.return_value = after
        response = self.api.patch(reverse("newsletter-admin-form-action-detail", args=["31", "7"]), {"name": "Renamed"}, format="json")
        self.assertEqual(response.status_code, 409)

    def test_existing_prohibited_action_cannot_be_edited(self):
        self.service.get_form.return_value = with_actions([{"id": 9, "type": "lead.remove_do_not_contact", "name": "Undo", "order": 1}])
        response = self.api.patch(reverse("newsletter-admin-form-action-detail", args=["31", "9"]), {"name": "Again"}, format="json")
        self.assertEqual((response.status_code, response.json()["code"]), (400, "form_action_prohibited"))
        self.assert_no_writes()

    def test_reorder(self):
        after = with_actions([{**POINTS_ACTION, "order": 1}, {**TAG_ACTION, "order": 2}])
        self.service.get_form.side_effect = [self.before, after]
        self.asserted.reorder_form_actions.return_value = after
        response = self.api.post(reverse("newsletter-admin-form-action-reorder", args=["31"]), {"order": ["8", "7"]}, format="json")
        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(MauticIdentityAuditLog.objects.get().action, FORM_ACTION_REORDER)

    def test_identity_and_provider_failures(self):
        self.service.get_form.return_value = self.before
        body = {"type": "lead.pointschange", "name": "S", "operator": "plus", "points": 1}
        with override_settings(**{**PER_USER_ON, "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": False}):
            self.assertEqual(self.api.post(self.list_url, body, format="json").status_code, 503)
        self.asserted.create_form_action.side_effect = MauticBridgeRejectedError("Mautic API request failed (HTTP 403)")
        self.assertEqual(self.api.post(self.list_url, body, format="json").status_code, 403)
        self.asserted.create_form_action.side_effect = TemporaryMauticError("timeout")
        response = self.api.post(self.list_url, body, format="json")
        self.assertEqual((response.status_code, response.json()["code"]), (502, "form_action_write_uncertain"))

    def test_metadata_offers_only_safe_actions(self):
        body = self.api.get(reverse("newsletter-admin-form-action-metadata")).json()
        self.assertEqual([t["type"] for t in body["actionTypes"]], ["lead.changetags", "lead.pointschange"])
        self.assertEqual([t["name"] for t in body["tags"]], ["Lead", "Webinar"])

    def test_detail_shows_existing_actions_with_their_policy(self):
        NewsletterCategory.objects.create(name="Weekly", slug="weekly", mautic_segment_id="70")
        self.service.get_form.return_value = with_actions([TAG_ACTION, {"id": 9, "type": "lead.changelist", "name": "Join", "order": 2,
                                                                         "properties": {"addToLists": [70]}}])
        actions = self.api.get(reverse("newsletter-admin-form-detail", args=["31"])).json()["actions"]
        self.assertEqual([(a["type"], a["editable"], a["policy"]) for a in actions],
                         [("lead.changetags", True, "allowed"), ("lead.changelist", False, "protected_segment")])
        self.assertEqual(actions[0]["addTags"], [{"name": "Lead", "id": "5"}])


SUBMISSION = {
    "id": 44, "dateSubmitted": "2026-10-20T10:00:00+00:00", "ipAddress": {"ipAddress": "10.0.0.1"}, "trackingId": "t",
    "referer": "https://site.example/?email=x", "form": {"id": 31, "name": "Training Inquiry"},
    "lead": {"id": 501, "email": "dana@example.test", "phone": "+15550100", "address1": "1 Road"},
    "results": {"email": "dana@example.test", "secret": "hunter2", "notes": "<b>hi</b>", "old_field": "kept",
                "form_id": "31", "submission_id": "44"},
}


@override_settings(**PER_USER_ON)
class SubmissionApiTests(_ApiBase):
    def setUp(self):
        super().setUp()
        self.form = native_form(fields=[
            {"id": 1, "label": "Email", "alias": "email", "type": "email", "order": 1},
            {"id": 2, "label": "Secret", "alias": "secret", "type": "password", "order": 2},
            {"id": 3, "label": "Notes", "alias": "notes", "type": "textarea", "order": 3},
            {"id": 4, "label": "Submit", "alias": "submit", "type": "button", "order": 4},
        ])
        self.service.get_form.return_value = self.form
        self.list_url = reverse("newsletter-admin-form-submission-list", args=["31"])
        self.detail_url = reverse("newsletter-admin-form-submission-detail", args=["31", "44"])

    def test_list_is_paginated_minimal_and_never_cached(self):
        self.service.list_form_submissions.return_value = {"total": 120, "submissions": [SUBMISSION]}
        response = self.api.get(self.list_url, {"page": 3, "page_size": 500})
        self.assertEqual(response.status_code, 200)
        self.service.list_form_submissions.assert_called_once_with("31", start=100, limit=50, timeout=10)
        body = response.json()
        self.assertEqual((body["count"], body["num_pages"], body["page_size"]), (120, 3, 50))
        row = body["results"][0]
        self.assertEqual(row["contact"], {"id": "501", "email": "dana@example.test"})
        self.assertNotIn("hunter2", response.content.decode())
        self.assertNotIn("10.0.0.1", response.content.decode())
        self.assertNotIn("+15550100", response.content.decode())
        self.assertEqual(response["Cache-Control"], "no-store, private")

    def test_detail_labels_values_masks_passwords_and_audits_the_view(self):
        self.service.get_form_submission.return_value = SUBMISSION
        response = self.api.get(self.detail_url)
        self.assertEqual(response.status_code, 200)
        values = {v["alias"]: v for v in response.json()["values"]}
        self.assertEqual(values["email"]["label"], "Email")
        self.assertEqual((values["secret"]["masked"], values["secret"]["value"]), (True, None))
        self.assertEqual(values["notes"]["value"], "<b>hi</b>")  # escaped by the UI, never interpreted
        self.assertTrue(values["old_field"]["removedField"])
        self.assertNotIn("submit", values)
        self.assertNotIn("form_id", values)
        self.assertNotIn("submission_id", values)
        self.assertNotIn("hunter2", response.content.decode())
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual((entry.action, entry.resource_id, entry.detail), ("form.submission.view", "31:44", ""))
        self.assertEqual(response["Cache-Control"], "no-store, private")

    def test_a_submission_of_another_form_is_not_found(self):
        self.service.get_form_submission.return_value = {**SUBMISSION, "form": {"id": 99}}
        self.assertEqual(self.api.get(self.detail_url).status_code, 404)
        self.assertFalse(MauticIdentityAuditLog.objects.exists())

    def test_provider_errors_and_bad_ids(self):
        self.service.get_form_submission.side_effect = PermanentMauticError("Mautic API request failed (HTTP 404)")
        self.assertEqual(self.api.get(self.detail_url).status_code, 404)
        self.service.list_form_submissions.side_effect = TemporaryMauticError("timeout")
        self.assertEqual(self.api.get(self.list_url).status_code, 502)
        self.assertEqual(self.api.get(reverse("newsletter-admin-form-submission-detail", args=["31", "x"])).status_code, 400)

    def test_submissions_are_refused_to_non_marketing_users_and_guests(self):
        other = APIClient()
        other.force_authenticate(User.objects.create_user(username="subs-normal", email="sn@example.test", password="x"))
        for client in (other, APIClient()):
            for url in (self.list_url, self.detail_url, reverse("newsletter-admin-form-usage", args=["31"])):
                self.assertIn(client.get(url).status_code, (401, 403))
        self.service.list_form_submissions.assert_not_called()
        self.service.get_form_submission.assert_not_called()

    def test_usage_summary(self):
        self.service.get_form_usage.return_value = {
            "campaignSources": [{"id": 3, "name": "Nurture", "published": True}],
            "campaignEvents": [{"id": 9, "type": "form.submit", "campaignId": 3}],
            "pointActions": [], "submissions": {"total": 4, "latest": "2026-10-20 10:00:00"}}
        body = self.api.get(reverse("newsletter-admin-form-usage", args=["31"])).json()
        self.assertEqual((body["campaignSources"][0]["name"], body["submissions"]["total"]), ("Nurture", 4))
