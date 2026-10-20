from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.form_fields import (
    FieldPolicyError,
    contact_field_choices,
    normalize_field,
    parse_order,
    plan_field_update,
    plan_new_field,
    suggest_alias,
    unexpected_changes,
)
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import MauticBridgeRejectedError, MauticIdentityConfigurationError
from newsletter.mautic.operations import (
    ASSERTABLE_OPERATIONS,
    FORM_FIELD_CREATE,
    FORM_FIELD_REORDER,
    FORM_FIELD_UPDATE,
)
from newsletter.models import MauticIdentityAuditLog
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_admin_forms_api import PER_USER_ON, native_form
from newsletter.tests.test_mautic_template_client import MAUTIC_SETTINGS, response

User = get_user_model()

CONTACT_FIELDS = {
    "email": "email", "firstname": "text", "lastname": "text", "mobile": "tel",
    "country": "country", "company": "text", "website": "url", "points": "number",
}
NATIVE_CONTACT_ROWS = [
    {"alias": "email", "label": "Email", "type": "email", "isPublished": True, "group": "core"},
    {"alias": "firstname", "label": "First Name", "type": "text", "isPublished": True, "group": "core"},
    {"alias": "mobile", "label": "Mobile", "type": "tel", "isPublished": True, "group": "core"},
    {"alias": "country", "label": "Country", "type": "country", "isPublished": True, "group": "core"},
    {"alias": "ecp_newsletter_opt_in", "label": "Newsletter opt-in", "type": "boolean", "isPublished": True},
    {"alias": "points", "label": "Points", "type": "number", "isPublished": True},
    {"alias": "hidden_one", "label": "Retired", "type": "text", "isPublished": False},
]


def form_with(fields=None, **overrides):
    return native_form(fields=fields if fields is not None else [
        {"id": 1, "label": "Email", "alias": "email", "type": "email", "order": 1, "isRequired": True,
         "mappedObject": "contact", "mappedField": "email", "properties": []},
        {"id": 2, "label": "Interest", "alias": "interest", "type": "select", "order": 2,
         "properties": {"list": {"list": [{"label": "A", "value": "a"}]}, "placeholder": "Pick", "multiple": "0", "syncList": "0"}},
        {"id": 3, "label": "Submit", "alias": "submit", "type": "button", "order": 3, "properties": []},
    ], **overrides)


class FieldContractTests(SimpleTestCase):
    def test_field_operations_are_assertable_and_match_the_bridge(self):
        self.assertEqual((FORM_FIELD_CREATE, FORM_FIELD_UPDATE, FORM_FIELD_REORDER),
                         ("form.field.create", "form.field.update", "form.field.reorder"))
        for operation in (FORM_FIELD_CREATE, FORM_FIELD_UPDATE, FORM_FIELD_REORDER):
            self.assertIn(operation, ASSERTABLE_OPERATIONS)


class NewFieldRuleTests(SimpleTestCase):
    def plan(self, data, form=None):
        return plan_new_field(data, form or form_with(), CONTACT_FIELDS)

    def test_text_field_with_mapping_becomes_native_settings(self):
        native, position = self.plan({"type": "text", "label": "First name", "mappedField": "firstname",
                                      "placeholder": "Jane", "helpMessage": "As on your ID", "position": 0})
        self.assertEqual(native, {
            "type": "text", "alias": "first_name", "label": "First name", "helpMessage": "As on your ID",
            "mappedObject": "contact", "mappedField": "firstname", "properties": {"placeholder": "Jane"},
        })
        self.assertEqual(position, 0)

    def test_option_fields_use_the_native_serialisation(self):
        select, _ = self.plan({"type": "select", "label": "Topic", "options": [{"label": "X", "value": "x"}], "multiple": True, "defaultValue": "x"})
        # The full native property set, as Mautic's own builder stores it.
        self.assertEqual(select["properties"], {"placeholder": "", "multiple": "1", "syncList": "0", "list": {"list": [{"label": "X", "value": "x"}]}})
        radio, _ = self.plan({"type": "radiogrp", "label": "Level", "options": [{"label": "Jr", "value": "jr"}]})
        # Without syncList Mautic's group template renders no choices at all.
        self.assertEqual(radio["properties"], {"syncList": "0", "optionlist": {"list": [{"label": "Jr", "value": "jr"}]}})

    def test_required_email_and_hidden_and_button(self):
        email, _ = self.plan({"type": "email", "label": "Work email", "isRequired": True, "validationMessage": "Required"},
                             form_with(fields=[]))
        self.assertEqual((email["isRequired"], email["validationMessage"]), (True, "Required"))
        hidden, _ = self.plan({"type": "hidden", "label": "Source", "defaultValue": "ecp"})
        self.assertEqual((hidden["type"], hidden["defaultValue"]), ("hidden", "ecp"))
        button, _ = self.plan({"type": "button", "label": "Send"}, form_with(fields=[]))
        self.assertEqual(button, {"type": "button", "alias": "send", "label": "Send"})

    def test_rejections(self):
        cases = [
            ({"type": "captcha", "label": "X"}, "unsupported_form_field_type"),
            ({"type": "file", "label": "X"}, "unsupported_form_field_type"),
            ({"type": "text"}, "invalid_form_field"),
            ({"type": "text", "label": "X", "inputAttributes": "onclick=1"}, "unsupported_form_field_settings"),
            ({"type": "button", "label": "Again"}, "form_field_duplicate_button"),
            ({"type": "hidden", "label": "H", "isRequired": True}, "unsupported_form_field_settings"),
            ({"type": "button", "label": "B", "mappedField": "email"}, "unsupported_form_field_settings"),
            ({"type": "text", "label": "X", "options": [{"label": "a", "value": "a"}]}, "unsupported_form_field_settings"),
            ({"type": "select", "label": "X"}, "invalid_form_field"),
            ({"type": "select", "label": "X", "options": [{"label": "", "value": "a"}]}, "invalid_form_field"),
            ({"type": "select", "label": "X", "options": [{"label": "A", "value": "a"}, {"label": "B", "value": "a"}]}, "invalid_form_field"),
            ({"type": "select", "label": "X", "options": [{"label": "A", "value": "a"}], "defaultValue": "z"}, "invalid_form_field"),
            ({"type": "text", "label": "X", "mappedField": "email"}, "form_field_invalid_mapping"),
            ({"type": "email", "label": "X", "mappedField": "email"}, "form_field_duplicate_mapping"),
            ({"type": "checkboxgrp", "label": "Opt in", "mappedField": "ecp_newsletter_opt_in",
              "options": [{"label": "Yes", "value": "1"}]}, "form_field_protected_mapping"),
            ({"type": "hidden", "label": "Score", "mappedField": "points"}, "form_field_protected_mapping"),
            ({"type": "text", "label": "X", "mappedField": "nope"}, "form_field_invalid_mapping"),
            ({"type": "text", "label": "X", "alias": "email"}, "invalid_form_field"),
            ({"type": "text", "label": "X", "alias": "formid"}, "invalid_form_field"),
            ({"type": "text", "label": "X", "alias": "Bad Alias"}, "invalid_form_field"),
            ({"type": "number", "label": "N", "defaultValue": "abc"}, "invalid_form_field"),
            ({"type": "number", "label": "N", "precision": "11"}, "invalid_form_field"),
            ({"type": "text", "label": "X", "position": 9}, "invalid_form_field"),
        ]
        for data, code in cases:
            with self.subTest(data=data), self.assertRaises(FieldPolicyError) as raised:
                self.plan(data)
            self.assertEqual(raised.exception.code, code)

    def test_alias_suggestions_are_unique_and_native_safe(self):
        self.assertEqual(suggest_alias("First Name", set()), "first_name")
        self.assertEqual(suggest_alias("First Name", {"first_name"}), "first_name_2")
        self.assertEqual(suggest_alias("2026 Budget", set()), "f_2026_budget")
        self.assertEqual(suggest_alias("Return", set()), "f_return")
        self.assertTrue(len(suggest_alias("x" * 60, set())) <= 25)


class FieldUpdateRuleTests(SimpleTestCase):
    def test_only_changed_settings_are_sent(self):
        form = form_with()
        select = form["fields"][1]
        native = plan_field_update({"label": "Interest area", "placeholder": "Pick"}, select, form, CONTACT_FIELDS)
        self.assertEqual(native, {"label": "Interest area"})

    def test_options_replace_the_list_and_keep_other_properties_to_the_bridge(self):
        form = form_with()
        native = plan_field_update({"options": [{"label": "A", "value": "a"}, {"label": "B", "value": "b"}]}, form["fields"][1], form, CONTACT_FIELDS)
        self.assertEqual(native, {"properties": {"list": {"list": [{"label": "A", "value": "a"}, {"label": "B", "value": "b"}]}}})

    def test_type_and_alias_are_immutable(self):
        form = form_with()
        for data in ({"type": "text"}, {"alias": "other"}):
            with self.assertRaises(FieldPolicyError) as raised:
                plan_field_update(data, form["fields"][0], form, CONTACT_FIELDS)
            self.assertEqual(raised.exception.code, "form_field_immutable")

    def test_unmapping_and_remapping(self):
        form = form_with()
        self.assertEqual(plan_field_update({"mappedField": ""}, form["fields"][0], form, CONTACT_FIELDS),
                         {"mappedObject": "", "mappedField": ""})
        with self.assertRaises(FieldPolicyError):
            plan_field_update({"mappedField": "firstname"}, form["fields"][0], form, CONTACT_FIELDS)

    def test_unsupported_existing_field_types_are_left_to_mautic(self):
        form = form_with(fields=[{"id": 9, "type": "captcha", "alias": "c", "label": "C", "order": 1}])
        with self.assertRaises(FieldPolicyError) as raised:
            plan_field_update({"label": "X"}, form["fields"][0], form, CONTACT_FIELDS)
        self.assertEqual(raised.exception.code, "form_field_managed_in_mautic")

    def test_order_must_be_a_permutation(self):
        form = form_with()
        self.assertEqual(parse_order({"order": ["3", 1, "2"]}, form), ["3", "1", "2"])
        for order in (["1", "2"], ["1", "1", "2"], ["1", "2", "3", "4"], "1,2,3"):
            with self.assertRaises(FieldPolicyError):
                parse_order({"order": order}, form)


class ReadBackTests(SimpleTestCase):
    def test_unexpected_changes_are_named(self):
        before = form_with()
        after = form_with(postAction="return")
        after["fields"][2] = {**after["fields"][2], "label": "Changed"}
        problems = unexpected_changes(before, after, target_id="2")
        self.assertIn("field 3 changed", problems)
        self.assertIn("postAction changed", problems)
        self.assertEqual(unexpected_changes(before, form_with(), target_id="2"), [])

    def test_contact_choices_hide_protected_and_unpublished_fields(self):
        aliases = [row["alias"] for row in contact_field_choices(NATIVE_CONTACT_ROWS)]
        self.assertEqual(aliases, ["country", "email", "firstname", "mobile"])
        email = next(row for row in contact_field_choices(NATIVE_CONTACT_ROWS) if row["alias"] == "email")
        self.assertEqual(email["fieldTypes"], ["email"])

    def test_normalized_fields_carry_options_and_lock_reasons(self):
        field = normalize_field(form_with()["fields"][1])
        self.assertEqual((field["options"], field["placeholder"], field["editable"]), ([{"label": "A", "value": "a"}], "Pick", True))
        self.assertFalse(normalize_field({"id": 1, "type": "captcha"})["editable"])


@override_settings(**MAUTIC_SETTINGS)
class FieldClientTests(SimpleTestCase):
    def test_field_writes_refuse_the_service_account(self):
        session = Mock()
        client = MauticClient(session=session)
        for call in (lambda: client.create_form_field(1, {"type": "text"}), lambda: client.update_form_field(1, 2, {"label": "x"}),
                     lambda: client.reorder_form_fields(1, [2, 1])):
            with self.assertRaises(MauticIdentityConfigurationError):
                call()
        session.request.assert_not_called()

    def test_field_writes_use_their_bridge_route_and_operation(self):
        session = Mock()
        session.request.return_value = response(200, {"form": {"id": 31}})
        provider = Mock(return_value="signed.jwt")
        client = MauticClient(session=session, assertion_provider=provider)
        client.create_form_field(31, {"type": "text", "label": "X"}, 0)
        client.update_form_field(31, 4, {"label": "Y"})
        client.reorder_form_fields(31, ["4", "5"])
        calls = [(c.args[0], c.args[1].split("/api/")[1], c.kwargs.get("json")) for c in session.request.call_args_list]
        self.assertEqual(calls, [
            ("POST", "ecp/bridge/forms/31/fields/new", {"field": {"type": "text", "label": "X"}, "position": 0}),
            ("PATCH", "ecp/bridge/forms/31/fields/4/edit", {"field": {"label": "Y"}}),
            ("POST", "ecp/bridge/forms/31/fields/reorder", {"order": [4, 5]}),
        ])
        self.assertEqual([c.args[0] for c in provider.call_args_list], [FORM_FIELD_CREATE, FORM_FIELD_UPDATE, FORM_FIELD_REORDER])


@override_settings(**PER_USER_ON)
class FieldApiTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.admin = User.objects.create_superuser(username="fields-admin", email="fields-admin@example.test", password="x")
        grant_marketing_access(self.admin, mautic_user_id=6)
        self.api.force_authenticate(self.admin)
        self.service = Mock(name="service")
        self.service._uses_asserted_user.return_value = False
        self.service.list_fields.return_value = {"fields": NATIVE_CONTACT_ROWS}
        self.asserted = Mock(name="asserted")
        self.asserted._uses_asserted_user.return_value = True
        self.asserted.last_assertion_jti = "jti"

        def factory(*args, **kwargs):
            if kwargs.get("assertion_provider") is not None:
                self.asserted.execution_identity = kwargs["execution_identity"]
                return self.asserted
            return self.service

        for target in ("newsletter.form_views.MauticClient",):
            patcher = patch(target, side_effect=factory)
            patcher.start()
            self.addCleanup(patcher.stop)
        cache = patch("newsletter.form_views.marketing_cache.fields", side_effect=lambda client, obj, limit: client.list_fields(obj))
        cache.start()
        self.addCleanup(cache.stop)

        self.before = form_with()
        self.fields_url = reverse("newsletter-admin-form-field-list", args=["31"])
        self.field_url = reverse("newsletter-admin-form-field-detail", args=["31", "2"])
        self.reorder_url = reverse("newsletter-admin-form-field-reorder", args=["31"])

    def after_adding(self, field):
        after = form_with()
        after["fields"] = after["fields"] + [{"order": 4, **field}]
        return after

    def assert_no_writes(self):
        self.asserted.create_form_field.assert_not_called()
        self.asserted.update_form_field.assert_not_called()
        self.asserted.reorder_form_fields.assert_not_called()

    def test_metadata_lists_types_and_safe_contact_fields(self):
        body = self.api.get(reverse("newsletter-admin-form-builder-metadata")).json()
        self.assertEqual([t["type"] for t in body["fieldTypes"]][:3], ["text", "email", "tel"])
        self.assertNotIn("captcha", [t["type"] for t in body["fieldTypes"]])
        self.assertNotIn("ecp_newsletter_opt_in", [c["alias"] for c in body["contactFields"]])
        self.assertIn("single Form type", body["formTypeNote"])

    def test_add_field_as_the_admin_and_verify_read_back(self):
        stored = {"id": 44, "label": "First name", "alias": "first_name", "type": "text",
                  "mappedObject": "contact", "mappedField": "firstname", "properties": {"placeholder": ""}}
        self.service.get_form.side_effect = [self.before, self.after_adding(stored)]
        self.asserted.create_form_field.return_value = self.after_adding(stored)

        response = self.api.post(self.fields_url, {"type": "text", "label": "First name", "mappedField": "firstname"}, format="json")

        self.assertEqual(response.status_code, 201, response.json())
        self.assertEqual(response.json()["fieldId"], "44")
        self.asserted.create_form_field.assert_called_once_with(
            "31", {"type": "text", "alias": "first_name", "label": "First name", "mappedObject": "contact", "mappedField": "firstname",
                   "properties": {"placeholder": ""}}, None)
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual((entry.action, entry.resource, entry.resource_id, entry.mautic_user_id, entry.auth_mode, entry.status),
                         (FORM_FIELD_CREATE, "form_field", "31:44", 6, "asserted_user", "succeeded"))
        self.assertIn("first_name", entry.detail)

    def test_a_read_back_that_changed_other_settings_is_not_success(self):
        stored = {"id": 44, "label": "First name", "alias": "first_name", "type": "text", "properties": {"placeholder": ""}}
        changed = self.after_adding(stored)
        changed["postAction"] = "return"
        self.service.get_form.side_effect = [self.before, changed]
        self.asserted.create_form_field.return_value = changed
        response = self.api.post(self.fields_url, {"type": "text", "label": "First name"}, format="json")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "form_field_write_mismatch")
        self.assertIn("postAction changed", response.json()["detail"])

    def test_invalid_fields_never_reach_mautic(self):
        self.service.get_form.return_value = self.before
        for data in ({"type": "file", "label": "Upload"}, {"type": "button", "label": "Two"},
                     {"type": "checkboxgrp", "label": "Opt", "mappedField": "ecp_newsletter_opt_in", "options": [{"label": "Y", "value": "1"}]},
                     {"type": "text", "label": "X", "mappedField": "email"}):
            with self.subTest(data=data):
                self.assertEqual(self.api.post(self.fields_url, data, format="json").status_code, 400)
        self.assert_no_writes()
        self.assertFalse(MauticIdentityAuditLog.objects.exists())

    def test_update_sends_only_changes_and_checks_the_field(self):
        after = form_with()
        after["fields"][1] = {**after["fields"][1], "label": "Interest area"}
        self.service.get_form.side_effect = [self.before, after]
        self.asserted.update_form_field.return_value = after

        response = self.api.patch(self.field_url, {"label": "Interest area", "placeholder": "Pick"}, format="json")

        self.assertEqual(response.status_code, 200, response.json())
        self.asserted.update_form_field.assert_called_once_with("31", "2", {"label": "Interest area"})
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual((entry.action, entry.resource_id, entry.detail), (FORM_FIELD_UPDATE, "31:2", "changed: label"))

    def test_update_that_drops_other_properties_is_flagged(self):
        after = form_with()
        after["fields"][1] = {**after["fields"][1], "label": "Interest area",
                              "properties": {"list": {"list": [{"label": "A", "value": "a"}]}}}
        self.service.get_form.side_effect = [self.before, after]
        self.asserted.update_form_field.return_value = after
        response = self.api.patch(self.field_url, {"label": "Interest area"}, format="json")
        self.assertEqual(response.status_code, 409)

    def test_unchanged_update_writes_nothing(self):
        self.service.get_form.return_value = self.before
        response = self.api.patch(self.field_url, {"label": "Interest"}, format="json")
        self.assertTrue(response.json()["unchanged"])
        self.assert_no_writes()

    def test_reorder_verifies_the_new_order(self):
        after = form_with()
        after["fields"] = [{**f, "order": n} for n, f in enumerate(reversed(after["fields"]), start=1)]
        self.service.get_form.side_effect = [self.before, after]
        self.asserted.reorder_form_fields.return_value = after
        response = self.api.post(self.reorder_url, {"order": ["3", "2", "1"]}, format="json")
        self.assertEqual(response.status_code, 200, response.json())
        self.asserted.reorder_form_fields.assert_called_once_with("31", ["3", "2", "1"])
        self.assertEqual([f["id"] for f in response.json()["fields"]], ["3", "2", "1"])
        self.assertEqual(MauticIdentityAuditLog.objects.get().action, FORM_FIELD_REORDER)

    def test_reorder_not_applied_is_reported(self):
        self.service.get_form.side_effect = [self.before, form_with()]
        self.asserted.reorder_form_fields.return_value = form_with()
        response = self.api.post(self.reorder_url, {"order": ["3", "2", "1"]}, format="json")
        self.assertEqual(response.status_code, 409)

    def test_conditional_forms_are_left_to_mautic(self):
        self.service.get_form.return_value = form_with(fields=[
            {"id": 1, "type": "select", "alias": "a", "order": 1}, {"id": 2, "type": "text", "alias": "b", "order": 2, "parent": "1"}])
        for call in (lambda: self.api.post(self.fields_url, {"type": "text", "label": "X"}, format="json"),
                     lambda: self.api.patch(reverse("newsletter-admin-form-field-detail", args=["31", "1"]), {"label": "Y"}, format="json"),
                     lambda: self.api.post(self.reorder_url, {"order": ["2", "1"]}, format="json")):
            response = call()
            self.assertEqual(response.status_code, 409)
            self.assertEqual(response.json()["code"], "form_fields_managed_in_mautic")
        self.assert_no_writes()

    @override_settings(**{**PER_USER_ON, "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": False})
    def test_without_per_user_identity_nothing_is_written(self):
        self.service.get_form.return_value = self.before
        response = self.api.post(self.fields_url, {"type": "text", "label": "X"}, format="json")
        self.assertEqual(response.status_code, 503)
        self.service.create_form_field.assert_not_called()
        self.assertEqual(MauticIdentityAuditLog.objects.get().status, "failed")

    def test_bridge_refusal_and_provider_errors(self):
        self.service.get_form.return_value = self.before
        self.asserted.create_form_field.side_effect = MauticBridgeRejectedError("Mautic API request failed (HTTP 403)")
        self.assertEqual(self.api.post(self.fields_url, {"type": "text", "label": "X"}, format="json").status_code, 403)
        self.asserted.create_form_field.side_effect = PermanentMauticError("Mautic API request failed (HTTP 400): Another field already uses this alias.")
        response = self.api.post(self.fields_url, {"type": "text", "label": "X"}, format="json")
        self.assertEqual((response.status_code, response.json()["detail"]), (400, "Another field already uses this alias."))
        self.asserted.create_form_field.side_effect = TemporaryMauticError("Mautic API request failed")
        response = self.api.post(self.fields_url, {"type": "text", "label": "X"}, format="json")
        self.assertEqual((response.status_code, response.json()["code"]), (502, "form_field_write_uncertain"))
        self.assertEqual(self.asserted.create_form_field.call_count, 3)

    def test_non_marketing_users_are_refused(self):
        other = APIClient()
        other.force_authenticate(User.objects.create_user(username="fields-normal", email="fn@example.test", password="x"))
        for method, url in (("get", self.fields_url), ("post", self.fields_url), ("patch", self.field_url), ("post", self.reorder_url)):
            self.assertEqual(getattr(other, method)(url, {}, format="json").status_code, 403)
        self.assert_no_writes()

    def test_there_is_no_field_delete(self):
        self.assertEqual(self.api.delete(self.field_url).status_code, 405)
        self.assertNotIn("delete_form_field", dir(MauticClient))
