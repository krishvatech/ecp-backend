from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.form_views import parse_form_settings, validate_redirect_url, FormPolicyError
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import (
    MauticBridgeRejectedError,
    MauticIdentityConfigurationError,
    MauticRequestNotSentError,
)
from newsletter.mautic.operations import (
    ASSERTABLE_OPERATIONS,
    FORM_CREATE,
    FORM_PUBLISH,
    FORM_UNPUBLISH,
    FORM_UPDATE,
)
from newsletter.models import MauticIdentityAuditLog, MauticUserConnection, NewsletterCategory
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_template_client import MAUTIC_SETTINGS, response
from newsletter.tests.test_mautic_user_identity import IDENTITY_SETTINGS

User = get_user_model()
PER_USER_ON = {**IDENTITY_SETTINGS, "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": True}


def native_form(**overrides):
    data = {
        "id": 31,
        "name": "Training Inquiry",
        "alias": "traininginq",
        "description": "",
        "isPublished": False,
        "formType": "standalone",
        "postAction": "message",
        "postActionProperty": "Thank you",
        "category": None,
        "cachedHtml": "<form>large</form>",
        "createdByUser": "Ecp DevProof",
        "modifiedByUser": "Ecp DevProof",
        "dateAdded": "2026-10-20T06:00:00+00:00",
        "dateModified": "2026-10-20T06:00:00+00:00",
        "fields": [
            {"id": 3, "label": "Submit", "alias": "submit", "type": "button", "order": 3},
            {"id": 1, "label": "Email", "alias": "email", "type": "email", "order": 1, "isRequired": True,
             "mappedObject": "contact", "mappedField": "email"},
        ],
        "actions": [
            {"id": 7, "name": "Tag", "type": "lead.changetags", "order": 1, "properties": {"add_tags": ["x"]}},
        ],
    }
    data.update(overrides)
    return data


class FormOperationContractTests(SimpleTestCase):
    def test_form_operations_are_assertable_and_match_the_bridge(self):
        self.assertEqual(
            (FORM_CREATE, FORM_UPDATE, FORM_PUBLISH, FORM_UNPUBLISH),
            ("form.create", "form.update", "form.publish", "form.unpublish"),
        )
        for operation in (FORM_CREATE, FORM_UPDATE, FORM_PUBLISH, FORM_UNPUBLISH):
            self.assertIn(operation, ASSERTABLE_OPERATIONS)


class FormSettingsValidationTests(SimpleTestCase):
    def test_create_sends_only_basic_settings(self):
        self.assertEqual(
            parse_form_settings({"name": "  Inquiry ", "description": "D", "postActionProperty": "Thanks",
                                 "formType": "standalone", "isPublished": False}),
            {"name": "Inquiry", "description": "D", "postAction": "message", "postActionProperty": "Thanks"},
        )

    def test_hide_form_is_a_native_choice_that_needs_its_message(self):
        self.assertEqual(
            parse_form_settings({"name": "F", "postAction": "hideform", "postActionProperty": "Bye"}),
            {"name": "F", "postAction": "hideform", "postActionProperty": "Bye"},
        )
        with self.assertRaises(FormPolicyError):
            parse_form_settings({"name": "F", "postAction": "hideform"})
        # An existing hide-form Form can still be renamed.
        self.assertEqual(
            parse_form_settings({"name": "G"}, current=native_form(postAction="hideform", postActionProperty="Bye")),
            {"name": "G"},
        )

    def test_return_clears_the_after_submit_value(self):
        self.assertEqual(
            parse_form_settings({"name": "F", "postAction": "return", "postActionProperty": "ignored"}),
            {"name": "F", "postAction": "return", "postActionProperty": ""},
        )

    def test_invalid_settings_are_rejected_with_codes(self):
        cases = [
            ({}, "invalid_form_settings", "name"),
            ({"name": "   "}, "invalid_form_settings", "name"),
            ({"name": "x" * 192, "postActionProperty": "T"}, "invalid_form_settings", "name"),
            ({"name": "F\x00", "postActionProperty": "T"}, "invalid_form_settings", "name"),
            ({"name": 5, "postActionProperty": "T"}, "invalid_form_settings", "name"),
            ({"name": "F"}, "invalid_form_settings", "postActionProperty"),
            ({"name": "F", "postAction": "popup", "postActionProperty": "T"}, "invalid_form_settings", "postAction"),
            ({"name": "F", "postAction": "redirect"}, "invalid_form_settings", "postActionProperty"),
            ({"name": "F", "postActionProperty": "T", "formType": "campaign"}, "invalid_form_settings", "formType"),
            ({"name": "F", "postActionProperty": "T", "isPublished": True}, "form_publish_separately", "isPublished"),
            ({"name": "F", "postActionProperty": "T", "alias": "x"}, "unsupported_form_settings", ""),
            ({"name": "F", "postActionProperty": "T", "fields": [{"type": "text"}]}, "form_fields_not_supported", "fields"),
            ({"name": "F", "postActionProperty": "T", "actions": [{"type": "lead.changetags"}]}, "form_actions_not_supported", "actions"),
            ({"name": "F", "actions": [{"type": "lead.remove_do_not_contact"}]}, "form_action_prohibited", "actions"),
            ({"name": "F", "actions": [{"type": "email.send.lead"}]}, "form_action_prohibited", "actions"),
            ({"name": "F", "actions": [{"type": "lead.changelist", "properties": {"addToLists": ["70"]}}]},
             "form_action_protected_segment", "actions"),
        ]
        for data, code, field in cases:
            with self.subTest(data=data):
                with self.assertRaises(FormPolicyError) as raised:
                    parse_form_settings(data, protected={"70"})
                self.assertEqual(raised.exception.code, code)
                self.assertEqual(raised.exception.field, field)

    def test_redirect_urls_must_be_absolute_web_addresses_without_tokens(self):
        self.assertEqual(validate_redirect_url("https://imaa.example/thanks?a=1"), "https://imaa.example/thanks?a=1")
        for value in (
            "javascript:alert(1)", "data:text/html,x", "ftp://host/x", "/thanks", "//host/x", "https://",
            "https://host/{contactfield=email}", "https://host/a b", "https://user:pw@host/x", "https://host:99999/",
            "https://" + "a" * 2050,
        ):
            with self.subTest(value=value), self.assertRaises(FormPolicyError):
                validate_redirect_url(value)

    def test_edit_sends_only_what_changes(self):
        current = native_form()
        self.assertEqual(parse_form_settings({"name": "Training Inquiry"}, current=current), {})
        self.assertEqual(parse_form_settings({"name": "New"}, current=current), {"name": "New"})
        self.assertEqual(
            parse_form_settings({"postActionProperty": "Thanks!"}, current=current),
            {"postAction": "message", "postActionProperty": "Thanks!"},
        )
        with self.assertRaises(FormPolicyError):
            parse_form_settings({"postAction": "redirect"}, current=current)
        self.assertEqual(
            parse_form_settings({"postAction": "redirect", "postActionProperty": "https://x.example/t"}, current=current),
            {"postAction": "redirect", "postActionProperty": "https://x.example/t"},
        )


@override_settings(**MAUTIC_SETTINGS)
class FormClientTests(SimpleTestCase):
    def test_form_writes_refuse_the_service_account(self):
        session = Mock()
        client = MauticClient(session=session)
        for call in (
            lambda: client.create_form({"name": "F"}),
            lambda: client.update_form(31, {"name": "F"}),
            lambda: client.set_form_published(31, True),
            lambda: client.set_form_published(31, False),
        ):
            with self.assertRaises(MauticIdentityConfigurationError):
                call()
        session.request.assert_not_called()

    def test_form_writes_use_the_bridge_with_their_operation(self):
        session = Mock()
        session.request.return_value = response(200, {"form": {"id": 31}})
        provider = Mock(return_value="signed.jwt")
        client = MauticClient(session=session, assertion_provider=provider)

        client.create_form({"name": "F", "postAction": "message", "postActionProperty": "T"})
        client.update_form(31, {"name": "G"})
        client.set_form_published(31, True)
        client.set_form_published(31, False)

        calls = [(c.args[0], c.args[1].split("/api/")[1]) for c in session.request.call_args_list]
        self.assertEqual(calls, [
            ("POST", "ecp/bridge/forms/new"),
            ("PATCH", "ecp/bridge/forms/31/edit"),
            ("POST", "ecp/bridge/forms/31/publish"),
            ("POST", "ecp/bridge/forms/31/unpublish"),
        ])
        self.assertEqual([c.args[0] for c in provider.call_args_list], [FORM_CREATE, FORM_UPDATE, FORM_PUBLISH, FORM_UNPUBLISH])
        create_data = dict(session.request.call_args_list[0].kwargs["data"])
        self.assertEqual(create_data, {"name": "F", "postAction": "message", "postActionProperty": "T"})
        self.assertNotIn("data", session.request.call_args_list[2].kwargs)

    def test_get_form_requires_a_numeric_id(self):
        client = MauticClient(session=Mock())
        with self.assertRaises(PermanentMauticError):
            client.get_form("../contacts")


class _FormsApiBase(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.admin = User.objects.create_superuser(
            username="forms-admin", email="forms-admin@example.test", password="test-password",
        )
        grant_marketing_access(self.admin, mautic_user_id=6)
        self.api.force_authenticate(self.admin)

        self.service = Mock(name="service-client")
        self.service._uses_asserted_user.return_value = False
        self.service.get_form.return_value = native_form()
        self.asserted = Mock(name="asserted-client")
        self.asserted._uses_asserted_user.return_value = True
        self.asserted.last_assertion_jti = "jti-form"
        self.asserted.create_form.return_value = {"id": 31}
        self.asserted.update_form.return_value = {"id": 31}
        self.asserted.set_form_published.return_value = {"id": 31}

        def factory(*args, **kwargs):
            if kwargs.get("assertion_provider") is not None:
                self.asserted.execution_identity = kwargs["execution_identity"]
                return self.asserted
            if "execution_identity" in kwargs:
                self.service.execution_identity = kwargs["execution_identity"]
            return self.service

        patcher = patch("newsletter.form_views.MauticClient", side_effect=factory)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.list_url = reverse("newsletter-admin-form-list")
        self.detail_url = reverse("newsletter-admin-form-detail", args=["31"])
        self.publish_url = reverse("newsletter-admin-form-publish", args=["31"])
        self.unpublish_url = reverse("newsletter-admin-form-unpublish", args=["31"])

    def audit(self):
        return list(MauticIdentityAuditLog.objects.order_by("id"))

    def assert_no_writes(self):
        self.asserted.create_form.assert_not_called()
        self.asserted.update_form.assert_not_called()
        self.asserted.set_form_published.assert_not_called()
        self.service.create_form.assert_not_called()
        self.service.update_form.assert_not_called()
        self.service.set_form_published.assert_not_called()


@override_settings(**PER_USER_ON)
class FormsReadApiTests(_FormsApiBase):
    def test_guests_and_non_marketing_users_are_denied(self):
        anonymous = APIClient()
        normal = APIClient()
        normal.force_authenticate(User.objects.create_user(username="forms-normal", email="n@example.test", password="x"))
        for client in (anonymous, normal):
            for method, url in (("get", self.list_url), ("get", self.detail_url), ("post", self.list_url),
                                ("patch", self.detail_url), ("post", self.publish_url), ("post", self.unpublish_url)):
                with self.subTest(method=method, url=url):
                    self.assertIn(getattr(client, method)(url, {}, format="json").status_code, (401, 403))
        self.assert_no_writes()

    def test_list_combines_status_search_sort_and_pagination(self):
        self.service.list_forms.return_value = {"total": 26, "forms": [native_form()]}

        response = self.api.get(self.list_url, {"status": "published", "search": "Inquiry", "sort": "name",
                                                "page": 2, "page_size": 25})

        self.assertEqual(response.status_code, 200)
        self.service.list_forms.assert_called_once_with(
            start=25, limit=25, orderBy="name", orderByDir="ASC", search="is:published Inquiry",
        )
        body = response.json()
        self.assertEqual((body["count"], body["num_pages"]), (26, 2))
        row = body["results"][0]
        self.assertEqual((row["id"], row["fieldCount"], row["actionCount"], row["isPublished"]), ("31", 2, 1, False))
        self.assertNotIn("cachedHtml", row)

    def test_list_rejects_unknown_filters(self):
        for params in ({"status": "deleted"}, {"sort": "random"}):
            self.assertEqual(self.api.get(self.list_url, params).status_code, 400)
        self.service.list_forms.assert_not_called()

    def test_empty_list(self):
        self.service.list_forms.return_value = {"total": 0, "forms": []}
        body = self.api.get(self.list_url).json()
        self.assertEqual((body["count"], body["num_pages"], body["results"]), (0, 0, []))

    def test_detail_shows_ordered_fields_actions_and_publish_readiness(self):
        body = self.api.get(self.detail_url).json()

        self.assertEqual([f["alias"] for f in body["fields"]], ["email", "submit"])
        self.assertEqual(body["fields"][0]["mappedField"], "email")
        self.assertEqual(body["actions"][0]["policy"], "allowed")
        self.assertTrue(body["publishable"])
        self.assertEqual(body["publishBlockers"], [])

    def test_detail_flags_prohibited_and_protected_segment_actions(self):
        NewsletterCategory.objects.create(name="Weekly", slug="weekly", mautic_segment_id="70")
        self.service.get_form.return_value = native_form(actions=[
            {"id": 8, "name": "Undo DNC", "type": "lead.remove_do_not_contact", "order": 1},
            {"id": 9, "name": "Join list", "type": "lead.changelist", "order": 2,
             "properties": {"addToLists": [70], "removeFromLists": []}},
            {"id": 10, "name": "Other segment", "type": "lead.changelist", "order": 3,
             "properties": {"addToLists": [71]}},
        ])

        body = self.api.get(self.detail_url).json()

        self.assertEqual([a["policy"] for a in body["actions"]], ["prohibited", "protected_segment", "allowed"])
        self.assertFalse(body["publishable"])
        self.assertEqual(len(body["publishBlockers"]), 2)

    def test_detail_errors(self):
        self.assertEqual(self.api.get(reverse("newsletter-admin-form-detail", args=["abc"])).status_code, 400)
        self.service.get_form.side_effect = PermanentMauticError("Mautic API request failed (HTTP 404): Item was not found.")
        self.assertEqual(self.api.get(self.detail_url).status_code, 404)
        self.service.get_form.side_effect = TemporaryMauticError("Mautic API request failed (HTTP 500)")
        self.assertEqual(self.api.get(self.detail_url).status_code, 502)


@override_settings(**PER_USER_ON)
class FormsCreateApiTests(_FormsApiBase):
    payload = {"name": "Training Inquiry", "postAction": "message", "postActionProperty": "Thank you"}

    def test_create_runs_as_the_admin_and_returns_the_stored_form(self):
        response = self.api.post(self.list_url, self.payload, format="json")

        self.assertEqual(response.status_code, 201)
        self.asserted.create_form.assert_called_once_with(self.payload)
        self.service.get_form.assert_called_once_with("31")
        self.assertFalse(response.json()["isPublished"])
        [entry] = self.audit()
        self.assertEqual(
            (entry.action, entry.status, entry.resource, entry.resource_id, entry.mautic_user_id, entry.auth_mode, entry.ecp_user_id),
            (FORM_CREATE, "succeeded", "form", "31", 6, "asserted_user", self.admin.pk),
        )

    def test_invalid_input_never_reaches_mautic(self):
        for data in ({"name": ""}, {"name": "F", "postAction": "redirect", "postActionProperty": "javascript:x"},
                     {**self.payload, "isPublished": True}, {**self.payload, "fields": []},
                     {**self.payload, "actions": [{"type": "email.send.lead"}]}, {**self.payload, "template": "x"}):
            with self.subTest(data=data):
                response = self.api.post(self.list_url, data, format="json")
                self.assertEqual(response.status_code, 400)
                self.assertIn("code", response.json())
        self.assert_no_writes()
        self.assertEqual(self.audit(), [])

    @override_settings(**{**PER_USER_ON, "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": False})
    def test_flag_off_fails_closed_without_a_service_account_write(self):
        response = self.api.post(self.list_url, self.payload, format="json")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["code"], "mautic_identity_not_configured")
        self.assert_no_writes()
        [entry] = self.audit()
        self.assertEqual((entry.action, entry.status), (FORM_CREATE, "failed"))

    def test_missing_mautic_connection_is_rejected(self):
        MauticUserConnection.objects.filter(user=self.admin).delete()

        response = self.api.post(self.list_url, self.payload, format="json")

        # Marketing Hub access itself requires the connection, so the request
        # is refused before any Mautic client exists.
        self.assertEqual(response.status_code, 403)
        self.assert_no_writes()

    def test_bridge_permission_refusal_is_reported_and_audited(self):
        self.asserted.create_form.side_effect = MauticBridgeRejectedError("Mautic API request failed (HTTP 403): Access denied.")

        response = self.api.post(self.list_url, self.payload, format="json")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "mautic_permission_denied")
        self.assertEqual(self.audit()[0].status, "denied")

    def test_provider_validation_error_is_shown(self):
        self.asserted.create_form.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 400): postActionProperty: Fill in a valid URL."
        )
        response = self.api.post(self.list_url, self.payload, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "postActionProperty: Fill in a valid URL.")

    def test_uncertain_create_reports_matching_forms_without_retry_or_delete(self):
        self.asserted.create_form.side_effect = TemporaryMauticError("Mautic API request failed")
        recent = timezone.now().isoformat()
        self.service.list_forms.return_value = {"total": 2, "forms": [
            native_form(id=40, dateAdded=recent),
            native_form(id=12, dateAdded="2020-01-01T00:00:00+00:00"),
            native_form(id=41, name="Training Inquiry v2", dateAdded=recent),
        ]}

        response = self.api.post(self.list_url, self.payload, format="json")

        self.assertEqual(response.status_code, 502)
        body = response.json()
        self.assertEqual(body["code"], "form_create_uncertain")
        self.assertTrue(body["verified"])
        self.assertEqual([c["id"] for c in body["candidates"]], ["40"])
        self.assertIn("#40", body["detail"])
        self.asserted.create_form.assert_called_once()
        self.service.delete_form.assert_not_called()
        self.asserted.delete_form.assert_not_called()
        self.assertEqual(self.audit()[0].status, "failed")

    def test_uncertain_create_with_no_match_says_so(self):
        self.asserted.create_form.side_effect = TemporaryMauticError("Mautic API request failed")
        self.service.list_forms.return_value = {"total": 0, "forms": []}
        body = self.api.post(self.list_url, self.payload, format="json").json()
        self.assertEqual((body["code"], body["candidates"]), ("form_create_uncertain", []))

    def test_request_not_sent_is_safe_to_retry(self):
        self.asserted.create_form.side_effect = MauticRequestNotSentError("Mautic API request failed")
        response = self.api.post(self.list_url, self.payload, format="json")
        self.assertEqual(response.status_code, 503)
        self.service.list_forms.assert_not_called()


@override_settings(**PER_USER_ON)
class FormsUpdateApiTests(_FormsApiBase):
    def test_edit_sends_only_changed_basic_settings_and_keeps_structure(self):
        self.service.get_form.side_effect = [native_form(), native_form(name="Renamed")]

        response = self.api.patch(self.detail_url, {"name": "Renamed", "description": ""}, format="json")

        self.assertEqual(response.status_code, 200)
        self.asserted.update_form.assert_called_once_with("31", {"name": "Renamed"})
        self.assertEqual(response.json()["name"], "Renamed")
        [entry] = self.audit()
        self.assertEqual((entry.action, entry.resource_id, entry.detail), (FORM_UPDATE, "31", "changed: name"))

    def test_unchanged_edit_writes_nothing(self):
        response = self.api.patch(self.detail_url, {"name": "Training Inquiry"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["unchanged"])
        self.assert_no_writes()

    def test_edit_of_a_form_with_existing_prohibited_actions_keeps_them(self):
        existing = native_form(actions=[{"id": 8, "name": "Undo DNC", "type": "lead.remove_do_not_contact", "order": 1}])
        self.service.get_form.side_effect = [existing, {**existing, "name": "Renamed"}]

        response = self.api.patch(self.detail_url, {"name": "Renamed"}, format="json")

        self.assertEqual(response.status_code, 200)
        self.asserted.update_form.assert_called_once_with("31", {"name": "Renamed"})
        self.assertEqual(response.json()["actions"][0]["type"], "lead.remove_do_not_contact")

    def test_edit_cannot_change_fields_actions_or_publication(self):
        for data in ({"fields": [{"id": 1, "label": "X"}]}, {"actions": []}, {"isPublished": True},
                     {"actions": [{"type": "lead.remove_do_not_contact"}]}):
            with self.subTest(data=data):
                self.assertEqual(self.api.patch(self.detail_url, data, format="json").status_code, 400)
        self.assert_no_writes()

    def test_a_changed_structure_after_save_is_reported(self):
        self.service.get_form.side_effect = [native_form(), native_form(name="Renamed", actions=[])]
        response = self.api.patch(self.detail_url, {"name": "Renamed"}, format="json")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "form_structure_changed")

    def test_a_reset_after_submit_behaviour_is_not_reported_as_success(self):
        self.service.get_form.side_effect = [native_form(), native_form(name="Renamed", postAction="return")]
        response = self.api.patch(self.detail_url, {"name": "Renamed"}, format="json")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "form_structure_changed")

    def test_uncertain_update_returns_the_verified_state(self):
        self.asserted.update_form.side_effect = TemporaryMauticError("Mautic API request failed")
        response = self.api.patch(self.detail_url, {"name": "Renamed"}, format="json")
        self.assertEqual(response.status_code, 502)
        body = response.json()
        self.assertEqual((body["code"], body["verified"], body["form"]["name"]), ("form_update_uncertain", True, "Training Inquiry"))
        self.asserted.update_form.assert_called_once()

    def test_missing_form_is_not_found(self):
        self.service.get_form.side_effect = PermanentMauticError("Mautic API request failed (HTTP 404)")
        self.assertEqual(self.api.patch(self.detail_url, {"name": "X"}, format="json").status_code, 404)
        self.assert_no_writes()


@override_settings(**PER_USER_ON)
class FormsPublicationApiTests(_FormsApiBase):
    def test_publish_confirms_the_provider_state(self):
        self.service.get_form.side_effect = [native_form(), native_form(isPublished=True)]

        response = self.api.post(self.publish_url)

        self.assertEqual(response.status_code, 200)
        self.asserted.set_form_published.assert_called_once_with("31", True)
        self.assertTrue(response.json()["isPublished"])
        [entry] = self.audit()
        self.assertEqual((entry.action, entry.resource_id, entry.mautic_user_id), (FORM_PUBLISH, "31", 6))

    def test_publish_is_refused_for_an_unusable_form(self):
        for form in (native_form(fields=[]), native_form(fields=[{"id": 1, "type": "button"}]),
                     native_form(fields=[{"id": 1, "type": "email"}]),
                     native_form(actions=[{"id": 2, "type": "email.send.lead", "name": "Send"}])):
            with self.subTest(form=form["fields"]):
                self.service.get_form.side_effect = None
                self.service.get_form.return_value = form
                response = self.api.post(self.publish_url)
                self.assertEqual(response.status_code, 409)
                self.assertTrue(response.json()["publishBlockers"])
        self.assert_no_writes()

    def test_publish_is_refused_when_an_action_targets_a_subscription_list(self):
        NewsletterCategory.objects.create(name="Weekly", slug="weekly", mautic_segment_id="70")
        self.service.get_form.return_value = native_form(actions=[
            {"id": 9, "name": "Join", "type": "lead.changelist", "properties": {"removeFromLists": ["70"]}},
        ])
        self.assertEqual(self.api.post(self.publish_url).status_code, 409)
        self.assert_no_writes()

    def test_unconfirmed_publish_is_not_reported_as_success(self):
        self.service.get_form.side_effect = [native_form(), native_form(), native_form()]
        response = self.api.post(self.publish_url)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["code"], "form_publish_unconfirmed")

    def test_publish_that_reset_after_submit_is_flagged(self):
        self.service.get_form.side_effect = [native_form(), native_form(isPublished=True, postAction="return")]
        response = self.api.post(self.publish_url)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "form_structure_changed")

    def test_already_published_is_a_no_op(self):
        self.service.get_form.return_value = native_form(isPublished=True)
        response = self.api.post(self.publish_url)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["unchanged"])
        self.assert_no_writes()

    def test_unpublish_confirms_the_provider_state(self):
        self.service.get_form.side_effect = [native_form(isPublished=True, fields=[]), native_form(fields=[])]

        response = self.api.post(self.unpublish_url)

        self.assertEqual(response.status_code, 200)
        self.asserted.set_form_published.assert_called_once_with("31", False)
        self.assertEqual(self.audit()[0].action, FORM_UNPUBLISH)

    def test_bridge_conflict_is_shown(self):
        self.service.get_form.side_effect = None
        self.service.get_form.return_value = native_form()
        self.asserted.set_form_published.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 409): The Form cannot be published: The Form has no submit button."
        )
        response = self.api.post(self.publish_url)
        self.assertEqual(response.status_code, 409)
        self.assertIn("no submit button", response.json()["detail"])

    def test_no_delete_route_exists(self):
        self.assertEqual(self.api.delete(self.detail_url).status_code, 405)
        self.assertNotIn("delete_form", dir(MauticClient))


class FormsAuditFilterTests(TestCase):
    def test_form_actions_are_filterable_under_their_own_domain(self):
        admin = User.objects.create_superuser(username="forms-audit", email="fa@example.test", password="x")
        grant_marketing_access(admin)
        MauticIdentityAuditLog.objects.create(ecp_user=admin, action=FORM_CREATE, status="succeeded", resource="form", resource_id="31")
        api = APIClient()
        api.force_authenticate(admin)
        url = reverse("newsletter-admin-marketing-audit")

        by_action = api.get(url, {"action": FORM_CREATE})
        by_domain = api.get(url, {"domain": "forms"})

        self.assertEqual(by_action.status_code, 200)
        self.assertEqual(by_action.json()["count"], 1)
        self.assertEqual(by_domain.json()["count"], 1)
        self.assertIn(FORM_PUBLISH, by_action.json()["filters"]["actions"])
