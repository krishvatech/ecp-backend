"""Send a template to one contact (never to Do Not Contact) and bulk tag changes."""

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.contact_bulk_services import BulkActionError, parse_bulk_request, run_bulk_action
from newsletter.mautic import PermanentMauticError
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import MauticIdentityConfigurationError
from newsletter.mautic.operations import ASSERTABLE_OPERATIONS, EMAIL_CONTACT_SEND
from newsletter.models import MauticIdentityAuditLog
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_admin_forms_api import PER_USER_ON
from newsletter.tests.test_mautic_template_client import MAUTIC_SETTINGS, response

User = get_user_model()


def contact(cid=51, email="dana@example.test", dnc=None, tags=()):
    return {"id": cid, "fields": {"all": {"email": email, "firstname": "Dana", "lastname": "L"}},
            "doNotContact": dnc or [], "tags": [{"tag": tag} for tag in tags]}


TEMPLATE = {"id": 22, "name": "Welcome", "emailType": "template", "isPublished": True}


@override_settings(**MAUTIC_SETTINGS)
class SendClientTests(SimpleTestCase):
    def test_send_goes_through_the_bridge_as_the_admin_only(self):
        self.assertIn(EMAIL_CONTACT_SEND, ASSERTABLE_OPERATIONS)
        with self.assertRaises(MauticIdentityConfigurationError):
            MauticClient(session=Mock()).send_template_to_contact(22, 51)
        session = Mock()
        session.request.return_value = response(200, {"success": 1})
        provider = Mock(return_value="signed.jwt")
        MauticClient(session=session, assertion_provider=provider).send_template_to_contact(22, 51)
        call = session.request.call_args
        self.assertEqual((call.args[0], call.args[1].split("/api/")[1]), ("POST", "ecp/bridge/templates/22/contact/51/send"))
        self.assertEqual(provider.call_args.args[0], EMAIL_CONTACT_SEND)


@override_settings(**PER_USER_ON)
class SendApiTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        admin = User.objects.create_superuser(username="send-admin", email="send-admin@example.test", password="x")
        grant_marketing_access(admin, mautic_user_id=6)
        self.api.force_authenticate(admin)
        self.service = Mock(name="service")
        self.service._uses_asserted_user.return_value = False
        self.asserted = Mock(name="asserted")
        self.asserted._uses_asserted_user.return_value = True
        self.asserted.last_assertion_jti = "jti"

        def factory(*args, **kwargs):
            if kwargs.get("assertion_provider") is not None:
                self.asserted.execution_identity = kwargs["execution_identity"]
                return self.asserted
            return self.service

        patcher = patch("newsletter.contact_email_views.MauticClient", side_effect=factory)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.url = reverse("newsletter-admin-contact-send-email", args=["51"])

    def test_a_published_template_is_sent_as_the_admin_and_audited(self):
        self.service.get_contact.return_value = contact()
        self.service.get_email.return_value = TEMPLATE
        self.asserted.send_template_to_contact.return_value = {"success": 1}
        result = self.api.post(self.url, {"emailId": "22"}, format="json")
        self.assertEqual(result.status_code, 200, result.json())
        self.assertEqual(result.json()["to"], "dana@example.test")
        self.asserted.send_template_to_contact.assert_called_once_with("22", "51")
        entry = MauticIdentityAuditLog.objects.get()
        self.assertEqual((entry.action, entry.resource_id, entry.status), (EMAIL_CONTACT_SEND, "51:22", "succeeded"))

    def test_refusals_never_send(self):
        cases = [
            (contact(dnc=[{"channel": "email", "reason": 1}]), TEMPLATE, "contact_dnc"),
            (contact(email=""), TEMPLATE, "contact_no_email"),
            (contact(), {**TEMPLATE, "isPublished": False}, "template_unpublished"),
            (contact(), {**TEMPLATE, "emailType": "list"}, "not_a_template"),
        ]
        for person, template, code in cases:
            with self.subTest(code=code):
                self.service.get_contact.return_value = person
                self.service.get_email.return_value = template
                result = self.api.post(self.url, {"emailId": "22"}, format="json")
                self.assertEqual((result.status_code, result.json()["code"]), (409, code))
        self.assertEqual(self.api.post(self.url, {}, format="json").status_code, 400)
        self.asserted.send_template_to_contact.assert_not_called()

    def test_a_bridge_refusal_is_shown(self):
        self.service.get_contact.return_value = contact()
        self.service.get_email.return_value = TEMPLATE
        self.asserted.send_template_to_contact.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 409): The contact is marked Do Not Contact for email; nothing was sent.")
        result = self.api.post(self.url, {"emailId": "22"}, format="json")
        self.assertEqual((result.status_code, result.json()["code"]), (409, "send_refused"))
        self.assertIn("Do Not Contact", result.json()["detail"])


class BulkTagTests(SimpleTestCase):
    def test_tag_requests_are_validated(self):
        self.assertEqual(parse_bulk_request({"action": "tags_add", "contact_ids": [1], "tags": ["Lead", "lead", " VIP "]})["tags"], ["Lead", "VIP"])
        for tags in ([], ["-Lead"], [""], ["x" * 101], [f"t{i}" for i in range(21)], "Lead"):
            with self.subTest(tags=tags), self.assertRaises(BulkActionError):
                parse_bulk_request({"action": "tags_add", "contact_ids": [1], "tags": tags})

    def test_add_and_remove_are_skipped_when_done_and_read_back(self):
        client = Mock()
        client.get_contact.side_effect = [contact(1, tags=["Lead"]), contact(1, tags=["Lead", "VIP"]),
                                          contact(2, tags=["VIP"])]
        result = run_bulk_action(parse_bulk_request({"action": "tags_add", "contact_ids": [1, 2], "tags": ["VIP"]}), client=client)
        self.assertEqual([r["status"] for r in result["results"]], ["updated", "skipped"])
        client.add_contact_tag.assert_called_once_with("1", "VIP", ["Lead", "VIP"])

        client = Mock()
        client.get_contact.side_effect = [contact(1, tags=["Lead", "VIP", "Old"]), contact(1, tags=["Lead"])]
        result = run_bulk_action(parse_bulk_request({"action": "tags_remove", "contact_ids": [1], "tags": ["vip", "old"]}), client=client)
        self.assertEqual(result["results"][0]["status"], "updated")
        self.assertEqual([c.args for c in client.remove_contact_tag.call_args_list],
                         [("1", "VIP", ["Lead", "Old"]), ("1", "Old", ["Lead"])])

    def test_an_unconfirmed_tag_change_is_a_failure(self):
        client = Mock()
        client.get_contact.side_effect = [contact(1, tags=[]), contact(1, tags=[])]
        result = run_bulk_action(parse_bulk_request({"action": "tags_add", "contact_ids": [1], "tags": ["VIP"]}), client=client)
        self.assertEqual(result["results"][0]["status"], "failed")
