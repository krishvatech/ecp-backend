from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.response import Response
from rest_framework.test import APIClient

from newsletter import contact_merge_services as svc
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import MauticIdentityConfigurationError
from newsletter.mautic.operations import ASSERTABLE_OPERATIONS, CONTACT_MERGE
from newsletter.models import MauticContactMapping, NewsletterCategory
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_template_client import response

User = get_user_model()
LOCMEM = {"CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "contact-merge-tests"}}}


def contact(cid, *, first="Ada", points=0, owner=None):
    return {"id": int(cid), "points": points, "owner": owner, "dateModified": "2026-10-28T09:00:00+00:00",
            "fields": {"all": {"firstname": first, "lastname": "L", "email": f"c{cid}@x.test"}}}


def fake_client(segments=None):
    segments = segments or {}
    client = Mock()
    client.get_contact.side_effect = lambda cid: contact(cid, first={"3": "Ada", "4": "Adah"}.get(str(cid), "X"))
    client.get_contact_segment_ids.side_effect = lambda cid: set(segments.get(str(cid), set()))
    client.merge_contacts.return_value = {"contactId": 3, "mergedContactId": 4}
    return client


def run_with(client):
    return lambda fn: (fn(client), None)


class MergeParsingTests(SimpleTestCase):
    def test_ids(self):
        self.assertEqual(svc.parse_merge_ids("3", 4), ("3", "4"))
        for kept, other, code in (("3", "3", "same_contact"), ("3", "", "invalid_contact"), ("x", "4", "invalid_contact"), ("3", True, "invalid_contact")):
            with self.subTest(other=other), self.assertRaises(svc.MergeError) as raised:
                svc.parse_merge_ids(kept, other)
            self.assertEqual(raised.exception.code, code)


class MergePreviewTests(TestCase):
    def setUp(self):
        self.member = User.objects.create_user(username="merge-member", email="mm@example.test", password="x")
        self.other_member = User.objects.create_user(username="merge-member2", email="mm2@example.test", password="x")

    def codes(self, preview):
        return [b["code"] for b in preview["blockers"]]

    def test_a_clean_merge_has_no_blockers(self):
        MauticContactMapping.objects.create(user=self.member, mautic_contact_id="3")
        preview = svc.merge_preview("3", "4", client=fake_client())
        self.assertEqual((preview["can_merge"], preview["kept"]["name"], preview["merged_away"]["name"]), (True, "Ada L", "Adah L"))
        self.assertEqual((preview["kept"]["linked_ecp_user_id"], preview["merged_away"]["linked_ecp_user_id"]), (self.member.id, None))

    def test_an_ecp_linked_contact_is_never_the_one_deleted(self):
        MauticContactMapping.objects.create(user=self.member, mautic_contact_id="4")
        preview = svc.merge_preview("3", "4", client=fake_client())
        self.assertEqual(self.codes(preview), ["linked_contact_merged_away"])
        self.assertIn("Open that contact and merge this one into it", preview["blockers"][0]["message"])

    def test_two_ecp_members_are_never_merged(self):
        MauticContactMapping.objects.create(user=self.member, mautic_contact_id="3")
        MauticContactMapping.objects.create(user=self.other_member, mautic_contact_id="4")
        self.assertEqual(self.codes(svc.merge_preview("3", "4", client=fake_client())), ["both_linked"])

    def test_subscription_lists_only_on_the_other_contact_block_the_merge(self):
        NewsletterCategory.objects.create(name="Weekly Digest", slug="weekly-merge", mautic_segment_id="31")
        NewsletterCategory.objects.create(name="Old", slug="old-merge", mautic_segment_id="32",
                                          deletion_state=NewsletterCategory.DeletionState.DELETED)
        # 31 only on the other contact: blocked. 32 is a deleted list, 33 an ordinary segment.
        client = fake_client({"4": {"31", "32", "33"}})
        preview = svc.merge_preview("3", "4", client=client)
        self.assertEqual(self.codes(preview), ["subscription_list_conflict"])
        self.assertIn("Weekly Digest", preview["blockers"][0]["message"])
        self.assertNotIn("Old", preview["blockers"][0]["message"])
        # Already on both: nothing moves, so nothing to refuse.
        self.assertEqual(self.codes(svc.merge_preview("3", "4", client=fake_client({"3": {"31"}, "4": {"31"}}))), [])

    def test_an_already_merged_id_is_refused(self):
        client = fake_client()
        client.get_contact.side_effect = lambda cid: contact(3)  # 4 resolves to its survivor, 3
        with self.assertRaises(svc.MergeError) as raised:
            svc.merge_preview("3", "4", client=client)
        self.assertEqual(raised.exception.code, "already_merged")


class MergeRunTests(TestCase):
    def test_merge_runs_after_the_blockers_are_rechecked(self):
        client = fake_client()
        result = svc.run_merge("3", "4", run_mutation=run_with(client), client=client)
        client.merge_contacts.assert_called_once_with("3", "4")
        self.assertEqual((result["mautic_contact_id"], result["merged_contact_id"]), ("3", "4"))

    def test_a_blocked_merge_never_reaches_mautic(self):
        member = User.objects.create_user(username="merge-run", email="mr@example.test", password="x")
        MauticContactMapping.objects.create(user=member, mautic_contact_id="4")
        client = fake_client()
        with self.assertRaises(svc.MergeError) as raised:
            svc.run_merge("3", "4", run_mutation=run_with(client), client=client)
        self.assertEqual((raised.exception.code, raised.exception.status_code), ("linked_contact_merged_away", 409))
        client.merge_contacts.assert_not_called()

    def test_an_identity_refusal_is_returned_as_is(self):
        refused = Response({"detail": "no"}, status=403)
        result = svc.run_merge("3", "4", run_mutation=lambda fn: (None, refused), client=fake_client())
        self.assertIs(result["identity_response"], refused)


class MergeClientTests(SimpleTestCase):
    def test_merge_requires_the_admins_identity(self):
        session = Mock()
        with self.assertRaises(MauticIdentityConfigurationError):
            MauticClient(session=session).merge_contacts(3, 4)
        session.request.assert_not_called()

    def test_merge_uses_the_bridge_with_its_own_operation(self):
        session = Mock()
        session.request.return_value = response(200, {"contactId": 3, "mergedContactId": 4})
        provider = Mock(return_value="signed.jwt")
        result = MauticClient(session=session, assertion_provider=provider).merge_contacts(3, 4)
        self.assertEqual(result, {"contactId": 3, "mergedContactId": 4})
        self.assertEqual(session.request.call_args.args[:2][0], "POST")
        self.assertTrue(session.request.call_args.args[1].endswith("/api/ecp/bridge/contacts/3/merge/4"))
        provider.assert_called_once_with(CONTACT_MERGE)
        self.assertIn(CONTACT_MERGE, ASSERTABLE_OPERATIONS)


@override_settings(**LOCMEM)
class MergeApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="merge-admin", email="ma@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api = APIClient()
        self.api.force_authenticate(self.admin)
        self.url = reverse("newsletter-admin-contact-merge", args=["3"])

    def test_preview_and_errors(self):
        with patch("newsletter.contact_merge_views.merge_preview", return_value={"can_merge": True}) as preview:
            self.assertEqual(self.api.get(self.url, {"other_contact_id": "4"}).json(), {"can_merge": True})
        preview.assert_called_once_with("3", "4")
        r = self.api.get(self.url, {"other_contact_id": "3"})
        self.assertEqual((r.status_code, r.json()["code"]), (400, "same_contact"))
        with patch("newsletter.contact_merge_views.merge_preview", side_effect=PermanentMauticError("Mautic API request failed (HTTP 404)")):
            self.assertEqual(self.api.get(self.url, {"other_contact_id": "4"}).json()["code"], "contact_not_found")

    def test_plugin_refusals_map_to_codes(self):
        cases = [
            (PermanentMauticError("Mautic API request failed (HTTP 409): ... a Subscription List the kept contact is not."), 409, "subscription_list_conflict"),
            (PermanentMauticError("Mautic API request failed (HTTP 409): One of the contacts is being edited"), 409, "contact_locked"),
            (TemporaryMauticError("down"), 502, "mautic_error"),
            (svc.MergeError("blocked", code="both_linked", status_code=409), 409, "both_linked"),
        ]
        for exc, status_code, code in cases:
            with self.subTest(code=code), patch("newsletter.contact_merge_views.run_merge", side_effect=exc):
                r = self.api.post(self.url, {"other_contact_id": "4"}, format="json")
            self.assertEqual((r.status_code, r.json()["code"]), (status_code, code))

    def test_contact_campaigns_lists_every_membership(self):
        rows = [{"id": 7, "name": "Draft", "published": False, "manuallyAdded": True, "dateAdded": "2026-10-28 09:00:00"}]
        with patch.object(MauticClient, "get_contact_campaigns", return_value=rows):
            body = self.api.get(reverse("newsletter-admin-contact-campaigns", args=["3"])).json()
        self.assertEqual(body, {"count": 1, "results": [
            {"id": "7", "name": "Draft", "published": False, "manually_added": True, "date_added": "2026-10-28 09:00:00"}]})
        self.assertEqual(self.api.get(reverse("newsletter-admin-contact-campaigns", args=["x"])).status_code, 400)

    def test_non_marketing_users_are_denied(self):
        normal = APIClient()
        normal.force_authenticate(User.objects.create_user(username="merge-normal", email="mn@example.test", password="x"))
        self.assertIn(normal.post(self.url, {"other_contact_id": "4"}, format="json").status_code, (401, 403))
        self.assertIn(normal.get(reverse("newsletter-admin-contact-campaigns", args=["3"])).status_code, (401, 403))
