from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import resolve, reverse
from rest_framework.response import Response
from rest_framework.test import APIClient

from newsletter import contact_bulk_services as svc
from newsletter.contact_services import _normalize_contact_payload, contact_filter_params
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import MauticIdentityConfigurationError
from newsletter.mautic.operations import ASSERTABLE_OPERATIONS, CAMPAIGN_CONTACT_ADD, CAMPAIGN_CONTACT_REMOVE
from newsletter.models import NewsletterCategory
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_template_client import MAUTIC_SETTINGS, response

User = get_user_model()
LOCMEM = {"CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "contact-bulk-tests"}}}


def contact(cid, *, owner=None, dnc=None, first="Ada"):
    return {"id": cid, "owner": owner, "doNotContact": dnc or [], "fields": {"all": {"firstname": first, "lastname": "L", "email": f"c{cid}@x.test"}}}


def fake_client(**overrides):
    client = Mock()
    client.get_segment.return_value = {"id": 5, "name": "Hot leads", "filters": []}
    client.get_campaign.return_value = {"id": 7, "name": "Summit follow-up"}
    client.get_user.return_value = {"id": 6, "firstName": "Rahul", "lastName": "Shah", "isPublished": True}
    client.get_contact.side_effect = lambda cid: contact(cid)
    for key, value in overrides.items():
        setattr(client, key, value)
    return client


class BulkParsingTests(SimpleTestCase):
    def test_valid_requests(self):
        self.assertEqual(svc.parse_bulk_request({"action": "segment_add", "contact_ids": [3, "3", 4], "segment_id": "5"}),
                         {"action": "segment_add", "contact_ids": ["3", "4"], "segment_id": "5"})
        self.assertEqual(svc.parse_bulk_request({"action": "owner_set", "contact_ids": [3], "owner_id": None})["owner_id"], "")
        self.assertEqual(svc.parse_bulk_request({"action": "dnc_add", "contact_ids": [3]})["reason"], "")

    def test_invalid_requests_have_codes(self):
        cases = [
            ({"action": "dnc_remove", "contact_ids": [3]}, "invalid_action"),
            ({"action": "tags_add", "contact_ids": [3]}, "invalid_action"),
            ({"action": "segment_add", "contact_ids": [3]}, "invalid_target"),
            ({"action": "segment_add", "contact_ids": [3], "segment_id": True}, "invalid_target"),
            ({"action": "campaign_add", "contact_ids": [3], "segment_id": 5}, "invalid_payload"),
            ({"action": "owner_set", "contact_ids": [3], "owner_id": "abc"}, "invalid_target"),
            ({"action": "dnc_add", "contact_ids": [3], "reason": "x" * 256}, "invalid_target"),
            ({"action": "dnc_add", "contact_ids": []}, "invalid_contact_ids"),
            ({"action": "dnc_add", "contact_ids": list(range(1, 102))}, "invalid_contact_ids"),
        ]
        for data, code in cases:
            with self.subTest(data=data), self.assertRaises(svc.BulkActionError) as raised:
                svc.parse_bulk_request(data)
            self.assertEqual(raised.exception.code, code)


class BulkRunTests(TestCase):
    def test_segment_add_skips_members_updates_others_and_confirms(self):
        memberships = {"3": {"5"}, "4": set()}
        client = fake_client()
        client.get_contact_segment_ids.side_effect = lambda cid: set(memberships[cid])
        client.add_contact_to_segment.side_effect = lambda seg, cid: memberships[cid].add(seg)
        result = svc.run_bulk_action(svc.parse_bulk_request({"action": "segment_add", "contact_ids": [3, 4], "segment_id": 5}), client=client)
        self.assertEqual((result["updated"], result["skipped"], result["failed"]), (1, 1, 0))
        self.assertEqual([r["status"] for r in result["results"]], ["skipped", "updated"])
        self.assertEqual(result["target"], {"type": "segment", "id": "5", "name": "Hot leads"})
        client.add_contact_to_segment.assert_called_once_with("5", "4")

    def test_an_unconfirmed_change_is_a_failure_not_success(self):
        client = fake_client()
        client.get_contact_segment_ids.return_value = set()
        result = svc.run_bulk_action(svc.parse_bulk_request({"action": "segment_add", "contact_ids": [3], "segment_id": 5}), client=client)
        self.assertEqual((result["failed"], result["results"][0]["message"]), (1, "Mautic did not confirm the segment change."))

    def test_subscription_list_segments_are_refused_before_reading_mautic(self):
        NewsletterCategory.objects.create(name="Weekly", slug="weekly-bulk", mautic_segment_id="5")
        client = fake_client()
        with self.assertRaises(svc.BulkActionError) as raised:
            svc.run_bulk_action(svc.parse_bulk_request({"action": "segment_remove", "contact_ids": [3], "segment_id": 5}), client=client)
        self.assertEqual((raised.exception.code, raised.exception.status_code), ("subscription_list_segment", 409))
        client.get_segment.assert_not_called()

    def test_dynamic_segments_are_refused(self):
        client = fake_client()
        client.get_segment.return_value = {"id": 5, "filters": [{"field": "email"}]}
        with self.assertRaises(svc.BulkActionError) as raised:
            svc.run_bulk_action(svc.parse_bulk_request({"action": "segment_add", "contact_ids": [3], "segment_id": 5}), client=client)
        self.assertEqual(raised.exception.code, "segment_not_static")

    def test_campaign_remove(self):
        memberships = {"3": {"7"}}
        client = fake_client()
        client.get_contact_campaign_ids.side_effect = lambda cid: set(memberships[cid])
        client.remove_contact_from_campaign.side_effect = lambda camp, cid: memberships[cid].discard(camp)
        result = svc.run_bulk_action(svc.parse_bulk_request({"action": "campaign_remove", "contact_ids": [3], "campaign_id": 7}), client=client)
        self.assertEqual(result["updated"], 1)
        client.remove_contact_from_campaign.assert_called_once_with("7", "3")

    def test_owner_set_and_clear(self):
        owners = {"3": None, "4": {"id": 6, "firstName": "Rahul", "lastName": "Shah"}}
        client = fake_client()
        client.get_contact.side_effect = lambda cid: contact(cid, owner=owners[cid])
        client.update_contact.side_effect = lambda cid, payload: owners.__setitem__(cid, {"id": 6} if payload["owner"] else None)
        result = svc.run_bulk_action(svc.parse_bulk_request({"action": "owner_set", "contact_ids": [3, 4], "owner_id": 6}), client=client)
        self.assertEqual([r["status"] for r in result["results"]], ["updated", "skipped"])
        self.assertEqual(result["target"]["name"], "Rahul Shah")
        client.update_contact.assert_called_once_with("3", {"owner": 6})
        cleared = svc.run_bulk_action(svc.parse_bulk_request({"action": "owner_set", "contact_ids": [3, 4], "owner_id": ""}), client=client)
        self.assertEqual((cleared["updated"], cleared["target"]["name"]), (2, "No owner"))

    def test_an_inactive_owner_is_refused(self):
        client = fake_client()
        client.get_user.return_value = {"id": 6, "isPublished": False}
        with self.assertRaises(svc.BulkActionError) as raised:
            svc.run_bulk_action(svc.parse_bulk_request({"action": "owner_set", "contact_ids": [3], "owner_id": 6}), client=client)
        self.assertEqual(raised.exception.code, "owner_inactive")

    def test_dnc_add_skips_existing_and_records_the_reason(self):
        dnc = {"3": [{"channel": "email", "reason": 1}], "4": []}
        client = fake_client()
        client.get_contact.side_effect = lambda cid: contact(cid, dnc=dnc[cid])
        client.add_contact_dnc.side_effect = lambda cid, channel, **kw: dnc[cid].append({"channel": channel})
        result = svc.run_bulk_action(svc.parse_bulk_request({"action": "dnc_add", "contact_ids": [3, 4], "reason": "Asked"}), client=client)
        self.assertEqual([r["status"] for r in result["results"]], ["skipped", "updated"])
        client.add_contact_dnc.assert_called_once_with("4", "email", reason=3, comments="Asked")

    def test_one_contact_failing_does_not_stop_the_rest(self):
        client = fake_client()
        client.get_contact.side_effect = lambda cid: (_ for _ in ()).throw(PermanentMauticError("HTTP 404")) if cid == "3" else contact(cid)
        client.get_contact_campaign_ids.side_effect = [set(), {"7"}]
        result = svc.run_bulk_action(svc.parse_bulk_request({"action": "campaign_add", "contact_ids": [3, 4], "campaign_id": 7}), client=client)
        self.assertEqual([r["status"] for r in result["results"]], ["failed", "updated"])

    def test_an_identity_refusal_aborts_the_whole_request(self):
        client = fake_client()
        client.get_contact_campaign_ids.return_value = set()
        refused = Response({"code": "mautic_permission_denied"}, status=403)
        with self.assertRaises(svc.BulkActionAbort):
            svc.run_bulk_action(svc.parse_bulk_request({"action": "campaign_add", "contact_ids": [3, 4], "campaign_id": 7}), client=client,
                                run_mutation=lambda *args: (None, refused))


class OwnerFieldTests(SimpleTestCase):
    def test_owner_in_contact_edits(self):
        self.assertEqual(_normalize_contact_payload({"owner": "6"}, partial=True), {"owner": 6})
        self.assertEqual(_normalize_contact_payload({"owner": None}, partial=True), {"owner": ""})
        with self.assertRaises(ValueError):
            _normalize_contact_payload({"owner": "x"}, partial=True)

    def test_stage_and_owner_filters_combine(self):
        self.assertEqual(contact_filter_params(stage_id="9", owner_id="none"), {
            "where[0][col]": "stage_id", "where[0][expr]": "eq", "where[0][val]": "9",
            "where[1][col]": "owner_id", "where[1][expr]": "isNull",
        })
        self.assertEqual(contact_filter_params(owner_id="6"), {"where[0][col]": "owner_id", "where[0][expr]": "eq", "where[0][val]": "6"})
        with self.assertRaises(ValueError):
            contact_filter_params(owner_id="abc")

    def test_owner_choices_are_active_users_by_name(self):
        client = Mock()
        client.list_users.return_value = {"users": [
            {"id": 7, "firstName": "Zoe", "lastName": "B", "email": "z@x", "isPublished": True},
            {"id": 6, "firstName": "Amy", "lastName": "C", "email": "a@x", "isPublished": True},
            {"id": 8, "firstName": "Old", "lastName": "D", "isPublished": False},
        ]}
        self.assertEqual([o["id"] for o in svc.list_owner_choices(client)], ["6", "7"])


@override_settings(**MAUTIC_SETTINGS)
class CampaignMembershipClientTests(SimpleTestCase):
    def test_campaign_membership_writes_require_the_admins_identity(self):
        session = Mock()
        client = MauticClient(session=session)
        for call in (lambda: client.add_contact_to_campaign(7, 3), lambda: client.remove_contact_from_campaign(7, 3)):
            with self.assertRaises(MauticIdentityConfigurationError):
                call()
        session.request.assert_not_called()

    def test_campaign_membership_writes_use_the_bridge(self):
        session = Mock()
        session.request.return_value = response(200, {"success": 1})
        provider = Mock(return_value="signed.jwt")
        client = MauticClient(session=session, assertion_provider=provider)
        client.add_contact_to_campaign(7, 3)
        client.remove_contact_from_campaign(7, 3)
        self.assertEqual([c.args[1].split("/api/")[1] for c in session.request.call_args_list],
                         ["ecp/bridge/campaigns/7/contact/3/add", "ecp/bridge/campaigns/7/contact/3/remove"])
        self.assertEqual([c.args[0] for c in provider.call_args_list], [CAMPAIGN_CONTACT_ADD, CAMPAIGN_CONTACT_REMOVE])
        for operation in (CAMPAIGN_CONTACT_ADD, CAMPAIGN_CONTACT_REMOVE):
            self.assertIn(operation, ASSERTABLE_OPERATIONS)

    def test_membership_reads_include_unpublished_campaigns(self):
        session = Mock()
        session.request.return_value = response(200, {"campaigns": [{"id": 7, "published": False}, {"id": 9, "published": True}]})
        self.assertEqual(MauticClient(session=session).get_contact_campaign_ids(3), {"7", "9"})
        self.assertTrue(session.request.call_args.args[1].endswith("/api/ecp/contacts/3/campaign-memberships"))


@override_settings(**LOCMEM)
class BulkApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="bulk-admin", email="ba@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api = APIClient()
        self.api.force_authenticate(self.admin)
        self.url = reverse("newsletter-admin-contact-bulk-action")

    def test_static_routes_are_not_contact_ids(self):
        self.assertEqual(resolve("/api/newsletter/admin/contacts/bulk/").url_name, "newsletter-admin-contact-bulk-action")
        self.assertEqual(resolve("/api/newsletter/admin/contacts/owners/").url_name, "newsletter-admin-contact-owners")

    def test_invalid_requests_never_reach_mautic(self):
        with patch("newsletter.contact_bulk_views.run_bulk_action") as run:
            r = self.api.post(self.url, {"action": "dnc_remove", "contact_ids": [3]}, format="json")
        self.assertEqual((r.status_code, r.json()["code"]), (400, "invalid_action"))
        run.assert_not_called()

    def test_results_and_errors_are_returned(self):
        with patch("newsletter.contact_bulk_views.run_bulk_action", return_value={"updated": 1}):
            self.assertEqual(self.api.post(self.url, {"action": "dnc_add", "contact_ids": [3]}, format="json").json(), {"updated": 1})
        with patch("newsletter.contact_bulk_views.run_bulk_action",
                   side_effect=svc.BulkActionError("managed", code="subscription_list_segment", status_code=409)):
            r = self.api.post(self.url, {"action": "segment_add", "contact_ids": [3], "segment_id": 5}, format="json")
        self.assertEqual((r.status_code, r.json()["code"]), (409, "subscription_list_segment"))
        with patch("newsletter.contact_bulk_views.run_bulk_action", side_effect=TemporaryMauticError("down")):
            self.assertEqual(self.api.post(self.url, {"action": "dnc_add", "contact_ids": [3]}, format="json").status_code, 502)

    def test_owner_choices_endpoint(self):
        with patch("newsletter.contact_bulk_views.list_owner_choices", return_value=[{"id": "6", "name": "Amy", "email": ""}]):
            body = self.api.get(reverse("newsletter-admin-contact-owners")).json()
        self.assertEqual(body, {"count": 1, "results": [{"id": "6", "name": "Amy", "email": ""}]})

    def test_non_marketing_users_are_denied(self):
        normal = APIClient()
        normal.force_authenticate(User.objects.create_user(username="bulk-normal", email="bn@example.test", password="x"))
        self.assertIn(normal.post(self.url, {"action": "dnc_add", "contact_ids": [3]}, format="json").status_code, (401, 403))
        self.assertIn(normal.get(reverse("newsletter-admin-contact-owners")).status_code, (401, 403))
