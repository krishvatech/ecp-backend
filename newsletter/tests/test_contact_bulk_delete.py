"""Marketing Hub bulk delete of Mautic contacts.

Only the HTTP session is faked (an in-memory Mautic): identity resolution,
assertion signing, bridge routing, auditing and the deletion plan run for real.
"""

from __future__ import annotations

import json
import time
from unittest.mock import Mock, patch

import jwt
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter import contact_delete_services as services
from newsletter.mautic import MauticClient
from newsletter.mautic.client import ECP_IDENTITY_ASSERTION_HEADER
from newsletter.mautic.exceptions import MauticBridgeRejectedError
from newsletter.mautic.operations import ASSERTABLE_OPERATIONS, CONTACT_DELETE
from newsletter.models import MauticContactMapping, MauticIdentityAuditLog, MauticUserConnection
from newsletter.tests.test_mautic_per_user_execution import PER_USER_OFF, PER_USER_ON
from newsletter.tests.test_mautic_user_identity import PUBLIC_KEY

User = get_user_model()
BASE = "https://mautic.example.test/api/"
MAUTIC_USER_ID = 41
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "contact-delete-tests"}}
SETTINGS = {"CACHES": LOCMEM, "MARKETING_RESPONSE_CACHE_ENABLED": False}


def _response(status_code=200, payload=None):
    response = Mock(status_code=status_code)
    response.json.return_value = payload if payload is not None else {}
    response.text = json.dumps(payload or {})
    response.headers = {}
    return response


class FakeMautic:
    """In-memory Mautic contacts, DNC and the endpoints bulk delete uses."""

    def __init__(self, count=0):
        self.contacts = {i: {"email": f"del-{i:05d}@example.test", "dnc": [], "campaigns": 0} for i in range(1, count + 1)}
        self.calls = []
        self.refuse = set()  # IDs Mautic will not delete
        self.timeout_after_delete = False

    def add(self, contact_id, email, **extra):
        self.contacts[contact_id] = {"email": email, "dnc": [], "campaigns": 0, **extra}

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        path = url[len(BASE):]
        if method == "POST" and path == "ecp/contacts/id-lookup":
            ids = kwargs["json"]["ids"]
            assert len(ids) <= services.LOOKUP_BATCH_SIZE
            return _response(payload={"contacts": {str(i): self.contacts[i] for i in ids if i in self.contacts}})
        if method == "POST" and path == "ecp/contacts/email-lookup":
            emails = kwargs["json"]["emails"]
            index = {}
            for contact_id, contact in self.contacts.items():
                index.setdefault(contact["email"].lower(), []).append(contact_id)
            matches = {e: {"contact_ids": index[e], "dnc_email": False} for e in emails if e in index}
            return _response(payload={"matches": matches})
        if method == "DELETE" and path in ("ecp/bridge/contacts/batch/delete", "contacts/batch/delete"):
            ids = [int(i) for i in kwargs["params"]["ids"].split(",")]
            assert len(ids) <= services.BATCH_SIZE
            for contact_id in ids:
                if contact_id not in self.refuse:
                    self.contacts.pop(contact_id, None)
            if self.timeout_after_delete:
                self.timeout_after_delete = False
                return _response(503, {"errors": [{"message": "timeout"}]})
            return _response(payload={"contacts": [{"id": i} for i in ids]})
        return _response(500, {"errors": [{"message": f"unexpected {method} {path}"}]})

    def deletes(self):
        return [c for c in self.calls if c["method"] == "DELETE"]


class _Fixtures:
    def setUp(self):
        cache.clear()
        self.actor = User.objects.create_user(username="delete-admin", email="delete-admin@example.test", password="x", is_superuser=True, is_staff=True)
        MauticUserConnection.objects.create(user=self.actor, mautic_user_id=MAUTIC_USER_ID, status=MauticUserConnection.Status.ACTIVE, is_active=True)
        self.api = APIClient()
        self.api.force_authenticate(user=self.actor)
        self.mautic = FakeMautic(10)
        factory = patch("newsletter.contact_delete_services.MauticClient", side_effect=self._factory)
        factory.start()
        self.addCleanup(factory.stop)

    def _factory(self, *args, **kwargs):
        kwargs["session"] = self.mautic
        return MauticClient(*args, **kwargs)

    def prepare(self, ids):
        return self.api.post(reverse("newsletter-admin-contact-delete-prepare"), {"mode": "selected", "contact_ids": ids}, format="json")

    def prepare_csv(self, text, name="delete.csv", **extra):
        data = {"mode": "csv", "file": SimpleUploadedFile(name, text.encode(), content_type="text/csv"), **extra}
        return self.api.post(reverse("newsletter-admin-contact-delete-prepare"), data, format="multipart")

    def execute(self, plan_id, count):
        return self.api.post(reverse("newsletter-admin-contact-delete-execute", args=[plan_id]), {"confirm_count": count}, format="json")

    def run_all(self, plan_id, count, limit=1000):
        response = None
        for _ in range(limit):
            response = self.execute(plan_id, count)
            if response.status_code != 200 or response.data["state"] not in ("ready", "running"):
                return response
        return response


@override_settings(**PER_USER_ON, **SETTINGS)
class SelectedDeleteTests(_Fixtures, TestCase):
    def test_operation_is_assertable(self):
        self.assertIn(CONTACT_DELETE, ASSERTABLE_OPERATIONS)

    def test_prepare_classifies_and_never_deletes(self):
        ecp_user = User.objects.create_user(username="member", email="Del-00003@Example.test", password="x")
        MauticContactMapping.objects.create(user=self.actor, mautic_contact_id="2")
        self.mautic.contacts[4]["dnc"] = [{"channel": "email", "reason": "unsubscribed"}]
        response = self.prepare([1, 2, 3, 4, 5, 999, "1"])
        self.assertEqual(response.status_code, 201, response.data)
        summary = response.data["summary"]
        self.assertEqual(summary["requested"], 6)
        self.assertEqual(summary["deletable"], 2)
        self.assertEqual(summary["protected"], {"linked_ecp_account": 1, "ecp_account_email": 1, "do_not_contact": 1})
        self.assertEqual(summary["not_found"], 1)
        self.assertEqual({s["id"] for s in response.data["samples"]["deletable"]}, {1, 5})
        self.assertEqual(self.mautic.deletes(), [])
        self.assertNotIn("targets", response.data)
        self.assertTrue(User.objects.filter(pk=ecp_user.pk).exists())

    def test_input_is_validated(self):
        for ids, code in (([], "no_contacts"), (["x"], "invalid_ids"), ([0], "invalid_ids"), (list(range(1, services.MAX_SELECTED + 2)), "too_many_contacts")):
            response = self.prepare(ids)
            self.assertEqual((response.status_code, response.data["code"]), (400, code))
        response = self.api.post(reverse("newsletter-admin-contact-delete-prepare"), {"mode": "all"}, format="json")
        self.assertEqual(response.data["code"], "invalid_mode")

    def test_exact_count_confirmation_is_required(self):
        plan = self.prepare([1, 2, 3]).data
        for wrong in ("", "2", "4", "three"):
            response = self.execute(plan["plan_id"], wrong)
            self.assertEqual((response.status_code, response.data["code"]), (400, "confirmation_required"))
        self.assertEqual(self.mautic.deletes(), [])

    def test_delete_one_and_five_as_the_mapped_user(self):
        users_before = User.objects.count()
        for ids in ([1], [2, 3, 4, 5, 6]):
            plan = self.prepare(ids).data
            response = self.execute(plan["plan_id"], len(ids))
            self.assertEqual(response.status_code, 200, response.data)
            self.assertEqual((response.data["state"], response.data["results"]["deleted"]), ("completed", len(ids)))
        self.assertEqual(sorted(self.mautic.contacts), [7, 8, 9, 10])
        call = self.mautic.deletes()[-1]
        self.assertEqual((call["url"], call["params"]["ids"]), (f"{BASE}ecp/bridge/contacts/batch/delete", "2,3,4,5,6"))
        claims = jwt.decode(call["headers"][ECP_IDENTITY_ASSERTION_HEADER], PUBLIC_KEY, algorithms=["RS256"], audience="ecp-mautic")
        self.assertEqual((claims["operation"], claims["mautic_user_id"]), (CONTACT_DELETE, MAUTIC_USER_ID))
        entry = MauticIdentityAuditLog.objects.latest("id")
        self.assertEqual((entry.action, entry.status, entry.resource, entry.ecp_user), (CONTACT_DELETE, "succeeded", "contact_bulk_delete", self.actor))
        self.assertEqual(User.objects.count(), users_before)

    def test_large_plans_run_in_bounded_batches_and_repeat_calls_are_harmless(self):
        self.mautic = FakeMautic(250)
        plan = self.prepare(list(range(1, 251))).data
        progress = []
        for _ in range(3):
            response = self.execute(plan["plan_id"], 250)
            progress.append(response.data["progress"]["processed"])
        self.assertEqual(progress, [100, 200, 250])
        self.assertEqual([len(c["params"]["ids"].split(",")) for c in self.mautic.deletes()], [100, 100, 50])
        self.assertEqual(response.data["state"], "completed")
        self.mautic.add(9999, "new@example.test")
        again = self.execute(plan["plan_id"], 250)
        self.assertEqual((again.status_code, again.data["state"]), (200, "completed"))
        self.assertEqual(len(self.mautic.deletes()), 3)
        self.assertIn(9999, self.mautic.contacts)

    def test_targets_are_rechecked_before_each_batch(self):
        plan = self.prepare([1, 2, 3, 4]).data
        self.mautic.contacts[1]["dnc"] = [{"channel": "email", "reason": "manual"}]
        self.mautic.contacts[2]["email"] = "changed@example.test"
        MauticContactMapping.objects.create(user=self.actor, mautic_contact_id="3")
        del self.mautic.contacts[4]
        response = self.execute(plan["plan_id"], 4)
        results = response.data["results"]
        self.assertEqual(results["skipped"], {"do_not_contact": 1, "email_changed": 1, "linked_ecp_account": 1})
        self.assertEqual((results["already_gone"], results["deleted"]), (1, 0))
        self.assertEqual(self.mautic.deletes(), [])
        self.assertTrue({1, 2, 3} <= set(self.mautic.contacts))

    def test_partial_failure_is_reported(self):
        self.mautic.refuse = {3}
        plan = self.prepare([1, 2, 3]).data
        response = self.execute(plan["plan_id"], 3)
        self.assertEqual(response.data["state"], "completed_with_errors")
        self.assertEqual((response.data["results"]["deleted"], response.data["results"]["failed"]), (2, 1))
        self.assertEqual(response.data["failures"], [{"id": 3, "reason": "not_deleted", "label": "Mautic did not delete this contact"}])

    def test_unknown_outcome_is_retried_without_double_counting(self):
        plan = self.prepare([1, 2]).data
        self.mautic.timeout_after_delete = True
        first = self.execute(plan["plan_id"], 2)
        self.assertEqual((first.status_code, first.data["code"]), (502, "retry"))
        second = self.execute(plan["plan_id"], 2)
        self.assertEqual(second.data["state"], "completed")
        self.assertEqual((second.data["results"]["deleted"], second.data["results"]["already_gone"]), (0, 2))

    def test_concurrent_batches_are_refused(self):
        plan = self.prepare([1]).data
        cache.add(f"{services.CACHE_PREFIX}:lock:{plan['plan_id']}", 1, 60)
        response = self.execute(plan["plan_id"], 1)
        self.assertEqual((response.status_code, response.data["code"]), (409, "busy"))
        self.assertEqual(self.mautic.deletes(), [])

    def test_cancel_stops_before_the_next_batch(self):
        self.mautic = FakeMautic(150)
        plan = self.prepare(list(range(1, 151))).data
        self.execute(plan["plan_id"], 150)
        cancelled = self.api.post(reverse("newsletter-admin-contact-delete-cancel", args=[plan["plan_id"]]))
        self.assertEqual(cancelled.data["state"], "cancelled")
        after = self.execute(plan["plan_id"], 150)
        self.assertEqual((after.data["state"], after.data["results"]["deleted"]), ("cancelled", 100))
        self.assertEqual(len(self.mautic.contacts), 50)

    def test_plans_belong_to_their_admin(self):
        plan = self.prepare([1]).data
        other = User.objects.create_user(username="other-admin", password="x", is_superuser=True)
        MauticUserConnection.objects.create(user=other, mautic_user_id=MAUTIC_USER_ID + 1, status=MauticUserConnection.Status.ACTIVE, is_active=True)
        api = APIClient()
        api.force_authenticate(user=other)
        for response in (
            api.get(reverse("newsletter-admin-contact-delete-detail", args=[plan["plan_id"]])),
            api.post(reverse("newsletter-admin-contact-delete-execute", args=[plan["plan_id"]]), {"confirm_count": 1}, format="json"),
        ):
            self.assertEqual(response.status_code, 404)
        self.assertEqual(self.mautic.deletes(), [])

    def test_expired_plan_cannot_run(self):
        plan = self.prepare([1]).data
        cache.delete(services._plan_key(plan["plan_id"]))
        self.assertEqual(self.execute(plan["plan_id"], 1).status_code, 404)

    def test_bridge_refusal_stops_the_batch(self):
        plan = self.prepare([1]).data
        with patch.object(MauticClient, "delete_contacts_batch", side_effect=MauticBridgeRejectedError("HTTP 403")):
            response = self.execute(plan["plan_id"], 1)
        self.assertEqual(response.status_code, 403)
        self.assertIn(1, self.mautic.contacts)


@override_settings(**PER_USER_ON, **SETTINGS)
class CsvDeleteTests(_Fixtures, TestCase):
    def test_csv_matching_reports_every_category(self):
        self.mautic.add(50, "twin@example.test")
        self.mautic.add(51, "TWIN@example.test")
        self.mautic.contacts[5]["dnc"] = [{"channel": "email", "reason": "bounced"}]
        rows = ["Email,First Name"] + [f"del-{i:05d}@example.test,X" for i in range(1, 11)] + [
            "DEL-00001@EXAMPLE.TEST,dup",
            "unknown@example.test,X",
            "not-an-email,X",
            ",X",
            "twin@example.test,X",
        ]
        response = self.prepare_csv("\n".join(rows) + "\n")
        self.assertEqual(response.status_code, 201, response.data)
        summary = response.data["summary"]
        self.assertEqual(
            (summary["requested"], summary["deletable"], summary["duplicate"], summary["invalid"], summary["not_found"]),
            (15, 9, 1, 2, 1),
        )
        self.assertEqual(summary["protected"], {"do_not_contact": 1, "ambiguous_email": 1})
        self.assertEqual(summary["email_column"], "Email")
        self.assertEqual(self.mautic.deletes(), [])
        done = self.run_all(response.data["plan_id"], 9)
        self.assertEqual((done.data["state"], done.data["results"]["deleted"]), ("completed", 9))
        self.assertEqual(sorted(self.mautic.contacts), [5, 50, 51])

    def test_ten_contacts_by_csv(self):
        text = "Email\n" + "\n".join(f"del-{i:05d}@example.test" for i in range(1, 11)) + "\n"
        plan = self.prepare_csv(text).data
        self.assertEqual(plan["summary"]["deletable"], 10)
        done = self.run_all(plan["plan_id"], 10)
        self.assertEqual(done.data["results"]["deleted"], 10)
        self.assertEqual(self.mautic.contacts, {})

    def test_csv_needs_an_email_column_and_never_matches_other_fields(self):
        response = self.prepare_csv("First Name,Company\nTest,Example\n")
        self.assertEqual((response.status_code, response.data["code"]), (400, "email_column_required"))
        explicit = self.prepare_csv("Contact,Name\ndel-00001@example.test,Test\n", email_column="Contact")
        self.assertEqual(explicit.data["summary"]["deletable"], 1)
        bad = self.prepare_csv("Email\nx@example.test\n", email_column="Nope")
        self.assertEqual(bad.data["code"], "unknown_column")

    def test_csv_file_errors(self):
        self.assertEqual(self.prepare_csv("").data["code"], "empty_file")
        self.assertEqual(self.prepare_csv("Email,Email\na,b\n").data["code"], "duplicate_headers")

    def test_50000_row_dry_run_prepares_without_deleting(self):
        self.mautic = FakeMautic(50000)
        text = "Email\n" + "\n".join(f"del-{i:05d}@example.test" for i in range(1, 50001)) + "\n"
        started = time.monotonic()
        response = self.prepare_csv(text)
        elapsed = time.monotonic() - started
        self.assertEqual(response.status_code, 201)
        self.assertEqual((response.data["summary"]["requested"], response.data["summary"]["deletable"]), (50000, 50000))
        self.assertEqual(response.data["progress"]["total"], 50000)
        self.assertLessEqual(len(response.data["samples"]["deletable"]), services.SAMPLE_SIZE)
        self.assertEqual(self.mautic.deletes(), [])
        self.assertEqual(len(self.mautic.contacts), 50000)
        self.assertLess(elapsed, 60)


@override_settings(**PER_USER_OFF, **SETTINGS)
class ServiceAccountModeTests(_Fixtures, TestCase):
    def test_native_batch_delete_without_per_user_execution(self):
        plan = self.prepare([1]).data
        self.execute(plan["plan_id"], 1)
        self.assertEqual(self.mautic.deletes()[0]["url"], f"{BASE}contacts/batch/delete")
        self.assertNotIn(1, self.mautic.contacts)


@override_settings(**PER_USER_ON, **SETTINGS)
class PermissionTests(TestCase):
    def test_non_marketing_users_are_refused(self):
        with patch("newsletter.contact_delete_services.MauticClient") as client:
            for user in (None, User.objects.create_user(username="staff", password="x", is_staff=True), User.objects.create_user(username="super", password="x", is_superuser=True)):
                api = APIClient()
                if user:
                    api.force_authenticate(user=user)
                responses = [
                    api.post(reverse("newsletter-admin-contact-delete-prepare"), {"mode": "selected", "contact_ids": [1]}, format="json"),
                    api.post(reverse("newsletter-admin-contact-delete-execute", args=["a" * 24]), {"confirm_count": 1}, format="json"),
                    api.post(reverse("newsletter-admin-contact-delete-cancel", args=["a" * 24])),
                ]
                self.assertTrue(all(r.status_code in (401, 403) for r in responses), [r.status_code for r in responses])
        client.assert_not_called()
