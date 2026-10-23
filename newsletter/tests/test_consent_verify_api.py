"""Mautic -> ECP consent verification: service authentication (real Ed25519,
no mocked cryptography) and authoritative decisions."""

import base64
import json
import time
import uuid
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

from newsletter.consent_service_auth import AUDIENCE, HEADER, ISSUER, PURPOSE, REPLAY_EPOCH_KEY, body_digest
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.models import (
    MauticContactMapping,
    MauticEmailSuppression,
    MauticIdentityAuditLog,
    NewsletterCategory,
    NewsletterSubscription,
)

User = get_user_model()
PATH = "/api/marketing/internal/consent/verify/"
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "consent-tests"}}


def new_key():
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, base64.b64encode(raw).decode()


KEY_A, PUB_A = new_key()
KEY_B, PUB_B = new_key()
KEYS = json.dumps({"mautic-2026-10": PUB_A, "mautic-2026-04": PUB_B})


def sign(body: bytes, *, key=KEY_A, kid="mautic-2026-10", method="POST", path=PATH, **overrides):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 60, "jti": uuid.uuid4().hex, "purpose": PURPOSE,
              "htm": method, "htu": path, "bdh": body_digest(body)}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": kid})


@override_settings(ECP_CONSENT_VERIFY_KEYS=KEYS, ECP_CONSENT_REVOKED_KEY_IDS="", CACHES=LOCMEM,
                   ECP_CONSENT_ALLOW_PROCESS_LOCAL_REPLAY_STORE=True)
class ConsentApiBase(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        cache.set(REPLAY_EPOCH_KEY, 0, None)  # a replay store that has been running for a long time
        self.http = Client(HTTP_HOST="localhost")
        self.list = NewsletterCategory.objects.create(name="Updates", slug="updates", mautic_segment_id="61", is_active=True)
        self.other = NewsletterCategory.objects.create(name="Events", slug="events", mautic_segment_id="62", is_active=True)
        self.user = User.objects.create_user(username="consent-member", email="consent-member@example.test", password="x")
        MauticContactMapping.objects.create(user=self.user, mautic_contact_id="501")
        self.subscription = NewsletterSubscription.objects.create(user=self.user, category=self.list, is_subscribed=True)
        patcher = patch("newsletter.authoritative_consent.MauticClient")
        self.mautic = patcher.start().return_value
        self.addCleanup(patcher.stop)
        self.mautic.get_consent_step.side_effect = self.consent_step
        self.campaign(email_category=f"ecp-list-{self.list.pk}")

    #: True: the bridge plugin predates the consent-step endpoint (Mautic 404s the route).
    legacy = False

    def consent_step(self, campaign_id, event_id, merged_ids):
        """The bridge plugin's consent-step endpoint, answered from the same facts
        the individual Mautic API mocks hold (see ConsentStepApiController)."""
        if self.legacy:
            return None
        try:
            campaign = self.mautic.get_campaign(campaign_id)
            states = self.mautic.get_campaign_event_states(campaign_id)
        except PermanentMauticError as exc:
            if "HTTP 404" not in str(exc):
                raise
            campaign, states = None, {"activeEventIds": []}
        active = {str(i) for i in states["activeEventIds"]}
        events = [e for e in (campaign or {}).get("events", []) if str(e["id"]) in active]
        step = next((e for e in events if str(e["id"]) == str(event_id)), None)
        email = None
        if step is not None:
            try:
                email = self.mautic.get_email(step["properties"]["email"])
            except PermanentMauticError:
                email = None
        merged = {}
        for merged_id in merged_ids:
            try:
                merged[str(merged_id)] = int(self.mautic.get_contact(str(merged_id))["id"])
            except PermanentMauticError:
                merged[str(merged_id)] = None
        return {"campaign": campaign and {"id": campaign["id"], "forms": campaign["forms"]}, "events": events,
                "email": email, "merged": merged}

    def campaign(self, *, email_category=None, gate_segments=(61,), forms=(31,), email_type="marketing", path="yes"):
        self.mautic.get_campaign.return_value = {
            "id": 7, "forms": [{"id": f} for f in forms],
            "events": [
                {"id": 11, "type": "lead.segments", "eventType": "condition", "properties": {"segments": list(gate_segments)}, "parent": None},
                {"id": 12, "type": "email.send", "eventType": "action", "parent": {"id": 11}, "decisionPath": path,
                 "properties": {"email": 5, "email_type": email_type}, "triggerMode": "interval"},
            ],
        }
        self.mautic.get_campaign_event_states.return_value = {"activeEventIds": [11, 12]}
        self.mautic.get_email.return_value = {"id": 5, "category": {"alias": email_category} if email_category else None}

    def post(self, payload=None, *, token=None, raw=None, **sign_kwargs):
        body = raw if raw is not None else json.dumps(payload or {"campaign_id": 7, "event_id": 12, "contacts": [{"id": 501}]}).encode()
        headers = {} if token is False else {f"HTTP_{HEADER.upper().replace('-', '_')}": token or sign(body, **sign_kwargs)}
        return self.http.post(PATH, data=body, content_type="application/json", **headers)

    def decisions(self, response):
        self.assertEqual(response.status_code, 200, response.content)
        return [(d["id"], d["decision"], d["reason"]) for d in response.json()["decisions"]]


class ServiceAuthenticationTests(ConsentApiBase):
    def assert_refused(self, response, status, code):
        self.assertEqual((response.status_code, response.json()["error"]), (status, code))

    def test_valid_signed_request_is_answered(self):
        self.assertEqual(self.decisions(self.post()), [(501, "ALLOW", "current_consent")])

    def test_missing_and_invalid_signatures(self):
        self.assert_refused(self.post(token=False), 401, "missing_signature")
        other, _ = new_key()
        self.assert_refused(self.post(key=other), 401, "invalid_signature")
        self.assert_refused(self.post(token="not.a.jws"), 401, "malformed_signature")

    def test_key_ids_come_only_from_configuration(self):
        self.assert_refused(self.post(kid="../../etc/passwd"), 401, "unknown_key")
        self.assert_refused(self.post(kid="unknown"), 401, "unknown_key")
        with override_settings(ECP_CONSENT_REVOKED_KEY_IDS="mautic-2026-04"):
            self.assert_refused(self.post(key=KEY_B, kid="mautic-2026-04"), 401, "unknown_key")

    def test_rotation_overlap_accepts_both_configured_keys(self):
        self.assertEqual(self.decisions(self.post(key=KEY_B, kid="mautic-2026-04"))[0][1], "ALLOW")
        self.assertEqual(self.decisions(self.post())[0][1], "ALLOW")

    def test_time_bounds(self):
        now = int(time.time())
        self.assert_refused(self.post(iat=now - 200, exp=now - 100), 401, "expired")
        self.assert_refused(self.post(iat=now + 300, exp=now + 330), 401, "not_yet_valid")
        self.assert_refused(self.post(iat=now, exp=now + 600), 401, "invalid_validity")

    def test_issuer_audience_purpose_method_path_and_body_are_bound(self):
        self.assert_refused(self.post(iss="ecp"), 401, "wrong_issuer")
        self.assert_refused(self.post(aud="ecp-mautic"), 401, "wrong_audience")
        self.assert_refused(self.post(purpose="anything"), 401, "wrong_purpose")
        self.assert_refused(self.post(method="GET"), 401, "wrong_method")
        self.assert_refused(self.post(path="/api/other/"), 401, "wrong_path")
        body = json.dumps({"campaign_id": 7, "event_id": 12, "contacts": [{"id": 501}]}).encode()
        token = sign(body)
        tampered = json.dumps({"campaign_id": 7, "event_id": 12, "contacts": [{"id": 999}]}).encode()
        self.assert_refused(self.post(raw=tampered, token=token), 401, "body_mismatch")
        self.assert_refused(self.post(jti=None), 401, "invalid_claims")

    def test_algorithm_confusion_and_none_are_refused(self):
        body = json.dumps({"campaign_id": 7, "event_id": 12, "contacts": [{"id": 501}]}).encode()
        claims = jwt.decode(sign(body), options={"verify_signature": False})
        hs = jwt.encode(claims, base64.b64decode(PUB_A), algorithm="HS256", headers={"kid": "mautic-2026-10"})
        self.assert_refused(self.post(raw=body, token=hs), 401, "unsupported_algorithm")
        none = jwt.encode(claims, None, algorithm="none", headers={"kid": "mautic-2026-10"})
        self.assert_refused(self.post(raw=body, token=none), 401, "unsupported_algorithm")

    def test_replayed_request_id_is_refused(self):
        body = json.dumps({"campaign_id": 7, "event_id": 12, "contacts": [{"id": 501}]}).encode()
        token = sign(body)
        self.assertEqual(self.post(raw=body, token=token).status_code, 200)
        self.assert_refused(self.post(raw=body, token=token), 401, "replayed")

    def test_unavailable_configuration_or_replay_store_fails_closed(self):
        with override_settings(ECP_CONSENT_VERIFY_KEYS=""):
            self.assert_refused(self.post(), 503, "not_configured")
        with override_settings(ECP_CONSENT_VERIFY_KEYS="{not json"):
            self.assert_refused(self.post(), 503, "verification_keys_invalid")
        with override_settings(ECP_CONSENT_ALLOW_PROCESS_LOCAL_REPLAY_STORE=False):
            self.assert_refused(self.post(), 503, "replay_store_not_shared")
        with patch("newsletter.consent_service_auth.cache.add", side_effect=ConnectionError("redis down")):
            self.assert_refused(self.post(), 503, "replay_store_unavailable")

    def test_tokens_issued_before_the_replay_store_restarted_are_refused(self):
        from django.core.cache import cache
        now = int(time.time())
        body = json.dumps({"campaign_id": 7, "event_id": 12, "contacts": [{"id": 501}]}).encode()
        token = sign(body, iat=now - 20, exp=now + 30)
        self.assertEqual(self.post(raw=body, token=token).status_code, 200)
        cache.clear()  # Redis restarted without persistence: every replay key is gone
        self.assert_refused(self.post(raw=body, token=token), 401, "issued_before_replay_store")
        self.assertEqual(self.post(iat=now + 1, exp=now + 31).status_code, 200)  # a fresh token works

    def test_only_shared_atomic_caches_are_replay_stores(self):
        from newsletter.consent_service_auth import ConsentAuthUnavailable, _require_shared_replay_store
        for backend in ("django.core.cache.backends.filebased.FileBasedCache", "django.core.cache.backends.db.DatabaseCache",
                        "django.core.cache.backends.dummy.DummyCache", "myproject.cache.RedisCacheLookalike"):
            with self.subTest(backend=backend), override_settings(CACHES={"default": {"BACKEND": backend}},
                                                                   ECP_CONSENT_ALLOW_PROCESS_LOCAL_REPLAY_STORE=False):
                with self.assertRaisesMessage(ConsentAuthUnavailable, "replay_store_not_shared"):
                    _require_shared_replay_store()
        with override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.redis.RedisCache"}},
                               ECP_CONSENT_ALLOW_PROCESS_LOCAL_REPLAY_STORE=False):
            _require_shared_replay_store()

    def test_process_local_override_is_ignored_outside_the_test_environment(self):
        with patch("newsletter.consent_service_auth._in_django_test_environment", return_value=False):
            self.assert_refused(self.post(), 503, "replay_store_not_shared")

    def test_only_post_and_no_browser_session(self):
        self.assertEqual(self.http.get(PATH).status_code, 405)
        self.http.force_login(User.objects.create_superuser(username="admin-x", email="ax@example.test", password="x"))
        self.assert_refused(self.post(token=False), 401, "missing_signature")  # a session is not authentication here

    def test_request_shape_and_size_bounds(self):
        self.assertEqual(self.post(raw=b"x" * (33 * 1024)).status_code, 413)
        self.assertEqual(self.post(raw=b"{not json").status_code, 400)
        too_many = {"campaign_id": 7, "event_id": 12, "contacts": [{"id": i} for i in range(1, 102)]}
        self.assertEqual(self.post(too_many).status_code, 400)
        for payload in ({"campaign_id": 7, "event_id": 12, "contacts": [{"id": 501}, {"id": 501}]},
                        {"campaign_id": 7, "event_id": 12, "contacts": [{"id": 501, "email": "a@example.test"}]},
                        {"campaign_id": 7, "event_id": 12, "contacts": [{"id": 501}], "allow": True},
                        {"campaign_id": 7, "event_id": 12, "contacts": [{"id": 501, "merged_ids": [501]}]},
                        {"campaign_id": "7", "event_id": 12, "contacts": [{"id": 501}]},
                        {"campaign_id": 7, "event_id": 12, "contacts": [{"id": True}]}):
            with self.subTest(payload=payload):
                self.assertEqual(self.post(payload).status_code, 400)

    @override_settings(ECP_CONSENT_AUTH_FAILURE_AUDIT_PER_MINUTE=5)
    def test_unauthenticated_floods_write_a_bounded_number_of_audit_rows(self):
        audited = lambda code: MauticIdentityAuditLog.objects.filter(action="consent.verify", error_code=f"auth:{code}").count()
        with self.assertLogs("newsletter.consent_verify_views", level="WARNING") as logs:
            for _ in range(40):
                self.assert_refused(self.post(token=False), 401, "missing_signature")
            for _ in range(8):
                self.assert_refused(self.post(token="not.a.jws"), 401, "malformed_signature")
            now = int(time.time())
            self.assert_refused(self.post(iat=now - 200, exp=now - 150), 401, "expired")
            self.assert_refused(self.post(kid="unknown"), 401, "unknown_key")
            body = json.dumps({"campaign_id": 7, "event_id": 12, "contacts": [{"id": 501}]}).encode()
            token = sign(body)
            self.post(raw=body, token=token)
            self.assert_refused(self.post(raw=body, token=token), 401, "replayed")
        self.assertEqual((audited("missing_signature"), audited("malformed_signature"), audited("expired"), audited("unknown_key"),
                          audited("replayed")), (5, 5, 1, 1, 1))
        self.assertEqual(sum("unauthenticated (missing_signature)" in line for line in logs.output), 40, "every refusal is still logged")
        self.assertFalse(any(token in line or "@" in line for line in logs.output), "no token or personal data in the log")

        # Authenticated refusals remain fully audited, whatever the unauthenticated noise.
        self.subscription.is_subscribed = False
        self.subscription.save()
        for _ in range(7):
            self.post()
        self.assertEqual(MauticIdentityAuditLog.objects.filter(action="consent.verify", status="succeeded").count(), 7)

    def test_no_audit_row_without_the_shared_counter(self):
        with patch("newsletter.consent_verify_views.cache.incr", side_effect=ConnectionError("redis down")):
            self.assert_refused(self.post(token=False), 401, "missing_signature")
        self.assertFalse(MauticIdentityAuditLog.objects.filter(action="consent.verify", error_code="auth:missing_signature").exists())

    def test_rate_limited_callers_are_unavailable_not_authorised(self):
        with override_settings(ECP_CONSENT_MAX_REQUESTS_PER_MINUTE=2):
            self.assertEqual(self.post().status_code, 200)
            self.assertEqual(self.post().status_code, 200)
            self.assert_refused(self.post(), 503, "rate_limited")

    def test_refusals_are_audited_without_personal_data(self):
        self.post(kid="unknown")
        self.subscription.is_subscribed = False
        self.subscription.save()
        self.post()
        rows = list(MauticIdentityAuditLog.objects.filter(action="consent.verify").values_list("status", "error_code", "detail"))
        self.assertIn(("denied", "auth:unknown_key", ""), rows)
        self.assertIn(("succeeded", "", "DENY:consent_withdrawn=1"), rows)
        self.assertFalse(any("@" in (code + detail) for _, code, detail in rows))


class AuthoritativeDecisionTests(ConsentApiBase):
    def one(self, **contact):
        return self.decisions(self.post({"campaign_id": 7, "event_id": 12, "contacts": [{"id": 501, **contact}]}))[0][1:]

    def test_current_consent_is_the_only_allow(self):
        self.assertEqual(self.one(), ("ALLOW", "current_consent"))
        self.subscription.is_subscribed = False
        self.subscription.save()
        self.assertEqual(self.one(), ("DENY", "consent_withdrawn"))  # Mautic's segment is irrelevant
        self.subscription.delete()
        self.assertEqual(self.one(), ("DENY", "no_consent"))

    def test_consent_to_another_list_never_authorises(self):
        self.subscription.delete()
        NewsletterSubscription.objects.create(user=self.user, category=self.other, is_subscribed=True)
        self.assertEqual(self.one(), ("DENY", "no_consent"))

    def test_email_scope_must_name_a_gate_list(self):
        self.campaign(email_category=None)
        self.assertEqual(self.one(), ("DENY", "email_scope_missing"))
        self.campaign(email_category="newsletters")
        self.assertEqual(self.one(), ("DENY", "email_scope_missing"))
        self.campaign(email_category=f"ecp-list-{self.other.pk}")  # a real list, but not the one the gate checks
        self.assertEqual(self.one(), ("DENY", "email_scope_mismatch"))

    def test_archived_or_deleted_list_never_authorises(self):
        NewsletterCategory.objects.filter(pk=self.list.pk).update(is_active=False)
        self.assertEqual(self.one(), ("DENY", "not_subscription_list"))

    def test_step_is_read_from_mautic_not_trusted_from_the_caller(self):
        self.campaign(email_category=f"ecp-list-{self.list.pk}", path="no")
        self.assertEqual(self.one(), ("DENY", "no_path"))
        self.campaign(email_category=f"ecp-list-{self.list.pk}", email_type="transactional")
        self.assertEqual(self.one(), ("DENY", "not_marketing"))
        self.campaign(email_category=f"ecp-list-{self.list.pk}", forms=())
        self.assertEqual(self.one(), ("DENY", "not_form_sourced"))
        self.campaign(email_category=f"ecp-list-{self.list.pk}", gate_segments=(7,))
        self.assertEqual(self.one(), ("DENY", "not_subscription_list"))
        self.campaign(email_category=f"ecp-list-{self.list.pk}")
        self.mautic.get_campaign_event_states.return_value = {"activeEventIds": [11]}  # step deleted
        self.assertEqual(self.one(), ("DENY", "step_not_found"))
        self.mautic.get_campaign.side_effect = PermanentMauticError("Mautic API request failed (HTTP 404)")
        self.assertEqual(self.one(), ("DENY", "step_not_found"))

    def test_mautic_read_failures_are_unavailable_not_decisions(self):
        self.mautic.get_campaign.side_effect = TemporaryMauticError("down")
        response = self.post()
        self.assertEqual((response.status_code, response.json()["error"]), (503, "upstream_unavailable"))
        self.mautic.get_campaign.side_effect = None
        self.mautic.get_email.side_effect = TemporaryMauticError("down")
        self.assertEqual(self.post().status_code, 503)

    def test_identity_comes_from_the_mapping_never_from_email(self):
        MauticContactMapping.objects.filter(user=self.user).update(mautic_contact_id="700")
        self.assertEqual(self.one(), ("UNKNOWN", "identity_unknown"))

    def test_merged_contact_is_accepted_only_when_mautic_resolves_the_old_id(self):
        MauticContactMapping.objects.filter(user=self.user).update(mautic_contact_id="400")
        self.mautic.get_contact.return_value = {"id": 501}
        self.assertEqual(self.one(merged_ids=[400]), ("ALLOW", "current_consent"))
        self.mautic.get_contact.assert_called_with("400")
        self.mautic.get_contact.return_value = {"id": 999}  # old id now belongs to someone else
        self.assertEqual(self.one(merged_ids=[400]), ("UNKNOWN", "merge_unverified"))
        self.mautic.get_contact.side_effect = PermanentMauticError("Mautic API request failed (HTTP 404)")
        self.assertEqual(self.one(merged_ids=[400]), ("UNKNOWN", "merge_unverified"))
        self.assertEqual(MauticContactMapping.objects.get(user=self.user).mautic_contact_id, "400")  # never re-linked

    def test_two_members_behind_one_contact_is_a_conflict(self):
        twin = User.objects.create_user(username="consent-twin", email="consent-twin@example.test", password="x")
        MauticContactMapping.objects.create(user=twin, mautic_contact_id="400")
        self.mautic.get_contact.return_value = {"id": 501}
        self.assertEqual(self.one(merged_ids=[400]), ("UNKNOWN", "identity_conflict"))

    def test_suppressed_or_inactive_member_is_denied(self):
        from django.utils import timezone
        MauticEmailSuppression.objects.create(user=self.user, reason=MauticEmailSuppression.Reason.MANUAL, suppressed_at=timezone.now())
        self.assertEqual(self.one(), ("DENY", "suppressed"))
        MauticEmailSuppression.objects.all().delete()
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertEqual(self.one(), ("DENY", "member_inactive"))

    def test_one_decision_per_contact_in_request_order(self):
        stranger = 900
        result = self.decisions(self.post({"campaign_id": 7, "event_id": 12, "contacts": [{"id": stranger}, {"id": 501}]}))
        self.assertEqual(result, [(900, "UNKNOWN", "identity_unknown"), (501, "ALLOW", "current_consent")])


class LegacyPluginDecisionTests(AuthoritativeDecisionTests):
    """The same decisions when the bridge plugin has no consent-step endpoint yet."""

    legacy = True


class ConsentLookupCostTests(ConsentApiBase):
    """One Mautic request and a fixed number of queries per decision, whatever
    the batch size or merge claims; and still nothing reused between requests."""

    def members(self, count, start=0):
        contacts = []
        for index in range(start, start + count):
            user = User.objects.create_user(username=f"cost-{index}", email=f"cost-{index}@example.test", password="x")
            MauticContactMapping.objects.create(user=user, mautic_contact_id=str(2000 + index))
            NewsletterSubscription.objects.create(user=user, category=self.list, is_subscribed=True)
            contacts.append({"id": 2000 + index})
        return contacts

    def fixed_step(self, merged=None):
        events = self.mautic.get_campaign.return_value["events"]
        self.mautic.get_consent_step.side_effect = None
        self.mautic.get_consent_step.return_value = {
            "campaign": {"id": 7, "forms": [{"id": 31}]}, "events": events,
            "email": {"id": 5, "category": {"alias": f"ecp-list-{self.list.pk}"}}, "merged": merged or {}}

    def test_one_mautic_request_per_batch(self):
        self.fixed_step()
        contacts = self.members(25)
        result = self.decisions(self.post({"campaign_id": 7, "event_id": 12, "contacts": contacts}))
        self.assertEqual({d for _, d, _ in result}, {"ALLOW"})
        self.assertEqual(self.mautic.get_consent_step.call_count, 1)
        for legacy_read in ("get_campaign", "get_campaign_event_states", "get_email", "get_contact"):
            self.assertEqual(getattr(self.mautic, legacy_read).call_count, 0, legacy_read)

    def test_database_queries_do_not_grow_with_the_batch(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        from newsletter.authoritative_consent import decide
        self.fixed_step()
        small, large = self.members(1), self.members(60, start=100)
        with CaptureQueriesContext(connection) as one:
            decide(7, 12, small, client=self.mautic)
        with CaptureQueriesContext(connection) as many:
            self.assertEqual({d["decision"] for d in decide(7, 12, large, client=self.mautic)}, {"ALLOW"})
        self.assertEqual(len(one.captured_queries), len(many.captured_queries))

    def test_merge_claims_are_resolved_in_the_same_request(self):
        MauticContactMapping.objects.filter(user=self.user).update(mautic_contact_id="400")
        self.fixed_step(merged={"400": 501})
        self.assertEqual(self.decisions(self.post({"campaign_id": 7, "event_id": 12, "contacts": [{"id": 501, "merged_ids": [400]}]})),
                         [(501, "ALLOW", "current_consent")])
        self.mautic.get_consent_step.assert_called_once_with(7, 12, [400])
        self.fixed_step(merged={"400": 999})  # Mautic now resolves the old id elsewhere
        self.assertEqual(self.decisions(self.post({"campaign_id": 7, "event_id": 12, "contacts": [{"id": 501, "merged_ids": [400]}]})),
                         [(501, "UNKNOWN", "merge_unverified")])

    def test_every_request_reads_mautic_and_consent_afresh(self):
        self.fixed_step()
        self.assertEqual(self.decisions(self.post())[0][1], "ALLOW")
        self.subscription.is_subscribed = False
        self.subscription.save()
        self.assertEqual(self.decisions(self.post())[0][1:], ("DENY", "consent_withdrawn"))
        self.subscription.is_subscribed = True
        self.subscription.save()
        self.mautic.get_consent_step.return_value["email"] = {"id": 5, "category": {"alias": f"ecp-list-{self.other.pk}"}}
        self.assertEqual(self.decisions(self.post())[0][1:], ("DENY", "email_scope_mismatch"))
        self.assertEqual(self.mautic.get_consent_step.call_count, 3)

    def test_endpoint_failures_are_unavailable(self):
        self.mautic.get_consent_step.side_effect = TemporaryMauticError("down")
        self.assertEqual(self.post().status_code, 503)
        self.mautic.get_consent_step.side_effect = PermanentMauticError("Mautic API request failed (HTTP 403)")
        self.assertEqual(self.post().status_code, 503)

    def test_missing_campaign_from_the_endpoint_is_step_not_found(self):
        self.mautic.get_consent_step.side_effect = None
        self.mautic.get_consent_step.return_value = {"campaign": None, "events": [], "email": None, "merged": {}}
        self.assertEqual(self.decisions(self.post())[0][1:], ("DENY", "step_not_found"))
