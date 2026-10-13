"""
Disposable email domain checks for new account signup.

Covers the shared checker, the bundled dataset, the public preflight endpoint
and every guarded account-creation path. Existing users must keep working
whatever their domain. No test reaches AWS, Google or the shared Redis.
"""
import hashlib
import json
import logging
import time
import uuid
from unittest import mock

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase, override_settings
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from users import disposable_email as de
from users.cognito_auth import CognitoJWTAuthentication
from users.models import CognitoIdentity, UserProfile
from users.validators import validate_email_strict

VALIDATE_URL = "/api/auth/validate-signup-email/"
REGISTER_URL = "/api/auth/register/"
GOOGLE_CALLBACK_URL = "/api/auth/google/callback/"

LOCMEM_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "disposable-email-tests"}}
# A small hand-made list keeps the matching tests independent of upstream changes.
TEST_LISTS = de.DomainLists(blocked=frozenset({"mailinator.com", "tempmail.example", "xn--bcher-kva.example"}))


class NormalizationTests(SimpleTestCase):
    def test_domain_is_trimmed_lowercased_and_trailing_dot_removed(self):
        self.assertEqual(de.normalize_domain("  MailInator.COM. "), "mailinator.com")

    def test_internationalized_domain_is_idna_encoded(self):
        self.assertEqual(de.normalize_domain("BÜCHER.example"), "xn--bcher-kva.example")

    def test_malformed_domains_are_rejected(self):
        for value in ("", "com", "a..b", "-bad.com", "bad-.com", "x" * 64 + ".com", "[1.2.3.4]", "a_b.com", None, 42):
            with self.subTest(value=value):
                self.assertEqual(de.normalize_domain(value), "")

    def test_email_domain_extraction(self):
        self.assertEqual(de.extract_email_domain("  JOHN@MAILINATOR.COM "), "mailinator.com")
        for value in ("no-at-sign", "@mailinator.com", "a b@gmail.com", "user@", None, "x@" + "a" * 250 + ".com"):
            with self.subTest(value=value):
                self.assertEqual(de.extract_email_domain(value), "")


class MatchingTests(SimpleTestCase):
    def check(self, email, lists=TEST_LISTS, extra_allowed=frozenset()):
        return de.check_email(email, lists, extra_allowed)

    def test_ordinary_domains_are_allowed(self):
        for email in ("john@gmail.com", "employee@company.com"):
            with self.subTest(email=email):
                result = self.check(email)
                self.assertTrue(result.allowed)
                self.assertEqual(result.code, de.ALLOWED_CODE)

    def test_listed_domain_is_blocked_case_and_whitespace_insensitive(self):
        for email in ("test@mailinator.com", "JOHN@MAILINATOR.COM", "  test@mailinator.com  "):
            with self.subTest(email=email):
                result = self.check(email)
                self.assertFalse(result.allowed)
                self.assertEqual(result.code, de.DISPOSABLE_EMAIL_CODE)
                self.assertEqual(result.message, de.DISPOSABLE_EMAIL_MESSAGE)

    def test_subdomain_of_listed_domain_is_blocked(self):
        result = self.check("test@a.sub.mailinator.com")
        self.assertTrue(result.is_disposable)
        self.assertEqual(result.matched_domain, "mailinator.com")

    def test_similar_looking_domains_are_not_blocked_by_substring(self):
        for email in ("test@notmailinator.com", "test@mailinator.company", "test@mailinator.com.au", "test@mailinatorcom.net"):
            with self.subTest(email=email):
                self.assertTrue(self.check(email).allowed)

    def test_internationalized_listed_domain_is_blocked(self):
        self.assertTrue(self.check("user@bücher.example").is_disposable)

    def test_allowlist_wins_for_domain_and_subdomains(self):
        lists = de.DomainLists(blocked=TEST_LISTS.blocked, allowed=frozenset({"mailinator.com"}))
        self.assertTrue(self.check("a@mailinator.com", lists).allowed)
        self.assertTrue(self.check("a@sub.mailinator.com", lists).allowed)
        self.assertTrue(self.check("a@mailinator.com", extra_allowed=de.parse_domain_csv("MAILINATOR.com, x.org")).allowed)

    def test_malformed_address_on_a_listed_domain_is_still_blocked(self):
        # Strict parsing rejects these, but Cognito may accept them; the
        # blocklist must still apply so they cannot slip through as "invalid".
        for email in ('"a b"@mailinator.com', "a b@mailinator.com", "a@x_y.mailinator.com", "a@-x.mailinator.com"):
            with self.subTest(email=email):
                result = self.check(email)
                self.assertTrue(result.is_disposable)
                self.assertEqual(result.matched_domain, "mailinator.com")
        self.assertEqual(self.check("a b@gmail.com").code, de.INVALID_EMAIL_CODE)
        self.assertEqual(self.check("a b@notmailinator-ok.com").code, de.INVALID_EMAIL_CODE)

    def test_invalid_input_is_reported_not_raised(self):
        for email in ("", "not-an-email", "user@localhost", None, ["a@b.com"]):
            with self.subTest(email=email):
                result = self.check(email)
                self.assertFalse(result.allowed)
                self.assertEqual(result.code, de.INVALID_EMAIL_CODE)


class DatasetTests(SimpleTestCase):
    def test_bundled_blocklist_matches_recorded_source(self):
        raw = de.BLOCKLIST_PATH.read_bytes()
        source = json.loads((de.DATA_DIR / "SOURCE.json").read_text())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), source["sha256"])
        self.assertEqual(len(de.load_domain_file(de.BLOCKLIST_PATH)), source["domain_count"])
        self.assertEqual(source["license"], "CC0-1.0")
        self.assertTrue((de.DATA_DIR / "LICENSE.txt").exists())

    def test_bundled_lists_load_and_cover_the_spec_examples(self):
        lists = de.load_domain_lists()
        self.assertGreaterEqual(len(lists.blocked), de.MIN_EXPECTED_BLOCKLIST_SIZE)
        self.assertTrue(de.check_email("test@mailinator.com", lists).is_disposable)
        self.assertTrue(de.check_email("test@sub.mailinator.com", lists).is_disposable)
        for email in ("john@gmail.com", "a@outlook.com", "a@yahoo.com", "a@icloud.com", "a@proton.me", "a@mailinator.company"):
            with self.subTest(email=email):
                self.assertTrue(de.check_email(email, lists).allowed)

    def test_malformed_lines_are_skipped(self):
        with self.assertLogs("users.disposable_email", level="WARNING"):
            domains = de.parse_domain_lines(["# comment", "", "Good.COM", "bad domain", "-x.com", "ok.org  # note"])
        self.assertEqual(domains, frozenset({"good.com", "ok.org"}))

    def test_missing_blocklist_logs_an_error_and_fails_open(self):
        with self.assertLogs("users.disposable_email", level="ERROR") as logs:
            lists = de.load_domain_lists(blocklist_path=de.DATA_DIR / "missing.conf", allowlist_path=de.DATA_DIR / "missing-allow.conf")
        self.assertEqual(lists.blocked, frozenset())
        self.assertTrue(any("could not be loaded" in line for line in logs.output))


class SignupHelperTests(SimpleTestCase):
    def test_settings_allowlist_and_master_switch(self):
        self.assertTrue(de.is_disposable_signup_email("a@mailinator.com"))
        with override_settings(DISPOSABLE_EMAIL_ALLOWLIST=["mailinator.com"]):
            self.assertFalse(de.is_disposable_signup_email("a@mailinator.com"))
        with override_settings(DISPOSABLE_EMAIL_VALIDATION_ENABLED=False):
            self.assertFalse(de.is_disposable_signup_email("a@mailinator.com"))
            self.assertEqual(de.check_signup_email("bad").code, de.INVALID_EMAIL_CODE)

    def test_settings_default_to_enforcing(self):
        # Env-backed in settings/base.py; unset env must mean "on".
        from django.conf import settings

        self.assertIs(settings.DISPOSABLE_EMAIL_VALIDATION_ENABLED, True)
        self.assertIs(settings.DISPOSABLE_EMAIL_BLOCK_COGNITO_JIT, True)
        self.assertEqual(de.parse_domain_csv(settings.DISPOSABLE_EMAIL_ALLOWLIST), frozenset())

    def test_validator_raises_with_code(self):
        with self.assertRaises(ValidationError) as ctx:
            de.validate_signup_email_domain("a@mailinator.com")
        self.assertEqual(ctx.exception.code, de.DISPOSABLE_EMAIL_CODE)
        de.validate_signup_email_domain("a@gmail.com")
        de.validate_signup_email_domain("not-an-email")  # syntax is other validators' job


@override_settings(CACHES=LOCMEM_CACHE, SIGNUP_EMAIL_CHECK_THROTTLE_RATE=None)
class ValidateSignupEmailEndpointTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def post(self, payload, **extra):
        return self.client.post(VALIDATE_URL, payload, format="json", **extra)

    def test_allowed_email(self):
        response = self.post({"email": "john@gmail.com"})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data, {"allowed": True, "code": "allowed", "message": ""})
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_disposable_email(self):
        response = self.post({"email": "  Test@Sub.Mailinator.com "})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data,
            {"allowed": False, "code": "disposable_email_domain", "message": de.DISPOSABLE_EMAIL_MESSAGE},
        )

    def test_invalid_or_missing_email_is_400(self):
        for payload in ({"email": "nope"}, {"email": ""}, {}, {"email": ["a@b.com"]}):
            with self.subTest(payload=payload):
                response = self.post(payload)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.data["code"], "invalid_email")
                self.assertFalse(response.data["allowed"])

    def test_anonymous_even_with_a_stale_bearer_token(self):
        response = self.post({"email": "john@gmail.com"}, HTTP_AUTHORIZATION="Bearer not-a-real-token")
        self.assertEqual(response.status_code, 200)

    def test_response_does_not_depend_on_account_existence(self):
        User.objects.create_user(username="existing-disposable", email="old@mailinator.com", password="x-Unused-123")
        existing = self.post({"email": "old@mailinator.com"})
        unknown = self.post({"email": "new@mailinator.com"})
        self.assertEqual(existing.data, unknown.data)

    def test_get_is_not_allowed(self):
        self.assertEqual(self.client.get(VALIDATE_URL, {"email": "a@gmail.com"}).status_code, 405)

    @override_settings(SIGNUP_EMAIL_CHECK_THROTTLE_RATE="2/min")
    def test_rate_limited(self):
        self.assertEqual(self.post({"email": "a@gmail.com"}).status_code, 200)
        self.assertEqual(self.post({"email": "b@gmail.com"}).status_code, 200)
        self.assertEqual(self.post({"email": "c@gmail.com"}).status_code, 429)


@override_settings(CACHES=LOCMEM_CACHE, STRICT_EMAIL_DNS=False)
class RegisterEndpointTests(TestCase):
    def setUp(self):
        cache.clear()
        for target in ("boto3.client", "users.views.send_platform_email"):
            patcher = mock.patch(target)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = APIClient()

    def register(self, email):
        return self.client.post(
            REGISTER_URL,
            {
                "username": "newmember",
                "email": email,
                "first_name": "Ada",
                "last_name": "Member",
                "password": "Str0ng!Passw0rd",
                "password2": "Str0ng!Passw0rd",
            },
            format="json",
        )

    def test_disposable_email_is_rejected_and_no_user_created(self):
        response = self.register("someone@mailinator.com")
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn(de.DISPOSABLE_EMAIL_MESSAGE, [str(e) for e in response.data["email"]])
        self.assertFalse(User.objects.filter(email__iexact="someone@mailinator.com").exists())

    def test_regular_email_still_registers(self):
        response = self.register("someone@company-example.com")
        self.assertEqual(response.status_code, 201, response.content)
        self.assertTrue(User.objects.filter(email="someone@company-example.com").exists())

    def test_profile_update_validator_does_not_block_existing_disposable_domains(self):
        user = User.objects.create_user(username="legacy", email="legacy@mailinator.com", password="x-Unused-123")
        self.assertEqual(validate_email_strict("legacy@mailinator.com", instance=user), "legacy@mailinator.com")


@override_settings(CACHES=LOCMEM_CACHE)
class GuestRegisterTests(TestCase):
    def call(self, email):
        from events.guest_views import GuestRegisterView

        guest = mock.MagicMock(email="guest@example.com")
        guest_user = mock.MagicMock(is_guest=True, is_authenticated=True, guest=guest)
        request = APIRequestFactory().post(
            "/api/auth/guest-register/",
            {"first_name": "Ada", "last_name": "Guest", "email": email, "password": "Str0ng!Passw0rd"},
            format="json",
        )
        force_authenticate(request, user=guest_user)
        return GuestRegisterView.as_view()(request), guest

    def test_disposable_email_rejected_before_any_change(self):
        with mock.patch("users.cognito_auth.create_cognito_user_from_guest") as create:
            response, guest = self.call("guest@mailinator.com")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], de.DISPOSABLE_EMAIL_CODE)
        create.assert_not_called()
        guest.save.assert_not_called()

    def test_regular_email_continues_to_account_creation(self):
        with mock.patch("users.cognito_auth.create_cognito_user_from_guest") as create, mock.patch(
            "users.email_utils.link_guest_history_to_user"
        ):
            create.return_value = mock.MagicMock(id=99)
            response, _ = self.call("guest@company-example.com")
        self.assertEqual(response.status_code, 200, response.data)
        create.assert_called_once()


@override_settings(
    CACHES=LOCMEM_CACHE,
    FRONTEND_URL="http://frontend.test",
    GOOGLE_CLIENT_ID="cid",
    GOOGLE_CLIENT_SECRET="secret",
    GOOGLE_REDIRECT_URI="http://backend.test/cb",
)
class LegacyGoogleCallbackTests(TestCase):
    def setUp(self):
        boto = mock.patch("boto3.client")
        boto.start()
        self.addCleanup(boto.stop)
        self.client = APIClient()

    def callback(self, email):
        token = mock.MagicMock(status_code=200)
        token.json.return_value = {"access_token": "google-token"}
        info = mock.MagicMock(status_code=200)
        info.json.return_value = {"email": email, "given_name": "Ada", "family_name": "Tester"}
        with mock.patch("users.views.requests.post", return_value=token), mock.patch(
            "users.views.requests.get", return_value=info
        ):
            return self.client.get(GOOGLE_CALLBACK_URL, {"code": "abc"})

    def test_new_disposable_user_is_not_created(self):
        response = self.callback("new@mailinator.com")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error"], de.DISPOSABLE_EMAIL_CODE)
        self.assertFalse(User.objects.filter(email="new@mailinator.com").exists())

    def test_existing_disposable_user_still_signs_in(self):
        User.objects.create_user(username="legacy-google", email="old@mailinator.com", password="x-Unused-123")
        response = self.callback("old@mailinator.com")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(User.objects.filter(email="old@mailinator.com").count(), 1)

    def test_new_regular_user_is_created(self):
        response = self.callback("new@company-example.com")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(email="new@company-example.com").exists())


# ---------------------------------------------------------------- Cognito JIT --
REGION = "eu-central-1"
POOL_ID = "eu-central-1_TESTPOOL"
CLIENT_ID = "test-client-id"
ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{POOL_ID}"
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PEM = _PRIVATE_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def make_id_token(sub, email, username=None, **extra):
    now = int(time.time())
    claims = {
        "sub": sub,
        "iss": ISSUER,
        "token_use": "id",
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 3600,
        "cognito:username": username or f"user-{sub[:8]}",
        "email": email,
        "email_verified": True,
        **extra,
    }
    return jwt.encode(claims, _PEM, algorithm="RS256", headers={"kid": "test-kid"})


@override_settings(
    CACHES=LOCMEM_CACHE,
    COGNITO_REGION=REGION,
    COGNITO_USER_POOL_ID=POOL_ID,
    COGNITO_APP_CLIENT_ID=CLIENT_ID,
)
class CognitoJitCreationTests(TestCase):
    def setUp(self):
        for target, kwargs in (
            ("boto3.client", {}),
            ("users.tasks.sync_user_to_saleor_async.delay", {}),
            ("users.cognito_auth._get_public_key", {"return_value": _PRIVATE_KEY.public_key()}),
            ("users.cognito_auth._fetch_imaa_wordpress_user_profile", {"return_value": None}),
            ("users.cognito_auth._enable_federated_user_password", {"return_value": True}),
        ):
            patcher = mock.patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def authenticate(self, token):
        request = APIRequestFactory().get("/api/auth/users/me/", HTTP_AUTHORIZATION=f"Bearer {token}")
        return CognitoJWTAuthentication().authenticate(request)

    def test_new_native_signup_with_disposable_domain_gets_no_local_user(self):
        with self.assertLogs("users.cognito_auth", level=logging.WARNING):
            with self.assertRaises(AuthenticationFailed) as ctx:
                self.authenticate(make_id_token(str(uuid.uuid4()), "fresh@mailinator.com"))
        self.assertEqual(ctx.exception.get_codes(), de.DISPOSABLE_EMAIL_CODE)
        self.assertFalse(User.objects.filter(email="fresh@mailinator.com").exists())

    def test_new_unverified_disposable_identity_is_also_refused(self):
        token = make_id_token(str(uuid.uuid4()), "fresh@mailinator.com", email_verified=False)
        with self.assertLogs("users.cognito_auth", level=logging.WARNING), self.assertRaises(AuthenticationFailed):
            self.authenticate(token)
        self.assertFalse(User.objects.filter(email="fresh@mailinator.com").exists())

    def test_first_time_federated_disposable_signup_is_refused(self):
        token = make_id_token(
            str(uuid.uuid4()),
            "fed@mailinator.com",
            username="Google_123",
            identities=[{"providerName": "Google"}],
        )
        with self.assertLogs("users.cognito_auth", level=logging.WARNING), self.assertRaises(AuthenticationFailed):
            self.authenticate(token)
        self.assertFalse(User.objects.filter(email="fed@mailinator.com").exists())

    def test_imaa_wordpress_sso_is_exempt(self):
        # Both IdP names, matching the Lambda's EXEMPT_EXTERNAL_PROVIDERS default.
        for idp in ("IMAAWordPressOAuth", "IMAAWordPress"):
            with self.subTest(idp=idp):
                email = f"member-{idp.lower()}@mailinator.com"
                token = make_id_token(
                    str(uuid.uuid4()), email, username=f"{idp}_member", identities=[{"providerName": idp}]
                )
                user, _ = self.authenticate(token)
                self.assertEqual(user.email, email)

    def test_existing_identity_with_disposable_domain_still_authenticates(self):
        sub = str(uuid.uuid4())
        user = User.objects.create_user(username="legacy-member", email="legacy@mailinator.com", password="x-Unused-123")
        UserProfile.objects.get_or_create(user=user)
        CognitoIdentity.objects.create(user=user, cognito_sub=sub, email=user.email, provider="cognito")
        authed, _ = self.authenticate(make_id_token(sub, "legacy@mailinator.com"))
        self.assertEqual(authed.pk, user.pk)

    def test_existing_local_user_with_new_cognito_sub_is_linked_not_blocked(self):
        user = User.objects.create_user(username="wp-member", email="Old@Mailinator.com", password="x-Unused-123")
        sub = str(uuid.uuid4())
        authed, _ = self.authenticate(make_id_token(sub, "old@mailinator.com"))
        self.assertEqual(authed.pk, user.pk)
        self.assertTrue(CognitoIdentity.objects.filter(cognito_sub=sub, user=user).exists())

    def test_new_regular_signup_still_creates_a_user(self):
        user, _ = self.authenticate(make_id_token(str(uuid.uuid4()), "fresh@company-example.com"))
        self.assertEqual(user.email, "fresh@company-example.com")

    # ------------------- unverified email must never select an existing account --
    def test_unverified_email_never_attaches_to_an_existing_django_user(self):
        victim = User.objects.create_user(username="victim", email="Victim@Example.com", password="x-Unused-123")
        for claim in (False, "false", None):
            with self.subTest(email_verified=claim):
                sub = str(uuid.uuid4())
                token = make_id_token(sub, "victim@example.com", username=f"Google_{sub[:6]}",
                                      identities=[{"providerName": "Google"}], email_verified=claim)
                with self.assertLogs("users.cognito_auth", level=logging.WARNING), self.assertRaises(AuthenticationFailed) as ctx:
                    self.authenticate(token)
                self.assertEqual(ctx.exception.get_codes(), "email_not_verified")
                self.assertFalse(CognitoIdentity.objects.filter(cognito_sub=sub).exists())
        self.assertEqual(User.objects.filter(email__iexact="victim@example.com").count(), 1)
        self.assertFalse(CognitoIdentity.objects.filter(user=victim).exists())

    def test_verified_email_still_attaches_to_the_existing_django_user(self):
        member = User.objects.create_user(username="member", email="member@example.com", password="x-Unused-123")
        sub = str(uuid.uuid4())
        authed, _ = self.authenticate(make_id_token(sub, "member@example.com", email_verified=True))
        self.assertEqual(authed.pk, member.pk)
        self.assertTrue(CognitoIdentity.objects.filter(cognito_sub=sub, user=member).exists())

    def test_unverified_email_with_no_existing_account_still_creates_a_user(self):
        user, _ = self.authenticate(make_id_token(str(uuid.uuid4()), "brand-new@company-example.com", email_verified=False))
        self.assertEqual(user.email, "brand-new@company-example.com")

    def test_known_identity_with_unverified_claim_still_authenticates(self):
        sub = str(uuid.uuid4())
        member = User.objects.create_user(username="known", email="known@example.com", password="x-Unused-123")
        UserProfile.objects.get_or_create(user=member)
        CognitoIdentity.objects.create(user=member, cognito_sub=sub, email=member.email, provider="google")
        authed, _ = self.authenticate(make_id_token(sub, "known@example.com", email_verified=False))
        self.assertEqual(authed.pk, member.pk)

    def test_creation_failure_fallback_does_not_attach_by_unverified_email(self):
        User.objects.create_user(username="taken-name", email="other@example.com", password="x-Unused-123")
        with mock.patch("users.cognito_auth._unique_username", return_value="taken-name"), \
                self.assertLogs("users.cognito_auth", level=logging.WARNING), \
                self.assertRaises(AuthenticationFailed):
            self.authenticate(make_id_token(str(uuid.uuid4()), "fresh@company-example.com", email_verified=False))
        self.assertFalse(User.objects.filter(email="fresh@company-example.com").exists())

    def test_imaa_sso_first_login_still_attaches_to_existing_member(self):
        # IMAA tokens carry email_verified=true (the trigger auto-verifies them),
        # so existing IMAA members keep mapping onto their Django account.
        member = User.objects.create_user(username="imaa-member", email="m@imaa-member.org", password="x-Unused-123")
        for idp in ("IMAAWordPress", "IMAAWordPressOAuth"):
            with self.subTest(idp=idp):
                sub = str(uuid.uuid4())
                authed, _ = self.authenticate(make_id_token(sub, "m@imaa-member.org", username=f"{idp}_m",
                                                            identities=[{"providerName": idp}]))
                self.assertEqual(authed.pk, member.pk)

    # ------------------------------------------------ cross-client bypass checks --
    def test_tokens_issued_to_other_app_clients_are_rejected(self):
        # A disposable account created through MANDA/Saleor/unknown clients cannot
        # use that client's tokens against IMAA Connect.
        for other in ("uf02q0duojl9s6tkuahegm2f8", "414gibcnh1kdspg940ujglml3n", "unknown-client"):
            with self.subTest(client=other):
                with self.assertRaises(AuthenticationFailed) as ctx:
                    self.authenticate(make_id_token(str(uuid.uuid4()), "cross@mailinator.com", aud=other))
                self.assertIn("audience", str(ctx.exception.detail))
        self.assertFalse(User.objects.filter(email="cross@mailinator.com").exists())

    def test_disposable_account_from_another_client_gets_no_imaa_profile_on_imaa_login(self):
        # The same Cognito user signing in through the IMAA client (valid audience)
        # is a brand-new identity to Django: the backstop refuses a local user.
        for username, identities in (("cross-native", None), ("Google_55", [{"providerName": "Google"}]),
                                     ("LinkedIn_Ab", [{"providerName": "LinkedIn"}])):
            with self.subTest(username=username):
                extra = {"identities": identities} if identities else {}
                with self.assertLogs("users.cognito_auth", level=logging.WARNING), self.assertRaises(AuthenticationFailed) as ctx:
                    self.authenticate(make_id_token(str(uuid.uuid4()), "cross@mailinator.com", username=username, **extra))
                self.assertEqual(ctx.exception.get_codes(), de.DISPOSABLE_EMAIL_CODE)
        self.assertFalse(User.objects.filter(email="cross@mailinator.com").exists())

    # ------------------------------------------- admin-created test accounts --
    def test_admin_created_disposable_test_user_can_log_in(self):
        # Mirrors StaffUserViewSet.create-with-password (superuser only): the Django
        # user is created FIRST, then Cognito AdminCreateUser with email_verified=true.
        # The first IMAA login attaches to that user; the disposable backstop does not apply.
        tester = User.objects.create_user(username="qa-tester", email="qa-tester@mailinator.com", password="x-Unused-123")
        UserProfile.objects.get_or_create(user=tester)
        sub = str(uuid.uuid4())
        authed, _ = self.authenticate(make_id_token(sub, "qa-tester@mailinator.com", username="qa-tester@mailinator.com"))
        self.assertEqual(authed.pk, tester.pk)
        # ...and later logins resolve by the stored sub.
        again, _ = self.authenticate(make_id_token(sub, "qa-tester@mailinator.com", username="qa-tester@mailinator.com"))
        self.assertEqual(again.pk, tester.pk)

    def test_documented_gap_console_only_admin_user_without_django_row_is_refused(self):
        # A disposable user created ONLY in the AWS Cognito console (no Django user)
        # is indistinguishable from a direct public signup in the token, so the
        # backstop refuses it. Supporting it needs an approved trusted signal.
        with self.assertLogs("users.cognito_auth", level=logging.WARNING), self.assertRaises(AuthenticationFailed):
            self.authenticate(make_id_token(str(uuid.uuid4()), "console-only@mailinator.com", username="console-only"))
        self.assertFalse(User.objects.filter(email="console-only@mailinator.com").exists())

    # ------------------------------ legacy provider_username fallback (step 3) --
    def _victim(self, username):
        victim = User.objects.create_user(username=username, email="victim@example.com", password="x-Unused-123")
        UserProfile.objects.get_or_create(user=victim)
        return victim

    def test_unverified_native_identity_cannot_take_over_an_account_by_username_collision(self):
        # A native Cognito username is chosen by whoever signs up, so a matching
        # Django username proves nothing about ownership.
        victim = self._victim("victim-member")
        for email in ("attacker@example.org", ""):  # unverified email, or none at all
            with self.subTest(email=email):
                sub = str(uuid.uuid4())
                authed, _ = self.authenticate(make_id_token(sub, email, username="Victim-Member", email_verified=False))
                self.assertNotEqual(authed.pk, victim.pk)
                self.assertFalse(CognitoIdentity.objects.filter(user=victim).exists())

    def test_native_username_spoofing_a_federated_prefix_is_not_trusted(self):
        # No `identities` claim: this is a native user who picked "google_…" as a username.
        victim = self._victim("google_1093")
        authed, _ = self.authenticate(make_id_token(str(uuid.uuid4()), "", username="google_1093", email_verified=False))
        self.assertNotEqual(authed.pk, victim.pk)
        # Mismatched identities claim (a LinkedIn identity carrying a Google_ username) is not trusted either.
        authed, _ = self.authenticate(make_id_token(str(uuid.uuid4()), "", username="google_1093", email_verified=False,
                                                    identities=[{"providerName": "LinkedIn"}]))
        self.assertNotEqual(authed.pk, victim.pk)

    def test_legacy_federated_username_mapping_still_resolves(self):
        # Older code stored Cognito-assigned federated usernames as Django usernames.
        # Cognito assigns "<Provider>_<subject>" itself and the signed `identities`
        # claim confirms it, so this mapping remains trusted.
        for idp, legacy_username in (("Google", "google_555"), ("IMAAWordPressOAuth", "imaawordpressoauth_77"),
                                     ("IMAAWordPress", "IMAAWordPress_Jane_Doe")):
            with self.subTest(idp=idp):
                legacy = User.objects.create_user(username=legacy_username, email="", password="x-Unused-123")
                UserProfile.objects.get_or_create(user=legacy)
                sub = str(uuid.uuid4())
                authed, _ = self.authenticate(make_id_token(sub, "", username=legacy_username.upper() if idp == "Google" else legacy_username,
                                                            email_verified=False, identities=[{"providerName": idp}]))
                self.assertEqual(authed.pk, legacy.pk)
                self.assertTrue(CognitoIdentity.objects.filter(cognito_sub=sub, user=legacy).exists())

    @override_settings(DISPOSABLE_EMAIL_BLOCK_COGNITO_JIT=False)
    def test_jit_backstop_can_be_switched_off(self):
        user, _ = self.authenticate(make_id_token(str(uuid.uuid4()), "fresh@mailinator.com"))
        self.assertEqual(user.email, "fresh@mailinator.com")
