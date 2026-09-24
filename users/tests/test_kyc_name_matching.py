"""
KYC name matching for non-Latin / special-character names.

All names and emails below are fictional test data.
"""
import hashlib
import hmac
import json
from io import StringIO

from django.contrib.auth.models import User
from django.core import mail
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, override_settings
from rest_framework.test import APIClient

from users.kyc_name_match import (
    best_linkedin_match,
    looks_like_mojibake,
    name_parts,
    repair_mojibake,
)
from users.models import UserProfile


def garble(text: str) -> str:
    """Simulate the bug: UTF-8 bytes decoded one byte at a time as cp1252 (Latin-1 fallback)."""
    out = []
    for b in text.encode("utf-8"):
        try:
            out.append(bytes([b]).decode("cp1252"))
        except UnicodeDecodeError:
            out.append(chr(b))
    return "".join(out)


class RepairMojibakeTests(SimpleTestCase):
    def test_repairs_cjk_vietnamese_and_emoji(self):
        for original in ["Alex Lin 林测试", "山田 太郎", "김 민수", "Đặng Văn Hùng", "Verified ✅"]:
            with self.subTest(original=original):
                broken = garble(original)
                self.assertNotEqual(broken, original)
                self.assertTrue(looks_like_mojibake(broken))
                self.assertEqual(repair_mojibake(broken), original)

    def test_repairs_latin1_decoded_text(self):
        broken = "林测试".encode("utf-8").decode("latin-1")
        self.assertEqual(repair_mojibake(broken), "林测试")

    def test_repairs_double_encoded_text(self):
        self.assertEqual(repair_mojibake(garble(garble("Test Nguyễn"))), "Test Nguyễn")

    def test_leaves_valid_names_untouched(self):
        for name in ["", "John Smith", "José Müller", "Søren Ærø", "Ångström", "林测试", "Đặng Văn Hùng", "Naïve Café"]:
            with self.subTest(name=name):
                self.assertEqual(repair_mojibake(name), name)
                self.assertFalse(looks_like_mojibake(name))


class NameMatchingMatrixTests(SimpleTestCase):
    """Same matrix that exposed the bugs; every row failed before the fix unless noted."""

    PASS_CASES = [
        # (label, profile name, ID-document name)
        ("CN garbled profile", garble("Alex Lin 林测试"), "LIN ALEX"),
        ("CN native both sides", "林测试", "林测试"),
        ("CN native with vs without space", "林 测试", "林测试"),
        ("CN mixed profile vs latin passport", "Alex Lin 林测试", "ALEX LIN"),
        ("JP native both sides", "山田 太郎", "山田 太郎"),
        ("JP full-width latin", "ＴＡＲＯ ＹＡＭＡＤＡ", "YAMADA TARO"),
        ("KR native both sides", "김 민수", "김 민수"),
        ("VN Đ", "Đặng Văn Hùng", "DANG VAN HUNG"),
        ("VN Nguyễn (passed before too)", "Nguyễn Thị Lan", "NGUYEN THI LAN"),
        ("NO æ/ø", "Søren Ærø", "SOREN AERO"),
        ("PL ł", "Paweł Łukasz", "PAWEL LUKASZ"),
        ("DE ß", "Hans Weiß", "HANS WEISS"),
        ("apostrophe", "Sean O'Brien", "SEAN OBRIEN"),
        ("curly apostrophe", "Sean O’Brien", "SEAN O'BRIEN"),
        ("hyphen (passed before too)", "Anne-Marie Smith", "ANNE MARIE SMITH"),
        ("mononym", "Sukarno", "SUKARNO"),
        ("title stripped", "Dr. John Smith", "JOHN SMITH"),
    ]

    FAIL_CASES = [
        # (label, profile, id, needs_review)
        ("latin mismatch", "John Smith", "PETER JONES", False),
        ("mononym mismatch", "Sukarno", "SUHARTO", False),
        ("CN native mismatch", "林测试", "王测试", True),
        ("JP native vs romanized", "山田 太郎", "YAMADA TARO", True),
        ("KR native vs romanized", "김 민수", "KIM MINSU", True),
        ("CN mixed vs pinyin passport", "Alex Lin 林测试", "LIN CESHI", True),
        ("JP dakuten is significant", "がく", "かく", True),
    ]

    def test_pass_cases(self):
        for label, profile, id_name in self.PASS_CASES:
            with self.subTest(label):
                ok, debug = best_linkedin_match([profile], [id_name])
                self.assertTrue(ok, debug)

    def test_fail_cases(self):
        for label, profile, id_name, needs_review in self.FAIL_CASES:
            with self.subTest(label):
                ok, debug = best_linkedin_match([profile], [id_name])
                self.assertFalse(ok, debug)
                self.assertEqual(debug["needs_review"], needs_review, debug)

    def test_unrepairable_garbage_goes_to_review(self):
        # Invisible control bytes stripped upstream -> cannot be repaired.
        broken = "".join(ch for ch in garble("Alex Lin 林测试") if not 0x80 <= ord(ch) <= 0x9F)
        broken = broken.replace("Ž", "").replace("‹", "")
        self.assertEqual(repair_mojibake(broken), broken)
        ok, debug = best_linkedin_match([broken], ["LIN ALEX"])
        self.assertFalse(ok, debug)
        self.assertTrue(debug["needs_review"], debug)

    def test_name_parts_splits_scripts(self):
        self.assertEqual(name_parts("Alex Lin 林测试"), (["alex", "lin"], ["林测试"]))
        self.assertEqual(name_parts("Đặng Văn Hùng"), (["dang", "van", "hung"], []))

    def test_debug_is_json_serializable(self):
        _, debug = best_linkedin_match(["山田 太郎"], ["YAMADA TARO"])
        json.dumps(debug)


WEBHOOK_SECRET = "test-webhook-secret"


@override_settings(
    DIDIT_WEBHOOK_SECRET=WEBHOOK_SECRET,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
)
class DiditWebhookNameMatchTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username="kyc-test-user",
            email="kyc-test-user@example.com",
            password="ValidPassword123!",
        )
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)

    def _set_name(self, first, last, full):
        self.user.first_name, self.user.last_name = first, last
        self.user.save()
        self.profile.full_name = full
        self.profile.kyc_status = UserProfile.KYC_STATUS_PENDING
        self.profile.save()

    def _post(self, id_full, id_first="", id_last="", status="Approved"):
        body = json.dumps({
            "session_id": "test-session-1",
            "status": status,
            "vendor_data": f"kyc_initial:{self.user.id}",
            "decision": {"id_verification": {"full_name": id_full, "first_name": id_first, "last_name": id_last}},
        }).encode("utf-8")
        signature = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
        response = self.client.generic(
            "POST", "/api/auth/didit/webhook/", body,
            content_type="application/json", HTTP_X_SIGNATURE=signature,
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.profile.refresh_from_db()
        return self.profile

    def test_garbled_profile_name_is_approved(self):
        self._set_name("Alex", garble("Lin 林测试"), garble("Alex Lin 林测试"))
        profile = self._post("LIN ALEX", "ALEX", "LIN")
        self.assertEqual(profile.kyc_status, UserProfile.KYC_STATUS_APPROVED)
        self.assertTrue(profile.legal_name_locked)

    def test_vietnamese_name_is_approved(self):
        self._set_name("Đặng", "Văn Hùng", "Đặng Văn Hùng")
        profile = self._post("DANG VAN HUNG", "VAN HUNG", "DANG")
        self.assertEqual(profile.kyc_status, UserProfile.KYC_STATUS_APPROVED)

    def test_native_script_mismatch_goes_to_review_not_declined(self):
        self._set_name("太郎", "山田", "山田 太郎")
        profile = self._post("YAMADA TARO", "TARO", "YAMADA")
        self.assertEqual(profile.kyc_status, UserProfile.KYC_STATUS_REVIEW)
        self.assertEqual(profile.kyc_decline_reason, UserProfile.KYC_DECLINE_REASON_NAME_MISMATCH)
        self.assertFalse(profile.legal_name_locked)

    def test_latin_mismatch_is_still_declined(self):
        self._set_name("John", "Smith", "John Smith")
        profile = self._post("PETER JONES", "PETER", "JONES")
        self.assertEqual(profile.kyc_status, UserProfile.KYC_STATUS_DECLINED)

    def test_no_emails_sent(self):
        self._set_name("太郎", "山田", "山田 太郎")
        self._post("YAMADA TARO", "TARO", "YAMADA")
        self.assertEqual(len(mail.outbox), 0)


class RepairMojibakeNamesCommandTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="mojibake-test-user",
            email="mojibake-test-user@example.com",
            first_name="Alex",
            last_name=garble("Lin 林测试"),
        )
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)
        self.profile.full_name = garble("Alex Lin 林测试")
        self.profile.save()
        self.clean_user = User.objects.create_user(
            username="accent-test-user", email="accent-test-user@example.com",
            first_name="José", last_name="Müller",
        )

    def test_dry_run_changes_nothing(self):
        out = StringIO()
        call_command("repair_mojibake_names", stdout=out)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.full_name, garble("Alex Lin 林测试"))
        self.assertIn("Dry run: 2 record(s)", out.getvalue())

    def test_commit_repairs_and_leaves_valid_accents(self):
        call_command("repair_mojibake_names", "--commit", stdout=StringIO())
        self.profile.refresh_from_db()
        self.user.refresh_from_db()
        self.clean_user.refresh_from_db()
        self.assertEqual(self.profile.full_name, "Alex Lin 林测试")
        self.assertEqual(self.user.last_name, "Lin 林测试")
        self.assertEqual((self.clean_user.first_name, self.clean_user.last_name), ("José", "Müller"))
