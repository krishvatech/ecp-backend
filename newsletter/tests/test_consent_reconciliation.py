import json
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from newsletter import consent_reconciliation as rec
from newsletter.mautic.exceptions import PermanentMauticError, TemporaryMauticError
from newsletter.models import (
    MauticContactMapping,
    MauticEmailSuppression,
    MauticIdentityAuditLog,
    NewsletterCategory,
    NewsletterSubscription,
)
from newsletter.webhooks import _sync_email_suppression

User = get_user_model()
R = MauticEmailSuppression.Reason


def contact(*reasons):
    return {"id": 1, "doNotContact": [{"id": i, "channel": "email", "reason": r, "channelId": None}
                                      for i, r in enumerate(reasons, start=1)]}


class FakeMautic:
    """get_contact answers from a script: a dict, an exception, or a callable."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def get_contact(self, contact_id, *, timeout=None):
        self.calls.append((str(contact_id), timeout))
        answer = self.answers[str(contact_id)]
        if isinstance(answer, list):
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        if callable(answer):
            answer = answer()
        if isinstance(answer, Exception):
            raise answer
        return answer


class ClassifyTests(SimpleTestCase):
    def test_rules(self):
        cases = [
            (None, [], (rec.IN_SYNC, rec.NONE)),
            (None, [R.UNSUBSCRIBED], (rec.MISSING_SUPPRESSION, rec.CREATE)),
            (None, [R.UNSUBSCRIBED, R.BOUNCED], (rec.MISSING_SUPPRESSION, rec.CREATE)),
            (R.UNSUBSCRIBED, [R.UNSUBSCRIBED], (rec.IN_SYNC, rec.NONE)),
            (R.UNSUBSCRIBED, [R.BOUNCED], (rec.ESCALATION, rec.ESCALATE)),
            (R.UNSUBSCRIBED, [R.UNSUBSCRIBED, R.MANUAL], (rec.ESCALATION, rec.ESCALATE)),
            (R.UNSUBSCRIBED, [], (rec.STALE_OPT_OUT, rec.CLEAR)),
            (R.BOUNCED, [], (rec.STALE_RESTRICTION, rec.MANUAL_REVIEW)),
            (R.MANUAL, [], (rec.STALE_RESTRICTION, rec.MANUAL_REVIEW)),
            (R.UNKNOWN, [], (rec.STALE_RESTRICTION, rec.MANUAL_REVIEW)),
            (R.BOUNCED, [R.UNSUBSCRIBED], (rec.REASON_DOWNGRADE, rec.MANUAL_REVIEW)),
            (R.MANUAL, [R.BOUNCED], (rec.REASON_DIFFERS, rec.MANUAL_REVIEW)),
            (R.BOUNCED, [R.BOUNCED, R.UNSUBSCRIBED], (rec.IN_SYNC, rec.NONE)),
        ]
        for ecp, mautic, expected in cases:
            with self.subTest(ecp=ecp, mautic=mautic):
                self.assertEqual(rec.classify(ecp, mautic)[:2], expected)
        self.assertEqual(rec.classify(None, [R.MANUAL, R.BOUNCED])[2], R.BOUNCED)


class ReconcilerTests(TestCase):
    def setUp(self):
        self.users = {}

    def member(self, key, contact_id, *, reason=None, suppressed_at=None, mapped=True):
        user = User.objects.create_user(username=f"rec-{key}", email=f"rec-{key}@example.test", password="pw")
        self.users[key] = user
        if mapped:
            MauticContactMapping.objects.create(user=user, mautic_contact_id=str(contact_id))
        if reason:
            MauticEmailSuppression.objects.create(
                user=user, reason=reason, mautic_contact_id=str(contact_id),
                suppressed_at=suppressed_at or timezone.now() - timedelta(days=1))
        return user

    def run_rec(self, answers, **kwargs):
        fake = FakeMautic(answers)
        reconciler = rec.Reconciler(client=fake, **kwargs)
        summary = reconciler.run()
        return {f.user_id: f for f in reconciler.findings}, summary, fake

    def suppressed(self, key):
        return MauticEmailSuppression.objects.filter(user=self.users[key]).first()

    def audits(self):
        return MauticIdentityAuditLog.objects.filter(action=rec.AUDIT_ACTION)

    # 1, 2, 3, 15
    def test_read_only_default_reports_and_changes_nothing(self):
        self.member("match", 10, reason=R.UNSUBSCRIBED)
        self.member("missing", 11)
        self.member("stale", 12, reason=R.UNSUBSCRIBED)
        before = list(MauticEmailSuppression.objects.order_by("user_id").values())

        findings, summary, _ = self.run_rec({"10": contact(1), "11": contact(1), "12": contact()})

        self.assertEqual(summary["mode"], "read-only")
        self.assertEqual(findings[self.users["match"].pk].status, rec.IN_SYNC)
        self.assertEqual(findings[self.users["missing"].pk].status, rec.MISSING_SUPPRESSION)
        self.assertEqual(findings[self.users["stale"].pk].status, rec.STALE_OPT_OUT)
        self.assertEqual(list(MauticEmailSuppression.objects.order_by("user_id").values()), before)
        self.assertFalse(self.audits().exists())

    def test_apply_creates_missing_and_clears_stale_opt_out_with_audit(self):
        self.member("missing", 11)
        self.member("stale", 12, reason=R.UNSUBSCRIBED)
        self.member("escalate", 13, reason=R.UNSUBSCRIBED)

        findings, summary, fake = self.run_rec(
            {"11": contact(1), "12": contact(), "13": contact(2)}, apply=True)

        self.assertEqual(self.suppressed("missing").reason, R.UNSUBSCRIBED)
        self.assertIsNone(self.suppressed("stale"))
        self.assertEqual(self.suppressed("escalate").reason, R.BOUNCED)
        self.assertEqual(summary["outcomes"], {"applied": 3})
        self.assertEqual(self.audits().filter(status="succeeded").count(), 3)
        # The clear re-read Mautic before lifting anything.
        self.assertEqual([call[0] for call in fake.calls].count("12"), 2)

    # 4
    def test_independent_ecp_opt_out_is_never_touched(self):
        user = self.member("optout", 14)
        category = NewsletterCategory.objects.create(name="Rec News", slug="rec-news")
        NewsletterSubscription.objects.create(user=user, category=category, is_subscribed=False,
                                              unsubscribed_at=timezone.now())
        findings, _, _ = self.run_rec({"14": contact()}, apply=True)

        self.assertEqual(findings[user.pk].status, rec.IN_SYNC)
        sub = NewsletterSubscription.objects.get(user=user)
        self.assertFalse(sub.is_subscribed)
        self.assertEqual(NewsletterSubscription.objects.filter(user=user).count(), 1)

    # 5, 6
    def test_manual_bounce_and_unknown_are_never_lifted(self):
        for key, cid, reason in (("manual", 15, R.MANUAL), ("bounce", 16, R.BOUNCED), ("unknown", 17, R.UNKNOWN)):
            self.member(key, cid, reason=reason)
        findings, _, _ = self.run_rec({"15": contact(), "16": contact(), "17": contact()}, apply=True)

        for key, reason in (("manual", R.MANUAL), ("bounce", R.BOUNCED), ("unknown", R.UNKNOWN)):
            self.assertEqual(findings[self.users[key].pk].action, rec.MANUAL_REVIEW)
            self.assertEqual(self.suppressed(key).reason, reason)
        self.assertFalse(self.audits().exists())

    def test_reason_downgrade_is_manual_review(self):
        self.member("bounce", 18, reason=R.BOUNCED)
        findings, _, _ = self.run_rec({"18": contact(1)}, apply=True)
        self.assertEqual(findings[self.users["bounce"].pk].status, rec.REASON_DOWNGRADE)
        self.assertEqual(self.suppressed("bounce").reason, R.BOUNCED)

    # 7, 8, 9 through the real webhook handler
    def _event(self, contact_id, old, new, at):
        return {"contact": {"id": int(contact_id)}, "channel": "email", "old_status": old,
                "new_status": new, "timestamp": at.isoformat()}

    def test_older_unsubscribe_after_newer_contactable_is_corrected(self):
        self.member("x", 20)
        t1, t2 = timezone.now() - timedelta(minutes=10), timezone.now() - timedelta(minutes=5)
        _sync_email_suppression(self._event(20, "unsubscribed", "contactable", t2))  # newer, delivered first
        _sync_email_suppression(self._event(20, "contactable", "unsubscribed", t1))  # older, retried later
        self.assertIsNotNone(self.suppressed("x"), "the webhook path leaves ECP stale")

        findings, _, _ = self.run_rec({"20": contact()}, apply=True)

        self.assertEqual(findings[self.users["x"].pk].status, rec.STALE_OPT_OUT)
        self.assertIsNone(self.suppressed("x"))

    def test_older_contactable_after_newer_unsubscribe_stays_suppressed(self):
        self.member("y", 21)
        t1, t2 = timezone.now() - timedelta(minutes=10), timezone.now() - timedelta(minutes=5)
        _sync_email_suppression(self._event(21, "contactable", "unsubscribed", t2))
        _sync_email_suppression(self._event(21, "unsubscribed", "contactable", t1))
        findings, _, _ = self.run_rec({"21": contact(1)}, apply=True)

        self.assertEqual(findings[self.users["y"].pk].status, rec.IN_SYNC)
        self.assertEqual(self.suppressed("y").reason, R.UNSUBSCRIBED)

    def test_duplicate_webhook_delivery_reconciles_as_in_sync(self):
        self.member("z", 22)
        event = self._event(22, "contactable", "unsubscribed", timezone.now())
        _sync_email_suppression(event)
        _sync_email_suppression(event)
        findings, _, _ = self.run_rec({"22": contact(1)}, apply=True)
        self.assertEqual(MauticEmailSuppression.objects.filter(user=self.users["z"]).count(), 1)
        self.assertEqual(findings[self.users["z"].pk].status, rec.IN_SYNC)

    # 10, 11
    def test_provider_timeouts_change_nothing_and_stop_reads(self):
        for i in range(5):
            self.member(f"t{i}", 30 + i, reason=R.UNSUBSCRIBED)
        answers = {str(30 + i): TemporaryMauticError("Mautic API request failed (timeout)") for i in range(5)}
        findings, summary, fake = self.run_rec(answers, apply=True, max_consecutive_errors=3)

        self.assertEqual(summary["statuses"], {rec.PROVIDER_ERROR: 3, rec.NOT_CHECKED: 2})
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(MauticEmailSuppression.objects.count(), 5)
        self.assertIn("consecutive provider errors", summary["provider_stopped"])

    def test_incomplete_or_invalid_responses_change_nothing(self):
        self.member("nokey", 40, reason=R.UNSUBSCRIBED)
        self.member("notlist", 41, reason=R.UNSUBSCRIBED)
        self.member("gone", 42, reason=R.UNSUBSCRIBED)
        self.member("bad", 43, reason=R.UNSUBSCRIBED)
        findings, _, _ = self.run_rec({
            "40": {"id": 40},
            "41": {"id": 41, "doNotContact": "none"},
            "42": PermanentMauticError("Mautic API request failed (HTTP 404)"),
            "43": PermanentMauticError("Mautic API request failed (HTTP 400)"),
        }, apply=True)

        statuses = {key: findings[self.users[key].pk].status for key in ("nokey", "notlist", "gone", "bad")}
        self.assertEqual(statuses, {"nokey": rec.PROVIDER_INCOMPLETE, "notlist": rec.PROVIDER_INCOMPLETE,
                                    "gone": rec.CONTACT_NOT_FOUND, "bad": rec.PROVIDER_ERROR})
        self.assertEqual(MauticEmailSuppression.objects.count(), 4)

    # 12
    def test_unmapped_and_conflicting_contacts_are_reported_only(self):
        self.member("unmapped", 50, reason=R.UNSUBSCRIBED, mapped=False)
        user = self.member("conflict", 51)
        MauticEmailSuppression.objects.create(user=user, reason=R.UNSUBSCRIBED, mautic_contact_id="999",
                                              suppressed_at=timezone.now())
        findings, _, fake = self.run_rec({}, apply=True)

        self.assertEqual(findings[self.users["unmapped"].pk].status, rec.UNMAPPED)
        self.assertEqual(findings[user.pk].status, rec.CONTACT_ID_CONFLICT)
        self.assertEqual(fake.calls, [])
        self.assertEqual(MauticEmailSuppression.objects.count(), 2)

    # 13
    def test_repeated_apply_is_idempotent(self):
        self.member("missing", 60)
        self.member("stale", 61, reason=R.UNSUBSCRIBED)
        answers = {"60": contact(1), "61": contact()}
        self.run_rec(dict(answers), apply=True)
        audits = self.audits().count()
        findings, summary, _ = self.run_rec(dict(answers), apply=True)

        self.assertEqual(summary["statuses"], {rec.IN_SYNC: 2})
        self.assertEqual(self.audits().count(), audits)

    # 14
    def test_concurrent_row_change_is_not_overwritten(self):
        user = self.member("race", 70, reason=R.UNSUBSCRIBED)

        def webhook_lands_meanwhile():
            MauticEmailSuppression.objects.filter(user=user).update(suppressed_at=timezone.now())
            return contact()

        findings, _, _ = self.run_rec({"70": webhook_lands_meanwhile}, apply=True)
        self.assertEqual(findings[user.pk].outcome, "skipped_concurrent_change")
        self.assertIsNotNone(self.suppressed("race"))

    def test_provider_change_between_reads_cancels_the_clear(self):
        user = self.member("flip", 71, reason=R.UNSUBSCRIBED)
        findings, _, fake = self.run_rec({"71": [contact(), contact(1)]}, apply=True)
        self.assertEqual(findings[user.pk].outcome, "skipped_provider_changed")
        self.assertIsNotNone(self.suppressed("flip"))

    def test_provider_failure_on_second_read_cancels_the_clear(self):
        user = self.member("down", 72, reason=R.UNSUBSCRIBED)
        findings, _, _ = self.run_rec({"72": [contact(), TemporaryMauticError("down")]}, apply=True)
        self.assertEqual(findings[user.pk].outcome, "skipped_provider_unavailable")
        self.assertIsNotNone(self.suppressed("down"))

    def test_bounded_scope_cursor_and_timeout(self):
        for i in range(5):
            self.member(f"b{i}", 80 + i)
        fake = FakeMautic({str(80 + i): contact() for i in range(5)})
        reconciler = rec.Reconciler(client=fake, timeout=4)
        summary = reconciler.run(limit=3, batch_size=2)
        self.assertEqual((summary["checked"], summary["batches"]), (3, 2))
        self.assertIsNotNone(summary["next_after_id"])
        self.assertEqual({call[1] for call in fake.calls}, {4})
        rest = rec.Reconciler(client=fake).run(limit=3, after_id=summary["next_after_id"])
        self.assertEqual((rest["checked"], rest["next_after_id"]), (2, None))

    def test_time_budget_stops_provider_reads(self):
        self.member("late", 90)
        ticks = iter([0, 1000, 1000])
        reconciler = rec.Reconciler(client=FakeMautic({"90": contact()}), max_seconds=10, clock=lambda: next(ticks))
        summary = reconciler.run()
        self.assertEqual(summary["statuses"], {rec.NOT_CHECKED: 1})


class CommandTests(TestCase):
    def test_command_is_read_only_by_default_and_prints_no_contact_data(self):
        user = User.objects.create_user(username="cmd-user", email="cmd-secret@example.test", password="pw")
        MauticContactMapping.objects.create(user=user, mautic_contact_id="5")
        MauticEmailSuppression.objects.create(user=user, reason=R.UNSUBSCRIBED, mautic_contact_id="5",
                                              suppressed_at=timezone.now())
        out = StringIO()
        with patch.object(rec, "MauticClient", return_value=FakeMautic({"5": contact()})):
            call_command("reconcile_mautic_consent", "--json", stdout=out)
        report = json.loads(out.getvalue())

        self.assertEqual(report["summary"]["mode"], "read-only")
        self.assertEqual(report["findings"][0]["status"], rec.STALE_OPT_OUT)
        self.assertNotIn("cmd-secret", out.getvalue())
        self.assertTrue(MauticEmailSuppression.objects.filter(user=user).exists())

    def test_command_apply_flag(self):
        user = User.objects.create_user(username="cmd-apply", email="cmd-apply@example.test", password="pw")
        MauticContactMapping.objects.create(user=user, mautic_contact_id="6")
        MauticEmailSuppression.objects.create(user=user, reason=R.UNSUBSCRIBED, mautic_contact_id="6",
                                              suppressed_at=timezone.now())
        out = StringIO()
        with patch.object(rec, "MauticClient", return_value=FakeMautic({"6": contact()})):
            call_command("reconcile_mautic_consent", "--apply", stdout=out)
        self.assertIn("APPLY", out.getvalue())
        self.assertFalse(MauticEmailSuppression.objects.filter(user=user).exists())
