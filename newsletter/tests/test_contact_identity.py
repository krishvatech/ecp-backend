import json
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from newsletter import contact_identity as ci
from newsletter.mautic.exceptions import PermanentMauticError, TemporaryMauticError
from newsletter.models import MauticContactMapping, MauticEmailSuppression, MauticIdentityAuditLog

User = get_user_model()


def answer(contact_id, email):
    return {"id": contact_id, "fields": {"all": {"email": email}}, "doNotContact": []}


class FakeMautic:
    """get_contact answers from a script: a dict, an exception, a callable or a list (in turn)."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def get_contact(self, contact_id, *, timeout=None):
        self.calls.append(str(contact_id))
        value = self.answers[str(contact_id)]
        if isinstance(value, list):
            value = value.pop(0) if len(value) > 1 else value[0]
        if callable(value):
            value = value()
        if isinstance(value, Exception):
            raise value
        return value


class IdentityReconcilerTests(TestCase):
    def member(self, key, contact_id, *, suppressed=False):
        user = User.objects.create_user(username=f"ci-{key}", email=f"ci-{key}@example.test", password="pw")
        mapping = MauticContactMapping.objects.create(user=user, mautic_contact_id=str(contact_id))
        if suppressed:
            MauticEmailSuppression.objects.create(user=user, reason="unsubscribed", mautic_contact_id=str(contact_id),
                                                  suppressed_at=timezone.now())
        return user, mapping

    def run(self, answers, **kwargs):
        reconciler = ci.IdentityReconciler(client=FakeMautic(answers), **kwargs)
        summary = reconciler.run()
        return {f.user_id: f for f in reconciler.findings}, summary, reconciler.client

    def mapped(self, user):
        return MauticContactMapping.objects.get(user=user).mautic_contact_id

    def test_current_links_are_left_alone(self):
        user, _ = self.member("current", 10)
        findings, summary, _ = self.run({"10": answer(10, "ci-current@example.test")}, apply=True)
        self.assertEqual((findings[user.pk].status, findings[user.pk].action), (ci.CURRENT, ci.NONE))
        self.assertEqual(summary["outcomes"], {})

    def test_read_only_reports_a_merged_link_without_changing_it(self):
        user, _ = self.member("merged", 11)
        findings, summary, _ = self.run({"11": answer(511, "CI-Merged@example.test ")})
        self.assertEqual((findings[user.pk].status, findings[user.pk].action, findings[user.pk].survivor_contact_id),
                         (ci.MERGED, ci.REMAP, "511"))
        self.assertEqual(self.mapped(user), "11")
        self.assertEqual(summary["mode"], "read-only")

    def test_apply_repoints_a_verified_merge_and_audits_it(self):
        user, _ = self.member("apply", 12, suppressed=True)
        findings, summary, fake = self.run({"12": answer(512, "ci-apply@example.test")}, apply=True)

        self.assertEqual(findings[user.pk].outcome, "applied")
        self.assertEqual(self.mapped(user), "512")
        self.assertEqual(MauticEmailSuppression.objects.get(user=user).mautic_contact_id, "512")
        self.assertEqual(MauticEmailSuppression.objects.get(user=user).reason, "unsubscribed")
        self.assertEqual(fake.calls, ["12", "12"])  # re-read just before the change
        entry = MauticIdentityAuditLog.objects.get(action=ci.AUDIT_ACTION)
        self.assertEqual((entry.resource, entry.resource_id, entry.status), ("contact_mapping", "12->512", "succeeded"))

    def test_repeated_apply_is_idempotent(self):
        user, _ = self.member("again", 13)
        self.run({"13": answer(513, "ci-again@example.test")}, apply=True)
        findings, summary, _ = self.run({"513": answer(513, "ci-again@example.test")}, apply=True)
        self.assertEqual(findings[user.pk].status, ci.CURRENT)
        self.assertEqual(MauticIdentityAuditLog.objects.filter(action=ci.AUDIT_ACTION).count(), 1)

    def test_email_alone_is_not_proof_and_a_different_email_is_manual_review(self):
        user, _ = self.member("mismatch", 14)
        findings, _, _ = self.run({"14": answer(514, "someone-else@example.test")}, apply=True)
        self.assertEqual((findings[user.pk].status, findings[user.pk].action), (ci.EMAIL_MISMATCH, ci.MANUAL_REVIEW))
        self.assertEqual(self.mapped(user), "14")

    def test_survivor_linked_to_another_member_is_never_taken_over(self):
        user, _ = self.member("one", 15)
        other, _ = self.member("two", 515)
        findings, _, _ = self.run({"15": answer(515, "ci-one@example.test"), "515": answer(515, "ci-two@example.test")},
                                  apply=True)
        self.assertEqual((findings[user.pk].status, findings[user.pk].action),
                         (ci.SURVIVOR_LINKED_ELSEWHERE, ci.MANUAL_REVIEW))
        self.assertEqual((self.mapped(user), self.mapped(other)), ("15", "515"))

    def test_missing_contact_and_provider_errors_change_nothing(self):
        gone, _ = self.member("gone", 16)
        down, _ = self.member("down", 17)
        bad, _ = self.member("bad", 18)
        findings, _, _ = self.run({
            "16": PermanentMauticError("Mautic API request failed (HTTP 404)"),
            "17": TemporaryMauticError("timeout"),
            "18": PermanentMauticError("Mautic API request failed (HTTP 403)"),
        }, apply=True)
        self.assertEqual((findings[gone.pk].status, findings[gone.pk].action), (ci.CONTACT_NOT_FOUND, ci.MANUAL_REVIEW))
        self.assertEqual((findings[down.pk].status, findings[down.pk].action), (ci.PROVIDER_ERROR, ci.SKIP))
        self.assertEqual((findings[bad.pk].status, findings[bad.pk].action), (ci.PROVIDER_ERROR, ci.SKIP))
        self.assertEqual([self.mapped(u) for u in (gone, down, bad)], ["16", "17", "18"])

    def test_a_later_merge_between_reads_cancels_the_change(self):
        # Out of order / chained merges: the second read names a newer survivor.
        user, _ = self.member("chain", 19)
        findings, _, _ = self.run({"19": [answer(519, "ci-chain@example.test"), answer(619, "ci-chain@example.test")]},
                                  apply=True)
        self.assertEqual(findings[user.pk].outcome, "skipped_provider_changed")
        self.assertEqual(self.mapped(user), "19")

    def test_second_read_failure_cancels_the_change(self):
        user, _ = self.member("flaky", 20)
        findings, _, _ = self.run({"20": [answer(520, "ci-flaky@example.test"), TemporaryMauticError("timeout")]},
                                  apply=True)
        self.assertEqual(findings[user.pk].outcome, "skipped_provider_unavailable")
        self.assertEqual(self.mapped(user), "20")

    def test_concurrent_link_change_is_not_overwritten(self):
        user, mapping = self.member("race", 21)

        def relinked_meanwhile():
            MauticContactMapping.objects.filter(pk=mapping.pk).update(mautic_contact_id="777")
            return answer(521, "ci-race@example.test")

        findings, _, _ = self.run({"21": [answer(521, "ci-race@example.test"), relinked_meanwhile]}, apply=True)
        self.assertEqual(findings[user.pk].outcome, "skipped_concurrent_change")
        self.assertEqual(self.mapped(user), "777")

    def test_a_unique_constraint_race_is_reported_as_a_conflict(self):
        user, _ = self.member("unique", 22)
        with patch.object(ci.MauticContactMapping.objects, "filter", wraps=ci.MauticContactMapping.objects.filter) as spy:
            original = spy.side_effect

            def boom(*args, **kwargs):
                qs = original(*args, **kwargs)
                if kwargs.get("mautic_contact_id") == "22" and "pk" in kwargs:
                    class Raiser:
                        def update(self, **_):
                            raise IntegrityError("duplicate key")
                    return Raiser()
                return qs

            spy.side_effect = boom
            findings, _, _ = self.run({"22": answer(522, "ci-unique@example.test")}, apply=True)
        self.assertEqual((findings[user.pk].status, findings[user.pk].outcome), (ci.SURVIVOR_LINKED_ELSEWHERE, "skipped_conflict"))
        self.assertEqual(self.mapped(user), "22")

    def test_command_is_read_only_by_default_and_prints_ids_only(self):
        user, _ = self.member("cmd", 23)
        out = StringIO()
        with patch.object(ci, "MauticClient", return_value=FakeMautic({"23": answer(523, "ci-cmd@example.test")})):
            call_command("reconcile_mautic_contact_identities", "--json", stdout=out)
        report = json.loads(out.getvalue())
        self.assertEqual(report["summary"]["mode"], "read-only")
        self.assertEqual(report["findings"][0]["survivor_contact_id"], "523")
        self.assertNotIn("ci-cmd@", out.getvalue())
        self.assertEqual(self.mapped(user), "23")

    def test_command_apply(self):
        user, _ = self.member("cmdapply", 24)
        out = StringIO()
        with patch.object(ci, "MauticClient", return_value=FakeMautic({"24": answer(524, "ci-cmdapply@example.test")})):
            call_command("reconcile_mautic_contact_identities", "--apply", stdout=out)
        self.assertIn("APPLY", out.getvalue())
        self.assertEqual(self.mapped(user), "524")
