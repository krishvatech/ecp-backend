"""Replay-expiring reminder emails (scheduled_send_replay_expiring_alerts)."""
from datetime import datetime, timedelta, timezone as dt_timezone
from types import SimpleNamespace
from unittest import mock
from zoneinfo import ZoneInfo

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from django.utils.dateformat import format as date_format

from cms.models import EmailTemplate
from community.models import Community
from events.models import Event, EventRegistration
from events.tasks import (
    get_replay_expiration,
    scheduled_send_replay_expiring_alerts,
    send_replay_expiring_soon_task,
)
from users.models import UserProfile


class GetReplayExpirationTests(SimpleTestCase):
    def setUp(self):
        self.end = timezone.now()

    def expiry_days(self, duration):
        event = SimpleNamespace(replay_availability_duration=duration, end_time=self.end, live_ended_at=None)
        expiry = get_replay_expiration(event)
        return None if expiry is None else (expiry - self.end).days

    def test_every_form_option_and_bare_day_count(self):
        expected = {
            "7 Days": 7, "14 Days": 14, "30 Days": 30, "60 Days": 60, "90 Days": 90,
            "6 Months": 180, "1 Year": 365, "30": 30, "365": 365,
        }
        for duration, days in expected.items():
            with self.subTest(duration=duration):
                self.assertEqual(self.expiry_days(duration), days)

    def test_case_and_spacing_do_not_matter(self):
        self.assertEqual(self.expiry_days(" 14 days "), 14)
        self.assertEqual(self.expiry_days("1 month"), 30)

    def test_values_that_never_expire(self):
        for duration in ("Unlimited", "", None, "0", "0 Days", "2 Weeks", "soon"):
            with self.subTest(duration=duration):
                self.assertIsNone(self.expiry_days(duration))

    def test_huge_value_does_not_crash(self):
        self.assertIsNone(self.expiry_days("999999999999"))

    def test_falls_back_to_live_ended_at(self):
        event = SimpleNamespace(replay_availability_duration="7", end_time=None, live_ended_at=self.end)
        self.assertEqual(get_replay_expiration(event), self.end + timedelta(days=7))

    def test_no_end_date_means_no_expiry(self):
        event = SimpleNamespace(replay_availability_duration="7", end_time=None, live_ended_at=None)
        self.assertIsNone(get_replay_expiration(event))


class ScheduledReplayExpiringAlertTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.now = timezone.now()
        self.owner = User.objects.create_user(username="replay-owner", password="pass")
        self.member = User.objects.create_user(username="replay-member", email="member@example.com", first_name="Priya")
        self.community = Community.objects.create(name="Replay community", owner=self.owner)
        mail.outbox = []

    def event(self, title="Webinar", **kw):
        """An event whose 14-day replay expires one day from now, unless overridden."""
        defaults = dict(
            community=self.community, created_by=self.owner, format="virtual", status="published",
            start_time=self.now - timedelta(days=13, hours=1), end_time=self.now - timedelta(days=13),
            replay_available=True, replay_visible_to_participants=True,
            replay_availability_duration="14 Days", recording_url="https://example.com/recording.mp4",
        )
        defaults.update(kw)
        ev = Event(title=title, **defaults)
        ev.skip_saleor_sync = True
        ev.save()
        EventRegistration.objects.create(event=ev, user=self.member, status="registered")
        return ev

    def run_task(self):
        return scheduled_send_replay_expiring_alerts.apply().get()

    def test_text_duration_no_longer_crashes_and_sends_the_email(self):
        ev = self.event(title="M&A Masterclass")

        result = self.run_task()

        self.assertEqual(result, {"status": "ok", "events_processed": 1, "total_emails": 1})
        self.assertEqual([m.to for m in mail.outbox], [["member@example.com"]])
        self.assertIn("M&A Masterclass", mail.outbox[0].subject)
        ev.refresh_from_db()
        self.assertIsNotNone(ev.replay_expiring_notifications_sent_at)

    def test_every_run_returns_counts_even_with_nothing_to_do(self):
        self.assertEqual(self.run_task(), {"status": "ok", "events_processed": 0, "total_emails": 0})

    def test_event_that_ran_live_and_ended_is_included(self):
        self.event(status="ended")

        self.assertEqual(self.run_task()["total_emails"], 1)

    def test_events_outside_the_rule_send_nothing(self):
        cases = {
            "unlimited": dict(replay_availability_duration="Unlimited"),
            "blank duration": dict(replay_availability_duration=""),
            "already expired": dict(replay_availability_duration="30",
                                    start_time=self.now - timedelta(days=41), end_time=self.now - timedelta(days=40)),
            "more than 2 days away": dict(replay_availability_duration="365"),
            "no recording": dict(recording_url=""),
            "hidden from participants": dict(replay_visible_to_participants=False),
            "replay off": dict(replay_available=False),
            "draft": dict(status="draft"),
            "cancelled": dict(status="cancelled"),
            "already alerted": dict(replay_expiring_notifications_sent_at=self.now - timedelta(days=1)),
        }
        for name, overrides in cases.items():
            self.event(title=name, **overrides)

        self.assertEqual(self.run_task(), {"status": "ok", "events_processed": 0, "total_emails": 0})
        self.assertEqual(mail.outbox, [])

    def test_only_registered_people_get_it(self):
        ev = self.event()
        for status in ("cancelled", "cancellation_requested"):
            user = get_user_model().objects.create_user(username=f"replay-{status}", email=f"{status}@example.com")
            EventRegistration.objects.create(event=ev, user=user, status=status)
        mail.outbox = []

        self.run_task()

        self.assertCountEqual([m.to[0] for m in mail.outbox],
                              ["member@example.com", "cancellation_requested@example.com"])

    def set_profile_timezone(self, name):
        UserProfile.objects.update_or_create(user=self.member, defaults={"timezone": name})

    def assert_email_shows_expiry(self, event, timezone_name):
        expiry = get_replay_expiration(event).astimezone(ZoneInfo(timezone_name))
        body = mail.outbox[0].body
        self.assertIn(f'{date_format(expiry, "F j, Y")} at {date_format(expiry, "g:i A")}', body)

    def test_email_shows_the_real_expiry_in_the_recipients_timezone(self):
        ev = self.event(timezone="Asia/Tokyo")
        self.set_profile_timezone("America/New_York")

        self.run_task()

        self.assert_email_shows_expiry(ev, "America/New_York")

    def test_editable_database_template_also_uses_the_recipients_timezone(self):
        ev = self.event(timezone="Asia/Tokyo")
        self.set_profile_timezone("America/New_York")
        EmailTemplate.objects.update_or_create(template_key="replay_expiring_soon", defaults={
            "subject": "Replay for {{ event_title }}",
            "html_body": "<p>{{ expiration_date|date:'F j, Y' }}</p>",
            "text_body": "{{ expiration_date|date:'F j, Y' }} at {{ expiration_date|time:'g:i A' }}",
            "is_active": True,
        })

        self.run_task()

        self.assertEqual(mail.outbox[0].subject, "Replay for Webinar")
        self.assert_email_shows_expiry(ev, "America/New_York")

    def test_bad_timezone_on_profile_falls_back_to_the_event(self):
        ev = self.event(timezone="Europe/Berlin")
        self.set_profile_timezone("Not/AZone")

        self.run_task()

        self.assert_email_shows_expiry(ev, "Europe/Berlin")

    def test_user_without_a_profile_falls_back_to_the_event(self):
        ev = self.event(timezone="Asia/Tokyo")
        UserProfile.objects.filter(user=self.member).delete()

        self.run_task()

        self.assert_email_shows_expiry(ev, "Asia/Tokyo")

    def test_second_run_does_not_email_again(self):
        self.event()

        self.run_task()
        self.run_task()

        self.assertEqual(len(mail.outbox), 1)

    def test_event_is_claimed_before_the_first_email(self):
        ev = self.event()
        seen = []

        def record_marker(user, event, expiration_date):
            seen.append(Event.objects.get(pk=ev.pk).replay_expiring_notifications_sent_at)
            return True

        with mock.patch("users.email_utils.send_replay_expiring_soon_email", side_effect=record_marker):
            self.run_task()

        self.assertEqual(len(seen), 1)
        self.assertIsNotNone(seen[0])

    def test_send_killed_part_way_never_repeats_the_emails(self):
        self.event()

        with mock.patch("users.email_utils.send_replay_expiring_soon_email", side_effect=RuntimeError("killed")) as send:
            self.assertEqual(self.run_task()["total_emails"], 0)
            self.run_task()

        self.assertEqual(send.call_count, 1)

    def test_overlapping_run_that_read_the_event_early_is_skipped(self):
        ev = self.event()
        Event.objects.filter(pk=ev.pk).update(replay_expiring_notifications_sent_at=self.now)
        stale = Event.objects.filter(pk=ev.pk).first()
        stale.replay_expiring_notifications_sent_at = None

        with mock.patch("events.models.Event.objects.get", return_value=stale):
            result = send_replay_expiring_soon_task.apply(args=[ev.pk]).get()

        self.assertEqual(result, {"skipped": True, "reason": "already_sent"})
        self.assertEqual(mail.outbox, [])

    def test_one_failing_event_does_not_stop_the_others(self):
        self.event(title="First")
        self.event(title="Second")
        calls = []

        def apply(args):
            calls.append(args[0])
            if len(calls) == 1:
                raise RuntimeError("boom")
            return send_replay_expiring_soon_task.run(args[0]) and mock.Mock(
                successful=lambda: True, get=lambda: {"status": "ok", "emails_sent": 1})

        with mock.patch.object(send_replay_expiring_soon_task, "apply", side_effect=apply):
            result = self.run_task()

        self.assertEqual(len(calls), 2)
        self.assertEqual(result["events_processed"], 1)

    def test_events_shaped_like_production_only_alert_when_their_window_opens(self):
        """The 10 events production held on 2026-11-05: deploying the fix emailed nobody."""
        def end(month, day, hour, minute=0):
            return datetime(2026, month, day, hour, minute, tzinfo=dt_timezone.utc)

        rows = [
            ("399", "published", "14 Days", end(3, 26, 9)),
            ("515", "published", "365", end(5, 13, 16, 30)),
            ("547", "published", "365", end(5, 20, 15)),
            ("548", "ended", "365", end(5, 22, 14)),
            ("402", "published", "365", end(6, 1, 15)),
            ("703", "published", "Unlimited", end(6, 5, 15)),
            ("555", "published", "30", end(6, 10, 15)),
            ("556", "published", "30", end(6, 11, 15)),
            ("558", "published", "Unlimited", end(6, 12, 15)),
            ("559", "published", "Unlimited", end(6, 13, 15)),
        ]
        for title, status, duration, ended in rows:
            self.event(title=title, status=status, replay_availability_duration=duration,
                       start_time=ended - timedelta(hours=1), end_time=ended)

        on_deploy = datetime(2026, 11, 5, 12, 0, tzinfo=dt_timezone.utc)
        with mock.patch("events.tasks.timezone.now", return_value=on_deploy):
            self.assertEqual(self.run_task()["total_emails"], 0)
        self.assertEqual(mail.outbox, [])

        before_515_expires = datetime(2027, 5, 12, 12, 0, tzinfo=dt_timezone.utc)
        with mock.patch("events.tasks.timezone.now", return_value=before_515_expires):
            self.assertEqual(self.run_task()["total_emails"], 1)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("515", mail.outbox[0].subject)

    def test_task_may_run_longer_than_the_default_limit(self):
        self.assertGreaterEqual(scheduled_send_replay_expiring_alerts.time_limit, 60 * 60)
        self.assertGreaterEqual(scheduled_send_replay_expiring_alerts.soft_time_limit, 55 * 60)
