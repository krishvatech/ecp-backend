"""1-hour "event starting soon" reminders (scheduled_send_event_starting_soon_reminders)."""
from datetime import datetime, timedelta, timezone as dt_timezone
from unittest import mock

from celery.exceptions import SoftTimeLimitExceeded
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase
from django.utils import timezone

from community.models import Community
from events.models import Event, EventRegistration
from events.tasks import (
    scheduled_send_event_starting_soon_reminders,
    send_event_starting_soon_task,
)


def run_in_worker(task):
    """Run a task the way a Celery worker does.

    A worker flags itself so that result.get() inside a task raises "Never call
    result.get() within a task!". Tests run outside a worker, which is how that
    error reached production unnoticed. Read .result here, as get() would raise too.
    """
    with mock.patch("celery.result.task_join_will_block", return_value=True):
        return task.apply().result


class EventStartingSoonReminderTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.now = timezone.now()
        self.owner = User.objects.create_user(username="soon-owner", password="pass")
        self.member = User.objects.create_user(username="soon-member", email="member@example.com", first_name="Priya")
        self.community = Community.objects.create(name="Reminder community", owner=self.owner)
        mail.outbox = []

    def event(self, title="M&A in Asia", **kw):
        """A published event starting 50 minutes from now, with one registered member."""
        defaults = dict(
            community=self.community, created_by=self.owner, format="virtual", status="published",
            start_time=self.now + timedelta(minutes=50), end_time=self.now + timedelta(hours=3),
        )
        defaults.update(kw)
        ev = Event(title=title, **defaults)
        ev.skip_saleor_sync = True
        ev.save()
        EventRegistration.objects.create(event=ev, user=self.member, status="registered")
        return ev

    def register(self, ev, count):
        emails = []
        for i in range(count):
            user = get_user_model().objects.create_user(username=f"soon-{ev.pk}-{i}", email=f"person{i + 1}@example.com")
            EventRegistration.objects.create(event=ev, user=user, status="registered")
            emails.append(user.email)
        return emails

    def run_task(self):
        return run_in_worker(scheduled_send_event_starting_soon_reminders)

    # Issue 1: the worker raised after the emails had gone, and reported 0 sent.

    def test_worker_run_reports_the_real_count_without_an_error(self):
        self.event()

        with self.assertNoLogs("events", level="ERROR"):
            result = self.run_task()

        self.assertEqual(result, {"status": "ok", "events_processed": 1, "total_emails": 1})
        self.assertEqual([m.to for m in mail.outbox], [["member@example.com"]])
        self.assertIn("M&A in Asia", mail.outbox[0].subject)

    def test_event_809_timeline_sends_one_reminder_an_hour_before(self):
        """Event 809 started at 01:00 UTC on 2026-11-10; the reminder went at 00:00."""
        start = datetime(2026, 11, 10, 1, 0, tzinfo=dt_timezone.utc)
        ev = self.event(start_time=start, end_time=start + timedelta(hours=9))
        others = self.register(ev, 2)

        def run_at(hour, minute, day=10):
            with mock.patch("events.tasks.timezone.now",
                            return_value=datetime(2026, 11, day, hour, minute, tzinfo=dt_timezone.utc)):
                return self.run_task()

        self.assertEqual(run_at(23, 55, day=9)["total_emails"], 0)
        self.assertEqual(run_at(0, 0), {"status": "ok", "events_processed": 1, "total_emails": 3})
        self.assertEqual(run_at(0, 5)["total_emails"], 0)
        self.assertCountEqual([m.to[0] for m in mail.outbox], ["member@example.com", *others])

    # Who gets it

    def test_events_outside_the_rule_send_nothing(self):
        cases = {
            "already started": dict(start_time=self.now - timedelta(minutes=10)),
            "two hours away": dict(start_time=self.now + timedelta(hours=2)),
            "draft": dict(status="draft"),
            "cancelled": dict(status="cancelled"),
            "already reminded": dict(starting_soon_notifications_sent_at=self.now - timedelta(minutes=5)),
        }
        for name, overrides in cases.items():
            self.event(title=name, **overrides)

        self.assertEqual(self.run_task(), {"status": "ok", "events_processed": 0, "total_emails": 0})
        self.assertEqual(mail.outbox, [])

    def test_only_registered_people_get_it(self):
        ev = self.event()
        for status in ("cancelled", "cancellation_requested"):
            user = get_user_model().objects.create_user(username=f"soon-{status}", email=f"{status}@example.com")
            EventRegistration.objects.create(event=ev, user=user, status=status)

        self.run_task()

        self.assertCountEqual([m.to[0] for m in mail.outbox],
                              ["member@example.com", "cancellation_requested@example.com"])

    def test_second_run_does_not_email_again(self):
        self.event()

        self.run_task()
        self.run_task()

        self.assertEqual(len(mail.outbox), 1)

    # Issue 2: a send cut off part way left the event unmarked, so every run resent it.

    def test_event_is_claimed_before_the_first_email(self):
        ev = self.event()
        seen = []

        def record_marker(user, event):
            seen.append(Event.objects.get(pk=ev.pk).starting_soon_notifications_sent_at)
            return True

        with mock.patch("users.email_utils.send_event_starting_soon_email", side_effect=record_marker):
            self.run_task()

        self.assertEqual(len(seen), 1)
        self.assertIsNotNone(seen[0])

    def test_big_send_cut_off_part_way_never_repeats_the_emails(self):
        """Time runs out on the 3rd of 5 emails, then the next two 5-minute runs come round."""
        ev = self.event()
        EventRegistration.objects.filter(event=ev).delete()
        self.register(ev, 5)
        received = []

        def send(user, event):
            if len(received) == 2 and not getattr(send, "stopped", False):
                send.stopped = True
                raise SoftTimeLimitExceeded()
            received.append(user.email)
            return True

        with mock.patch("users.email_utils.send_event_starting_soon_email", side_effect=send):
            self.assertEqual(self.run_task()["total_emails"], 0)
            self.run_task()
            self.run_task()

        self.assertEqual(len(received), len(set(received)), f"someone got the reminder twice: {received}")
        self.assertEqual(len(received), 2)

    def test_overlapping_run_that_read_the_event_early_is_skipped(self):
        ev = self.event()
        Event.objects.filter(pk=ev.pk).update(starting_soon_notifications_sent_at=self.now)
        stale = Event.objects.filter(pk=ev.pk).first()
        stale.starting_soon_notifications_sent_at = None

        with mock.patch("events.models.Event.objects.get", return_value=stale):
            result = send_event_starting_soon_task.apply(args=[ev.pk]).result

        self.assertEqual(result, {"skipped": True, "reason": "already_sent"})
        self.assertEqual(mail.outbox, [])

    def test_task_may_run_longer_than_the_default_limit(self):
        self.assertGreaterEqual(scheduled_send_event_starting_soon_reminders.time_limit, 60 * 60)
        self.assertGreaterEqual(scheduled_send_event_starting_soon_reminders.soft_time_limit, 55 * 60)
