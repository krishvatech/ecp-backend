"""Each person gets one reminder per meeting, with the real time left in it."""
from datetime import datetime, timedelta, timezone as dt_timezone
from unittest import mock

from celery.app.task import Task
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from community.models import Community
from events.models import (
    Event,
    EventNetworkingSettings,
    EventPlatform,
    EventPublication,
    EventRegistration,
    NetworkingMeeting,
    NetworkingTable,
)
from events.tasks import schedule_networking_meeting_reminders, send_networking_meeting_reminder_email

REMINDER_TASK = "send_networking_meeting_reminder_email"
START = datetime(2030, 3, 1, 10, 40, tzinfo=dt_timezone.utc)


class ReminderTestBase(TestCase):
    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create_user(username="reminder-owner", password="pass")
        community = Community.objects.create(name="Reminder community", owner=self.owner)
        self.platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect", defaults={"name": "IMAA Connect", "is_active": True},
        )
        self.event = self.make_event(community)
        self.settings = EventNetworkingSettings.objects.create(
            event=self.event, enabled=True, duration_options_minutes=[5, 10, 15], reminder_minutes_before=5,
        )
        self.requester_user = User.objects.create_user(
            username="reminder-a", email="a@example.com", first_name="Asha", last_name="Rao",
        )
        self.recipient_user = User.objects.create_user(
            username="reminder-b", email="b@example.com", first_name="Ben", last_name="Yates",
        )
        self.requester = EventRegistration.objects.create(event=self.event, user=self.requester_user, status="registered")
        self.recipient = EventRegistration.objects.create(event=self.event, user=self.recipient_user, status="registered")

        self.queued = []
        apply_async = mock.patch.object(Task, "apply_async", self.fake_apply_async(run_reminders=True))
        apply_async.start()
        self.addCleanup(apply_async.stop)

        send_email = mock.patch("users.email_utils.send_template_email", return_value=True)
        self.send_email = send_email.start()
        self.addCleanup(send_email.stop)

    def make_event(self, community, **extra):
        event = Event(
            title="Reminder summit", community=community, created_by=self.owner, format="in_person",
            status="published", start_time=START - timedelta(hours=2), end_time=START + timedelta(hours=8),
            timezone="UTC", **extra,
        )
        event.skip_saleor_sync = True
        event.save()
        EventPublication.objects.get_or_create(event=event, platform=self.platform, defaults={"is_enabled": True})
        return event

    def fake_apply_async(self, run_reminders):
        """Records every queued task. A reminder task with no delay runs straight away, as a worker would."""
        test = self

        def fake(task, args=None, kwargs=None, **options):
            test.queued.append((task.name, args, options))
            if run_reminders and task.name.endswith(REMINDER_TASK) and "eta" not in options:
                return task(*(args or ()))
            return None

        return fake

    def make_meeting(self, start=START, status="accepted"):
        return NetworkingMeeting.objects.create(
            event=self.event, requester=self.requester, recipient=self.recipient, duration_minutes=10,
            start_time=start, end_time=start + timedelta(minutes=10), status=status,
        )

    def run_scheduler_at(self, now):
        with mock.patch("django.utils.timezone.now", return_value=now):
            return schedule_networking_meeting_reminders()

    def run_every_minute(self, start, first_minute, last_minute, lag_seconds=0.0):
        """Runs the every-minute task from first_minute to last_minute before start. Negative means after it."""
        sent_at = {}
        for before in range(first_minute, last_minute - 1, -1):
            emails_before = self.send_email.call_count
            self.run_scheduler_at(start - timedelta(minutes=before) + timedelta(seconds=lag_seconds))
            if self.send_email.call_count > emails_before:
                sent_at[before] = self.send_email.call_count - emails_before
        return sent_at

    def send_at(self, meeting, now):
        with mock.patch("django.utils.timezone.now", return_value=now):
            return send_networking_meeting_reminder_email(meeting.id)

    def recipients(self):
        return sorted(call.kwargs["to_email"] for call in self.send_email.call_args_list)

    def minutes_shown(self):
        return {call.kwargs["context"]["reminder_minutes"] for call in self.send_email.call_args_list}


class ReminderTimingTests(ReminderTestBase):
    def test_one_email_each_when_the_worker_runs_exactly_on_the_minute(self):
        self.make_meeting()
        sent_at = self.run_every_minute(START, first_minute=8, last_minute=-3)
        self.assertEqual(sent_at, {5: 2})
        self.assertEqual(self.recipients(), ["a@example.com", "b@example.com"])
        self.assertEqual(self.minutes_shown(), {5})

    def test_one_email_each_when_the_worker_runs_slightly_late(self):
        self.make_meeting()
        sent_at = self.run_every_minute(START, first_minute=8, last_minute=-3, lag_seconds=1.5)
        self.assertEqual(sent_at, {5: 2})
        self.assertEqual(self.minutes_shown(), {5})

    def test_one_email_each_when_the_server_clock_is_slightly_early(self):
        self.make_meeting()
        sent_at = self.run_every_minute(START, first_minute=8, last_minute=-3, lag_seconds=-5)
        self.assertEqual(sent_at, {5: 2})
        self.assertEqual(self.minutes_shown(), {5})

    def test_the_reminder_setting_is_respected(self):
        EventNetworkingSettings.objects.filter(pk=self.settings.pk).update(reminder_minutes_before=15)
        self.make_meeting()
        sent_at = self.run_every_minute(START, first_minute=18, last_minute=-3, lag_seconds=1.5)
        self.assertEqual(sent_at, {15: 2})
        self.assertEqual(self.minutes_shown(), {15})

    def test_a_setting_of_zero_still_reminds_one_minute_before(self):
        EventNetworkingSettings.objects.filter(pk=self.settings.pk).update(reminder_minutes_before=0)
        self.make_meeting()
        sent_at = self.run_every_minute(START, first_minute=5, last_minute=-3)
        self.assertEqual(sent_at, {1: 2})
        self.assertEqual(self.minutes_shown(), {1})

    def test_a_meeting_accepted_late_gets_one_reminder_with_the_real_time_left(self):
        # Becomes accepted between the runs at 3 and 2 minutes before the start.
        meeting = self.make_meeting(status="pending")
        self.assertEqual(self.run_every_minute(START, first_minute=8, last_minute=3), {})
        NetworkingMeeting.objects.filter(pk=meeting.pk).update(status="accepted")
        sent_at = self.run_every_minute(START, first_minute=2, last_minute=-3, lag_seconds=1.5)
        self.assertEqual(sent_at, {2: 2})
        self.assertEqual(self.minutes_shown(), {2})


class ReminderDuplicateTests(ReminderTestBase):
    def test_two_tasks_for_the_same_meeting_send_once(self):
        meeting = self.make_meeting()
        now = START - timedelta(minutes=5)
        self.assertTrue(self.send_at(meeting, now))
        self.assertFalse(self.send_at(meeting, now))
        self.assertEqual(self.send_email.call_count, 2)

    def test_a_finished_reminder_queues_no_more_tasks(self):
        self.make_meeting()
        self.run_scheduler_at(START - timedelta(minutes=5))
        self.queued.clear()
        self.run_scheduler_at(START - timedelta(minutes=4))
        self.assertEqual(self.queued, [])

    def test_each_meeting_gets_its_own_reminder(self):
        self.make_meeting()
        self.make_meeting(start=START + timedelta(minutes=1))
        self.run_every_minute(START, first_minute=8, last_minute=-3)
        self.assertEqual(self.send_email.call_count, 4)

    def test_a_reminder_does_not_mark_the_meeting_as_updated(self):
        # My Meetings shows an unread badge when updated_at is newer than the last visit.
        meeting = self.make_meeting()
        updated_at = NetworkingMeeting.objects.get(pk=meeting.pk).updated_at
        self.send_at(meeting, START - timedelta(minutes=5))
        self.assertEqual(NetworkingMeeting.objects.get(pk=meeting.pk).updated_at, updated_at)


class ReminderRescheduleAndStaleTaskTests(ReminderTestBase):
    def test_a_rescheduled_meeting_gets_a_reminder_for_the_new_time(self):
        meeting = self.make_meeting()
        self.run_every_minute(START, first_minute=8, last_minute=3)
        self.assertEqual(self.send_email.call_count, 2)

        new_start = START + timedelta(hours=1)
        NetworkingMeeting.objects.filter(pk=meeting.pk).update(start_time=new_start, end_time=new_start + timedelta(minutes=10))
        self.send_email.reset_mock()
        self.assertEqual(self.run_every_minute(new_start, first_minute=8, last_minute=-3), {5: 2})

    def test_an_old_queued_task_does_nothing_after_a_reschedule(self):
        meeting = self.make_meeting()
        new_start = START + timedelta(hours=1)
        NetworkingMeeting.objects.filter(pk=meeting.pk).update(start_time=new_start, end_time=new_start + timedelta(minutes=10))
        self.assertFalse(self.send_at(meeting, START - timedelta(minutes=5)))
        self.send_email.assert_not_called()
        self.assertEqual(NetworkingMeeting.objects.get(pk=meeting.pk).reminder_task_id, "")

    def test_no_reminder_too_early_or_after_the_start(self):
        meeting = self.make_meeting()
        self.assertFalse(self.send_at(meeting, START - timedelta(minutes=6)))
        self.assertFalse(self.send_at(meeting, START))
        self.assertFalse(self.send_at(meeting, START + timedelta(minutes=1)))
        self.send_email.assert_not_called()

    def test_a_meeting_that_is_no_longer_accepted_is_not_reminded(self):
        for status in ("pending", "declined", "cancelled", "suggested", "expired"):
            meeting = self.make_meeting(status=status)
            self.assertFalse(self.send_at(meeting, START - timedelta(minutes=5)), status)
            self.assertEqual(NetworkingMeeting.objects.get(pk=meeting.pk).reminder_task_id, "", status)
        self.send_email.assert_not_called()

    def test_a_missing_email_address_sends_nothing_and_leaves_the_meeting_unmarked(self):
        meeting = self.make_meeting()
        get_user_model().objects.filter(pk=self.recipient_user.pk).update(email="")
        self.assertFalse(self.send_at(meeting, START - timedelta(minutes=5)))
        self.send_email.assert_not_called()
        self.assertEqual(NetworkingMeeting.objects.get(pk=meeting.pk).reminder_task_id, "")


class ReminderSchedulerQueryTests(ReminderTestBase):
    """Sentry ECP-BACKEND-7: the task ran two extra queries for every accepted meeting ever made."""

    def query_count(self, now):
        with CaptureQueriesContext(connection) as queries:
            self.run_scheduler_at(now)
        return len(queries)

    def test_query_count_does_not_grow_with_meetings(self):
        now = START - timedelta(hours=1)
        self.make_meeting(start=START + timedelta(hours=1))
        small = self.query_count(now)

        for hours in range(2, 8):
            self.make_meeting(start=START + timedelta(hours=hours))
        for hours in range(2, 8):
            self.make_meeting(start=START - timedelta(hours=hours))

        self.assertEqual(self.query_count(now), small)
        self.assertEqual(small, 1)
        self.assertEqual(self.queued, [])

    def test_past_meetings_are_never_reminded(self):
        self.make_meeting(start=START - timedelta(days=30))
        self.run_every_minute(START, first_minute=8, last_minute=-3)
        self.send_email.assert_not_called()

    def test_an_event_without_networking_settings_is_skipped(self):
        other_event = self.make_event(self.event.community)
        NetworkingMeeting.objects.create(
            event=other_event, requester=self.requester, recipient=self.recipient, duration_minutes=10,
            start_time=START, end_time=START + timedelta(minutes=10), status="accepted",
        )
        self.run_every_minute(START, first_minute=8, last_minute=-3)
        self.send_email.assert_not_called()


class ReminderAcceptTests(ReminderTestBase):
    def test_accepting_a_meeting_queues_no_separate_reminder(self):
        NetworkingTable.objects.create(event=self.event, table_number=1, name="Table 1", is_active=True)
        future = timezone.now() + timedelta(days=2)
        meeting = self.make_meeting(start=future, status="pending")
        client = APIClient()
        client.force_authenticate(self.recipient_user)

        with self.captureOnCommitCallbacks(execute=True):
            response = client.post(f"/api/networking-meetings/{meeting.id}/accept/", {}, format="json")

        self.assertEqual(response.status_code, 200, response.content[:300])
        self.assertEqual(NetworkingMeeting.objects.get(pk=meeting.pk).status, "accepted")
        self.assertTrue(any("accepted_email" in name for name, _args, _options in self.queued), self.queued)
        self.assertEqual([name for name, _args, _options in self.queued if name.endswith(REMINDER_TASK)], [])
