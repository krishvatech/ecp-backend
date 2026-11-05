"""Daily "Suggestion Digest" notification (friends.tasks)."""
from datetime import date, datetime, timedelta, timezone as dt_timezone
from unittest import mock
from zoneinfo import ZoneInfo

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from community.models import Community
from friends.models import Friendship, FriendRequest, Notification
from friends.tasks import (
    _local_day_bounds_utc,
    count_connection_suggestions,
    count_group_suggestions,
    dispatch_suggestion_digest_local_9am,
    send_suggestion_digest_for_timezone,
)
from groups.models import Group, GroupMembership
from users.models import UserProfile

User = get_user_model()
LOCMEM_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


def at_utc(year, month, day, hour, minute=0):
    return datetime(year, month, day, hour, minute, tzinfo=dt_timezone.utc)


def frozen_now(moment):
    return mock.patch("friends.tasks.timezone.now", return_value=moment)


class LocalDayBoundsTests(TestCase):
    def test_utc_timezone_from_the_sentry_error_no_longer_crashes(self):
        start, end = _local_day_bounds_utc(date(2026, 11, 5), ZoneInfo("UTC"))

        self.assertEqual(start, at_utc(2026, 11, 5, 0))
        self.assertEqual(end, at_utc(2026, 11, 6, 0))

    def test_bounds_follow_the_local_day(self):
        start, end = _local_day_bounds_utc(date(2026, 11, 5), ZoneInfo("Asia/Kolkata"))

        self.assertEqual(start, at_utc(2026, 11, 4, 18, 30))
        self.assertEqual(end, at_utc(2026, 11, 5, 18, 30))


@override_settings(CACHES=LOCMEM_CACHE)
class DigestTestCase(TestCase):
    def setUp(self):
        cache.clear()
        self.owner = self.user("digest-owner", tz="Europe/Oslo")
        self.community = Community.objects.create(name="Digest community", owner=self.owner)
        self.me = self.user("digest-me")

    def user(self, username, tz="Asia/Kolkata", is_active=True, profile_status=None):
        user = User.objects.create_user(username=username, email=f"{username}@example.com", is_active=is_active)
        values = {"timezone": tz}
        if profile_status:
            values["profile_status"] = profile_status
        UserProfile.objects.update_or_create(user=user, defaults=values)
        return user

    def befriend(self, a, b):
        return Friendship.objects.create(user1_id=min(a.id, b.id), user2_id=max(a.id, b.id))

    def group(self, slug, **kw):
        return Group.objects.create(name=slug, slug=slug, community=self.community,
                                    owner=self.owner, created_by=self.owner, **kw)

    def join(self, group, *users, status=GroupMembership.STATUS_ACTIVE):
        for user in users:
            GroupMembership.objects.create(group=group, user=user, status=status)

    def friends_of_me(self, *names):
        friends = [self.user(name) for name in names]
        for friend in friends:
            self.befriend(self.me, friend)
        return friends

    def candidate_with_mutuals(self, name, *mutuals, **kw):
        candidate = self.user(name, **kw)
        for friend in mutuals:
            self.befriend(candidate, friend)
        return candidate


class CountConnectionSuggestionsTests(DigestTestCase):
    def setUp(self):
        super().setUp()
        self.f1, self.f2 = self.friends_of_me("digest-f1", "digest-f2")

    def test_counts_someone_with_two_mutual_friends(self):
        self.candidate_with_mutuals("digest-two", self.f1, self.f2)

        self.assertEqual(count_connection_suggestions(self.me.id), 1)

    def test_one_mutual_friend_is_not_enough(self):
        self.candidate_with_mutuals("digest-one", self.f1)

        self.assertEqual(count_connection_suggestions(self.me.id), 0)

    def test_no_friends_means_no_suggestions(self):
        loner = self.user("digest-loner")

        self.assertEqual(count_connection_suggestions(loner.id), 0)

    def test_existing_friend_is_not_suggested(self):
        third = self.friends_of_me("digest-f3")[0]
        self.befriend(third, self.f1)
        self.befriend(third, self.f2)

        self.assertEqual(count_connection_suggestions(self.me.id), 0)

    def test_pending_request_in_either_direction_is_not_suggested(self):
        sent = self.candidate_with_mutuals("digest-sent", self.f1, self.f2)
        received = self.candidate_with_mutuals("digest-received", self.f1, self.f2)
        FriendRequest.objects.create(from_user=self.me, to_user=sent, status=FriendRequest.PENDING)
        FriendRequest.objects.create(from_user=received, to_user=self.me, status=FriendRequest.PENDING)

        self.assertEqual(count_connection_suggestions(self.me.id), 0)

    def test_profiles_hidden_on_the_suggestions_page_are_not_counted(self):
        for status in ("suspended", "fake", "deceased"):
            self.candidate_with_mutuals(f"digest-{status}", self.f1, self.f2, profile_status=status)

        self.assertEqual(count_connection_suggestions(self.me.id), 0)


class CountGroupSuggestionsTests(DigestTestCase):
    def setUp(self):
        super().setUp()
        self.f1, self.f2 = self.friends_of_me("digest-f1", "digest-f2")

    def test_counts_public_group_with_two_active_friends(self):
        self.join(self.group("digest-public"), self.f1, self.f2)

        self.assertEqual(count_group_suggestions(self.me.id), 1)

    def test_one_friend_is_not_enough(self):
        self.join(self.group("digest-one"), self.f1)

        self.assertEqual(count_group_suggestions(self.me.id), 0)

    def test_pending_friends_do_not_count(self):
        group = self.group("digest-pending")
        self.join(group, self.f1)
        self.join(group, self.f2, status=GroupMembership.STATUS_PENDING)

        self.assertEqual(count_group_suggestions(self.me.id), 0)

    def test_my_own_groups_are_not_suggested(self):
        group = self.group("digest-mine")
        self.join(group, self.f1, self.f2, self.me)

        self.assertEqual(count_group_suggestions(self.me.id), 0)

    def test_private_and_sub_groups_are_not_suggested(self):
        self.join(self.group("digest-private", visibility=Group.VISIBILITY_PRIVATE), self.f1, self.f2)
        parent = self.group("digest-parent")
        self.join(self.group("digest-child", parent=parent), self.f1, self.f2)

        self.assertEqual(count_group_suggestions(self.me.id), 0)


class SendSuggestionDigestForTimezoneTests(DigestTestCase):
    def setUp(self):
        super().setUp()
        self.f1, self.f2 = self.friends_of_me("digest-f1", "digest-f2")
        self.candidate_with_mutuals("digest-candidate", self.f1, self.f2)
        self.join(self.group("digest-public"), self.f1, self.f2)

    def digests(self, user=None):
        return Notification.objects.filter(recipient=user or self.me, kind="suggestion_digest")

    def test_creates_the_daily_suggestions_notification(self):
        with frozen_now(at_utc(2026, 11, 5, 3, 30)):
            result = send_suggestion_digest_for_timezone("Asia/Kolkata")

        note = self.digests().get()
        self.assertEqual(note.title, "Daily suggestions")
        self.assertEqual(note.description,
                         "1 new connection suggestions - 1 groups your friends are active in today")
        self.assertEqual(note.state, "info")
        self.assertIsNone(note.actor)
        self.assertFalse(note.is_read)
        self.assertEqual(note.data["connection_count"], 1)
        self.assertEqual(note.data["group_count"], 1)
        self.assertEqual(note.data["date"], "2026-11-05")
        self.assertEqual(note.data["timezone"], "Asia/Kolkata")
        self.assertEqual(result["date"], "2026-11-05")
        self.assertGreaterEqual(result["created"], 1)

    def test_people_with_nothing_to_suggest_get_nothing(self):
        loner = self.user("digest-loner")

        result = send_suggestion_digest_for_timezone("Asia/Kolkata")

        self.assertEqual(self.digests(loner).count(), 0)
        self.assertGreaterEqual(result["skipped_empty"], 1)

    def test_only_people_in_that_timezone_are_processed(self):
        send_suggestion_digest_for_timezone("Europe/London")

        self.assertEqual(self.digests().count(), 0)

    def test_inactive_user_gets_nothing(self):
        User.objects.filter(pk=self.me.pk).update(is_active=False)

        send_suggestion_digest_for_timezone("Asia/Kolkata")

        self.assertEqual(self.digests().count(), 0)

    def test_running_twice_the_same_day_does_not_notify_twice(self):
        moment = at_utc(2026, 11, 5, 3, 30)
        with frozen_now(moment):
            send_suggestion_digest_for_timezone("Asia/Kolkata")
        with frozen_now(moment + timedelta(minutes=5)):
            result = send_suggestion_digest_for_timezone("Asia/Kolkata")

        self.assertEqual(self.digests().count(), 1)
        self.assertEqual(result["created"], 0)
        self.assertGreaterEqual(result["skipped_locked"], 1)

    def test_lost_cache_still_does_not_notify_twice(self):
        Notification.objects.create(recipient=self.me, kind="suggestion_digest", title="Daily suggestions")

        cache.clear()
        result = send_suggestion_digest_for_timezone("Asia/Kolkata")

        self.assertEqual(self.digests().count(), 1)
        self.assertGreaterEqual(result["skipped_already_sent"], 1)

    def test_next_day_gets_a_new_notification(self):
        first = at_utc(2026, 11, 5, 3, 30)
        with frozen_now(first):
            send_suggestion_digest_for_timezone("Asia/Kolkata")
        self.digests().update(created_at=first)

        with frozen_now(first + timedelta(days=1)):
            send_suggestion_digest_for_timezone("Asia/Kolkata")

        self.assertEqual(self.digests().count(), 2)

    def test_notification_api_returns_it_with_no_actor(self):
        send_suggestion_digest_for_timezone("Asia/Kolkata")
        client = APIClient()
        client.force_authenticate(self.me)

        response = client.get(reverse("notifications-list"), {"kind": "suggestion_digest"})

        self.assertEqual(response.status_code, 200)
        row = response.json()["results"][0]
        self.assertIsNone(row["actor"])
        self.assertEqual(row["data"]["connection_count"], 1)
        self.assertEqual(row["data"]["group_count"], 1)


class DispatchSuggestionDigestTests(DigestTestCase):
    def dispatched_at(self, moment):
        with frozen_now(moment), mock.patch.object(send_suggestion_digest_for_timezone, "delay") as delay:
            result = dispatch_suggestion_digest_local_9am()
        return {call.args[0] for call in delay.call_args_list}, result

    def test_queues_only_timezones_where_it_is_nine_am(self):
        self.user("digest-utc", tz="UTC")
        self.user("digest-london", tz="Europe/London")
        self.user("digest-berlin", tz="Europe/Berlin")

        due, result = self.dispatched_at(at_utc(2026, 11, 5, 9))

        self.assertEqual(due, {"UTC", "Europe/London"})
        self.assertEqual(result["dispatched"], 2)

    def test_half_hour_timezone_is_due_on_the_half_hour(self):
        due, _ = self.dispatched_at(at_utc(2026, 11, 5, 3, 30))

        self.assertEqual(due, {"Asia/Kolkata"})

    def test_next_five_minute_tick_does_not_queue_it_again(self):
        due, result = self.dispatched_at(at_utc(2026, 11, 5, 3, 35))

        self.assertEqual(due, set())
        self.assertEqual(result["dispatched"], 0)

    def test_blank_and_unknown_timezones_do_not_stop_the_run(self):
        self.user("digest-blank", tz="")
        self.user("digest-unknown", tz="Not/AZone")

        with override_settings(TIME_ZONE="Asia/Kolkata"):
            due, result = self.dispatched_at(at_utc(2026, 11, 5, 3, 30))

        self.assertEqual(due, {"Asia/Kolkata", "Not/AZone"})
        self.assertIn("", result["invalid_timezones"])

    def test_dispatcher_and_task_run_end_to_end(self):
        f1, f2 = self.friends_of_me("digest-f1", "digest-f2")
        self.candidate_with_mutuals("digest-candidate", f1, f2)

        with frozen_now(at_utc(2026, 11, 5, 3, 30)), mock.patch.object(
            send_suggestion_digest_for_timezone, "delay", side_effect=send_suggestion_digest_for_timezone
        ):
            dispatch_suggestion_digest_local_9am()

        self.assertEqual(Notification.objects.filter(recipient=self.me, kind="suggestion_digest").count(), 1)


class SuggestionDigestScheduleTests(TestCase):
    def test_beat_runs_the_dispatcher_every_five_minutes(self):
        entry = settings.CELERY_BEAT_SCHEDULE["dispatch_suggestion_digest_local_9am"]

        self.assertEqual(entry["task"], dispatch_suggestion_digest_local_9am.name)
        self.assertEqual(entry["schedule"].minute, set(range(0, 60, 5)))
