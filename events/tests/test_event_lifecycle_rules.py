from datetime import timedelta
from types import SimpleNamespace

from django.test import SimpleTestCase
from django.utils import timezone

from events.lifecycle import (
    is_event_effectively_ended,
    is_post_event_lounge_open,
    is_replay_ready_for_signup,
)


class EventLifecycleRuleTests(SimpleTestCase):
    def make_event(self, **overrides):
        now = timezone.now()
        values = {
            "status": "published",
            "is_live": False,
            "end_time": now + timedelta(hours=1),
            "replay_enabled": False,
            "replay_visible_to_participants": False,
            "replay_video_url": "",
            "recording_url": "",
            "lounge_enabled_after": False,
            "lounge_after_buffer": 0,
            "live_ended_at": None,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_stale_published_event_is_ended_after_end_time(self):
        now = timezone.now()
        event = self.make_event(end_time=now - timedelta(minutes=1))
        self.assertTrue(is_event_effectively_ended(event, now=now))

    def test_future_event_is_not_ended(self):
        now = timezone.now()
        event = self.make_event(end_time=now + timedelta(minutes=1))
        self.assertFalse(is_event_effectively_ended(event, now=now))

    def test_active_live_event_can_run_overtime(self):
        now = timezone.now()
        event = self.make_event(
            status="live",
            is_live=True,
            end_time=now - timedelta(minutes=10),
        )
        self.assertFalse(is_event_effectively_ended(event, now=now))

    def test_stale_live_status_without_live_flag_is_ended(self):
        now = timezone.now()
        event = self.make_event(
            status="live",
            is_live=False,
            end_time=now - timedelta(minutes=10),
        )
        self.assertTrue(is_event_effectively_ended(event, now=now))

    def test_replay_signup_requires_visible_playable_media(self):
        now = timezone.now()
        event = self.make_event(
            end_time=now - timedelta(minutes=1),
            replay_enabled=True,
            replay_visible_to_participants=True,
            replay_video_url="https://example.com/replay",
        )
        self.assertTrue(is_replay_ready_for_signup(event, now=now))

        event.replay_video_url = ""
        event.recording_url = ""
        self.assertFalse(is_replay_ready_for_signup(event, now=now))

    def test_post_event_lounge_is_limited_to_its_buffer(self):
        now = timezone.now()
        event = self.make_event(
            lounge_enabled_after=True,
            lounge_after_buffer=30,
            live_ended_at=now - timedelta(minutes=10),
        )
        self.assertTrue(is_post_event_lounge_open(event, now=now))

        event.live_ended_at = now - timedelta(minutes=31)
        self.assertFalse(is_post_event_lounge_open(event, now=now))
