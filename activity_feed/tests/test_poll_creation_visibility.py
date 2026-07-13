from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from activity_feed.models import FeedItem, Poll
from activity_feed.views import FeedItemViewSet
from community.models import Community
from groups.models import Group


User = get_user_model()


class PollCreationVisibilityTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.owner = User.objects.create_user(
            username="poll-owner",
            email="poll-owner@example.com",
            password="test-password",
        )
        self.community = Community.objects.create(
            name="Poll Community",
            owner=self.owner,
        )
        self.group = Group.objects.create(
            name="Poll Group",
            slug="poll-group",
            description="Group used for poll tests",
            community=self.community,
            created_by=self.owner,
            owner=self.owner,
            forum_enabled=True,
        )

    def test_create_poll_returns_feed_item_and_does_not_duplicate_after_on_commit(self):
        request = self.factory.post(
            "/api/activity/feed/polls/create/",
            {
                "question": "Which option?",
                "options": ["One", "Two"],
                "group_id": self.group.id,
            },
            format="json",
        )
        force_authenticate(request, user=self.owner)

        with self.captureOnCommitCallbacks(execute=True):
            response = FeedItemViewSet.as_view({"post": "polls_create"})(request)

        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.data["feed_item_id"])

        poll = Poll.objects.get(question="Which option?")
        items = FeedItem.objects.filter(
            target_content_type=ContentType.objects.get_for_model(Poll),
            target_object_id=poll.id,
        )
        self.assertEqual(items.count(), 1)
        item = items.get()
        self.assertFalse(item.is_deleted)
        self.assertIs(item.metadata.get("is_deleted"), False)
        self.assertEqual(len(item.metadata.get("options") or []), 2)

    def test_feed_includes_legacy_active_item_without_metadata_delete_key(self):
        poll = Poll.objects.create(
            group=self.group,
            community=self.community,
            question="Legacy active poll",
            created_by=self.owner,
        )
        item = FeedItem.objects.create(
            community=self.community,
            group=self.group,
            actor=self.owner,
            verb="created_poll",
            target_content_type=ContentType.objects.get_for_model(Poll),
            target_object_id=poll.id,
            metadata={
                "type": "poll",
                "poll_id": poll.id,
                "question": poll.question,
                # Deliberately no metadata.is_deleted key.
            },
            is_deleted=False,
        )

        request = self.factory.get(
            "/api/activity/feed/",
            {"scope": "group", "group_id": self.group.id},
        )
        force_authenticate(request, user=self.owner)
        response = FeedItemViewSet.as_view({"get": "list"})(request)

        self.assertEqual(response.status_code, 200)
        rows = response.data.get("results", response.data)
        self.assertIn(item.id, [row["id"] for row in rows])
