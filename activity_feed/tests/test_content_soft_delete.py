from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from activity_feed.models import FeedItem, Poll, PollOption, PollVote
from activity_feed.views import FeedItemViewSet
from community.models import Community
from engagements.models import Comment, Reaction, Share
from engagements.views import CommentViewSet
from moderation.models import Report


User = get_user_model()


class ContentSoftDeleteTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.author = User.objects.create_user(
            username="content-author",
            email="content-author@example.com",
            password="test-password",
        )
        self.other_user = User.objects.create_user(
            username="content-reader",
            email="content-reader@example.com",
            password="test-password",
        )
        self.community = Community.objects.create(
            name="Soft Delete Community",
            owner=self.author,
        )

    def _create_feed_item(self, metadata=None):
        ct = ContentType.objects.get_for_model(Community)
        return FeedItem.objects.create(
            community=self.community,
            actor=self.author,
            verb="posted",
            target_content_type=ct,
            target_object_id=self.community.id,
            metadata=metadata or {"type": "text", "text": "Retained post"},
        )

    def test_post_soft_delete_preserves_engagements_and_reports(self):
        item = self._create_feed_item()
        feed_ct = ContentType.objects.get_for_model(FeedItem)

        comment = Comment.objects.create(
            content_type=feed_ct,
            object_id=item.id,
            user=self.other_user,
            text="Retained comment",
        )
        Reaction.objects.create(
            content_type=feed_ct,
            object_id=item.id,
            user=self.other_user,
            reaction=Reaction.LIKE,
        )
        share = Share.objects.create(
            content_type=feed_ct,
            object_id=item.id,
            user=self.author,
            to_user=self.other_user,
        )
        report = Report.objects.create(
            reporter=self.other_user,
            content_type=feed_ct,
            object_id=item.id,
            reason=Report.REASON_SPAM,
        )

        item.soft_delete(user=self.author, reason="Author removed this post")
        item.refresh_from_db()

        self.assertTrue(item.is_deleted)
        self.assertIsNotNone(item.deleted_at)
        self.assertEqual(item.deleted_by_id, self.author.id)
        self.assertEqual(item.deletion_reason, "Author removed this post")
        self.assertTrue(item.metadata.get("is_deleted"))
        self.assertTrue(Comment.objects.filter(pk=comment.id).exists())
        self.assertTrue(Reaction.objects.filter(object_id=item.id, content_type=feed_ct).exists())
        self.assertTrue(Share.objects.filter(pk=share.id).exists())
        self.assertTrue(Report.objects.filter(pk=report.id).exists())

        request = self.factory.get(f"/api/activity/feed/{item.id}/")
        force_authenticate(request, user=self.author)
        response = FeedItemViewSet.as_view({"get": "retrieve"})(request, pk=item.id)
        self.assertEqual(response.status_code, 404)

    def test_poll_delete_keeps_poll_options_votes_and_feed_item(self):
        poll = Poll.objects.create(
            community=self.community,
            question="Keep these votes?",
            created_by=self.author,
        )
        option = PollOption.objects.create(poll=poll, text="Yes", index=0)
        PollOption.objects.create(poll=poll, text="No", index=1)
        vote = PollVote.objects.create(
            poll=poll,
            option=option,
            user=self.other_user,
        )
        poll_ct = ContentType.objects.get_for_model(Poll)
        item = FeedItem.objects.create(
            community=self.community,
            actor=self.author,
            verb="created_poll",
            target_content_type=poll_ct,
            target_object_id=poll.id,
            metadata={"type": "poll", "poll_id": poll.id, "question": poll.question},
        )

        request = self.factory.delete(
            f"/api/activity/feed/polls/{poll.id}/delete/",
            {},
            format="json",
        )
        force_authenticate(request, user=self.author)
        response = FeedItemViewSet.as_view({"delete": "polls_delete"})(
            request,
            poll_id=str(poll.id),
        )

        self.assertEqual(response.status_code, 200)
        poll.refresh_from_db()
        item.refresh_from_db()
        self.assertTrue(poll.is_deleted)
        self.assertTrue(poll.is_closed)
        self.assertTrue(item.is_deleted)
        self.assertEqual(PollOption.objects.filter(poll=poll).count(), 2)
        self.assertTrue(PollVote.objects.filter(pk=vote.id).exists())
        self.assertIn("remains stored in the database", response.data["message"])

    def test_comment_delete_keeps_text_replies_reactions_and_reports(self):
        item = self._create_feed_item()
        feed_ct = ContentType.objects.get_for_model(FeedItem)
        comment = Comment.objects.create(
            content_type=feed_ct,
            object_id=item.id,
            user=self.author,
            text="Retained comment text",
        )
        reply = Comment.objects.create(
            content_type=feed_ct,
            object_id=item.id,
            user=self.other_user,
            parent=comment,
            text="Retained reply",
        )
        comment_ct = ContentType.objects.get_for_model(Comment)
        reaction = Reaction.objects.create(
            content_type=comment_ct,
            object_id=comment.id,
            user=self.other_user,
            reaction=Reaction.LIKE,
        )
        report = Report.objects.create(
            reporter=self.other_user,
            content_type=comment_ct,
            object_id=comment.id,
            reason=Report.REASON_OTHER,
        )

        request = self.factory.delete(
            f"/api/engagements/comments/{comment.id}/",
            {},
            format="json",
        )
        force_authenticate(request, user=self.author)
        response = CommentViewSet.as_view({"delete": "destroy"})(
            request,
            pk=str(comment.id),
        )

        self.assertEqual(response.status_code, 200)
        comment.refresh_from_db()
        self.assertTrue(comment.is_deleted)
        self.assertEqual(comment.text, "Retained comment text")
        self.assertTrue(Comment.objects.filter(pk=reply.id).exists())
        self.assertTrue(Reaction.objects.filter(pk=reaction.id).exists())
        self.assertTrue(Report.objects.filter(pk=report.id).exists())
        self.assertIn("remains stored in the database", response.data["message"])

        list_request = self.factory.get(
            "/api/engagements/comments/",
            {"target_id": item.id},
        )
        force_authenticate(list_request, user=self.author)
        list_response = CommentViewSet.as_view({"get": "list"})(list_request)
        self.assertEqual(list_response.status_code, 200)
        rows = list_response.data.get("results", list_response.data)
        self.assertNotIn(comment.id, [row["id"] for row in rows])
