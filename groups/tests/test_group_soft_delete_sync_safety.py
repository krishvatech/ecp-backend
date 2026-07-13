from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from activity_feed.models import FeedItem, Poll, PollOption, PollVote
from community.models import Community
from groups.models import Group, GroupMembership, GroupNotification, WordPressGroupSource
from messaging.models import Conversation
from groups.wordpress_group_sync import sync_wordpress_source_to_connect_group


User = get_user_model()


class GroupSoftDeleteSyncSafetyTests(APITestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            username="group-admin",
            email="group-admin@example.com",
            password="pass1234",
            is_staff=True,
        )
        self.member = User.objects.create_user(
            username="group-member",
            email="group-member@example.com",
            password="pass1234",
        )
        self.community = Community.objects.create(
            name="Soft Delete Test Community",
            owner=self.admin,
        )
        self.client.force_authenticate(self.admin)

    def _create_group(self, name="Local Group", **kwargs):
        return Group.objects.create(
            name=name,
            slug=name.lower().replace(" ", "-"),
            community=self.community,
            owner=self.admin,
            created_by=self.admin,
            **kwargs,
        )

    def test_local_group_delete_preserves_history_and_primary_descendants(self):
        group = self._create_group()
        child = self._create_group(name="Local Child", parent=group)
        membership = GroupMembership.objects.create(
            group=group,
            user=self.member,
            status=GroupMembership.STATUS_ACTIVE,
            role=GroupMembership.ROLE_MEMBER,
        )
        child_membership = GroupMembership.objects.create(
            group=child,
            user=self.member,
            status=GroupMembership.STATUS_ACTIVE,
            role=GroupMembership.ROLE_MEMBER,
        )
        content_type = ContentType.objects.get_for_model(Group)
        feed_item = FeedItem.objects.create(
            community=self.community,
            group=group,
            actor=self.member,
            verb="posted",
            target_content_type=content_type,
            target_object_id=group.id,
            metadata={"type": "text", "text": "Retain me"},
        )
        poll = Poll.objects.create(
            community=self.community,
            group=group,
            question="Retain this poll?",
            created_by=self.member,
        )
        option = PollOption.objects.create(poll=poll, text="Yes", index=0)
        vote = PollVote.objects.create(poll=poll, option=option, user=self.admin)
        conversation = Conversation.objects.create(
            group=group,
            created_by=self.admin,
            title=group.name,
            room_key=f"group:{group.id}",
        )
        notification = GroupNotification.objects.create(
            recipient=self.admin,
            actor=self.member,
            group=group,
            kind=GroupNotification.KIND_MEMBER_JOINED,
            title="Member joined",
            description="Historical notification",
        )

        response = self.client.delete(
            reverse("group-detail", args=[group.id]),
            {"reason": "No longer needed on the platform."},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data["soft_deleted"])
        self.assertTrue(response.data["retained_in_database"])
        self.assertEqual(response.data["deleted_descendant_count"], 1)

        retained_group = Group.all_objects.get(pk=group.id)
        retained_child = Group.all_objects.get(pk=child.id)
        self.assertTrue(retained_group.is_deleted)
        self.assertTrue(retained_child.is_deleted)
        self.assertEqual(retained_group.deleted_by_id, self.admin.id)
        self.assertEqual(retained_group.deletion_reason, "No longer needed on the platform.")
        self.assertEqual(retained_child.deletion_batch_id, retained_group.deletion_batch_id)

        self.assertFalse(Group.objects.filter(pk=group.id).exists())
        self.assertFalse(Group.objects.filter(pk=child.id).exists())
        self.assertTrue(GroupMembership.objects.filter(pk=membership.id).exists())
        self.assertTrue(GroupMembership.objects.filter(pk=child_membership.id).exists())
        self.assertTrue(FeedItem.objects.filter(pk=feed_item.id).exists())
        self.assertTrue(Poll.objects.filter(pk=poll.id).exists())
        self.assertTrue(PollOption.objects.filter(pk=option.id).exists())
        self.assertTrue(PollVote.objects.filter(pk=vote.id).exists())
        self.assertTrue(Conversation.objects.filter(pk=conversation.id).exists())
        self.assertTrue(GroupNotification.objects.filter(pk=notification.id).exists())
        conversation.refresh_from_db()
        self.assertFalse(conversation.user_can_view(self.member))

        detail_response = self.client.get(reverse("group-detail", args=[group.id]))
        self.assertEqual(detail_response.status_code, status.HTTP_404_NOT_FOUND)

        joined_response = self.client.get(reverse("group-joined"))
        self.assertEqual(joined_response.status_code, status.HTTP_200_OK)
        payload = joined_response.data.get("results", joined_response.data)
        self.assertNotIn(group.id, [row["id"] for row in payload])

    def test_wordpress_owned_group_cannot_be_deleted_locally(self):
        group = self._create_group(
            name="WordPress Group",
            source=Group.SOURCE_WORDPRESS,
            source_group_id="775",
        )
        WordPressGroupSource.objects.create(
            wp_group_id=775,
            name="WordPress Group",
            slug="wordpress-group",
            status="public",
            sync_enabled=True,
            linked_group=group,
        )

        response = self.client.delete(
            reverse("group-detail", args=[group.id]),
            {"reason": "Attempt local delete"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.data["code"], "wordpress_group_source_controlled")
        group.refresh_from_db()
        self.assertFalse(group.is_deleted)

    def test_wordpress_sync_reuses_retained_deleted_row_without_duplicate(self):
        retained = Group.all_objects.create(
            name="Old Synced Group",
            slug="old-synced-group",
            community=self.community,
            owner=self.admin,
            created_by=self.admin,
            source=Group.SOURCE_WORDPRESS,
            source_group_id="991",
            is_deleted=True,
            deletion_source=Group.DELETION_SOURCE_WORDPRESS,
        )
        source = WordPressGroupSource.objects.create(
            wp_group_id=991,
            name="Updated Synced Group",
            slug="updated-synced-group",
            description="Updated from source",
            status="public",
            sync_enabled=True,
        )

        synced, created = sync_wordpress_source_to_connect_group(source, actor=self.admin)

        self.assertFalse(created)
        self.assertEqual(synced.id, retained.id)
        synced = Group.all_objects.get(pk=retained.id)
        self.assertTrue(synced.is_deleted)
        self.assertEqual(synced.name, "Updated Synced Group")
        self.assertEqual(
            Group.all_objects.filter(
                source=Group.SOURCE_WORDPRESS,
                source_group_id="991",
            ).count(),
            1,
        )
        source.refresh_from_db()
        self.assertEqual(source.linked_group_id, retained.id)
