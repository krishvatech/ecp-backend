from datetime import timedelta

from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from activity_feed.models import FeedItem
from community.models import Community
from content.models import Resource
from content.tasks import publish_due_resources_task
from events.models import Event


class ResourceSoftDeleteTests(APITestCase):
    def setUp(self):
        from django.contrib.auth.models import Group
        self.owner = User.objects.create_user(
            username="resource-owner",
            email="resource-owner@example.com",
            password="test-pass-123",
            is_staff=True,
            is_superuser=True,
        )
        platform_admin_group, _ = Group.objects.get_or_create(name='platform_admin')
        self.owner.groups.add(platform_admin_group)
        self.community = Community.objects.create(
            name="Resource Test Community",
            owner=self.owner,
        )
        self.client.force_authenticate(self.owner)

    def _create_resource(self, **overrides):
        values = {
            "community": self.community,
            "title": "Retained resource",
            "description": "Must remain stored",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com/resource",
            "is_published": True,
            "uploaded_by": self.owner,
        }
        values.update(overrides)
        return Resource.all_objects.create(**values)

    def test_delete_soft_deletes_resource_and_retains_feed_history(self):
        resource = self._create_resource()
        content_type = ContentType.objects.get_for_model(Resource)
        feed_item = FeedItem.objects.create(
            verb="uploaded_resource",
            target_content_type=content_type,
            target_object_id=resource.id,
            community=self.community,
            actor=self.owner,
            metadata={"title": resource.title},
        )

        response = self.client.delete(
            f"/api/content/resources/{resource.id}/",
            {"reason": "Outdated material"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        retained = Resource.all_objects.get(pk=resource.pk)
        self.assertTrue(retained.is_deleted)
        self.assertFalse(retained.is_published)
        self.assertEqual(retained.deleted_by_id, self.owner.id)
        self.assertEqual(retained.deletion_reason, "Outdated material")
        self.assertEqual(retained.link_url, "https://example.com/resource")
        self.assertFalse(Resource.objects.filter(pk=resource.pk).exists())

        feed_item.refresh_from_db()
        self.assertTrue(feed_item.is_deleted)
        self.assertEqual(feed_item.target_object_id, resource.id)

        detail = self.client.get(f"/api/content/resources/{resource.id}/")
        self.assertEqual(detail.status_code, status.HTTP_404_NOT_FOUND)

    def test_scheduled_publisher_cannot_republish_soft_deleted_resource(self):
        resource = self._create_resource(
            is_published=False,
            is_deleted=True,
            deleted_at=timezone.now(),
            publish_at=timezone.now() - timedelta(minutes=5),
        )

        published_count = publish_due_resources_task()

        self.assertEqual(published_count, 0)
        resource.refresh_from_db()
        self.assertFalse(resource.is_published)
        self.assertTrue(resource.is_deleted)

    def test_resource_for_soft_deleted_event_is_not_exposed(self):
        event = Event.objects.create(
            community=self.community,
            title="Deleted event",
            status="archived",
        )
        resource = self._create_resource(event=event)

        response = self.client.get("/api/content/resources/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        payload = response.data.get("results", response.data)
        self.assertNotIn(resource.id, [item["id"] for item in payload])

    def test_admin_restore_keeps_resource_unpublished(self):
        resource = self._create_resource()
        resource.soft_delete(user=self.owner, reason="Temporary removal")

        self.assertTrue(resource.restore())
        resource.refresh_from_db()
        self.assertFalse(resource.is_deleted)
        self.assertFalse(resource.is_published)
        self.assertIsNone(resource.deleted_at)
        self.assertEqual(resource.deletion_reason, "")
