from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from community.models import Community
from groups.models import Group


User = get_user_model()


class GroupCreateSourceFieldTests(APITestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(
            username="group-create-admin",
            email="group-create-admin@example.com",
            password="pass1234",
        )
        self.community = Community.objects.create(
            name="Group Create Test Community",
            owner=self.admin,
        )
        self.client.force_authenticate(self.admin)

    def _payload(self, name):
        return {
            "name": name,
            "slug": name.lower().replace(" ", "-"),
            "description": "Local group creation test",
            "visibility": Group.VISIBILITY_PUBLIC,
            "join_policy": Group.JOIN_OPEN,
            "community_id": self.community.id,
        }

    def test_local_group_create_does_not_require_source_group_id(self):
        response = self.client.post(
            reverse("group-list"),
            self._payload("Local Group Without Source ID"),
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        group = Group.objects.get(pk=response.data["id"])
        self.assertEqual(group.source, Group.SOURCE_MANUAL)
        self.assertEqual(group.source_group_id, "")

    def test_client_cannot_mark_local_group_as_wordpress_owned(self):
        payload = self._payload("Attempted Source Spoof")
        payload.update({
            "source": Group.SOURCE_WORDPRESS,
            "source_group_id": "999999",
            "source_slug": "spoofed-source",
            "source_url": "https://example.test/groups/spoofed-source",
        })

        response = self.client.post(reverse("group-list"), payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        group = Group.objects.get(pk=response.data["id"])
        self.assertEqual(group.source, Group.SOURCE_MANUAL)
        self.assertEqual(group.source_group_id, "")
        self.assertEqual(group.source_slug, "")
        self.assertEqual(group.source_url, "")
