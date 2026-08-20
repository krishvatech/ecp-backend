from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITransactionTestCase

from community.models import Community
from groups.models import Group, GroupMembership


User = get_user_model()


class PublicGroupLandingTests(APITransactionTestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="landing-owner",
            email="landing-owner@example.com",
            password="pass1234",
        )
        self.active_member = User.objects.create_user(
            username="landing-active-member",
            email="landing-active@example.com",
            password="pass1234",
        )
        self.inactive_member = User.objects.create_user(
            username="landing-inactive-member",
            email="landing-inactive@example.com",
            password="pass1234",
        )
        self.community = Community.objects.create(
            name="Public Landing Test Community",
            owner=self.owner,
        )

    def _group(self, **overrides):
        values = {
            "name": "IT in M&A",
            "slug": "it-in-ma",
            "description": "IT challenges around Mergers & Acquisitions.",
            "community": self.community,
            "owner": self.owner,
            "created_by": self.owner,
            "visibility": Group.VISIBILITY_PUBLIC,
            "join_policy": Group.JOIN_OPEN,
            "public_landing_enabled": True,
        }
        values.update(overrides)
        return Group.objects.create(**values)

    def test_anonymous_user_can_view_enabled_public_landing_page(self):
        group = self._group()
        GroupMembership.objects.create(
            group=group,
            user=self.active_member,
            status=GroupMembership.STATUS_ACTIVE,
        )
        GroupMembership.objects.create(
            group=group,
            user=self.inactive_member,
            status=GroupMembership.STATUS_LEFT,
        )

        response = self.client.get(
            reverse("public-group-landing", kwargs={"slug": group.slug})
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertEqual(response.data["name"], "IT in M&A")
        self.assertEqual(response.data["member_count"], 2)
        self.assertEqual(
            set(response.data.keys()),
            {
                "id",
                "name",
                "slug",
                "description",
                "visibility",
                "join_policy",
                "cover_image",
                "logo",
                "member_count",
            },
        )

    def test_disabled_landing_page_is_not_public(self):
        group = self._group(public_landing_enabled=False)

        response = self.client.get(
            reverse("public-group-landing", kwargs={"slug": group.slug})
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_private_group_is_not_exposed_even_when_flag_is_enabled(self):
        group = self._group(
            visibility=Group.VISIBILITY_PRIVATE,
            join_policy=Group.JOIN_INVITE,
        )

        response = self.client.get(
            reverse("public-group-landing", kwargs={"slug": group.slug})
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
