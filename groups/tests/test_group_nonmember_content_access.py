from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITransactionTestCase

from community.models import Community
from groups.models import Group, GroupMembership


User = get_user_model()


class GroupNonMemberContentAccessTests(APITransactionTestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="content-owner",
            email="content-owner@example.com",
            password="pass1234",
        )
        self.member = User.objects.create_user(
            username="content-member",
            email="content-member@example.com",
            password="pass1234",
        )
        self.outsider = User.objects.create_user(
            username="content-outsider",
            email="content-outsider@example.com",
            password="pass1234",
        )
        self.community = Community.objects.create(
            name="Group Content Access Community",
            owner=self.owner,
        )
        self.group = Group.objects.create(
            name="Protected Group",
            slug="protected-group",
            community=self.community,
            owner=self.owner,
            created_by=self.owner,
            visibility=Group.VISIBILITY_PUBLIC,
            join_policy=Group.JOIN_OPEN,
        )
        GroupMembership.objects.create(
            group=self.group,
            user=self.member,
            role=GroupMembership.ROLE_MEMBER,
            status=GroupMembership.STATUS_ACTIVE,
        )

    def test_non_member_cannot_list_members(self):
        self.client.force_authenticate(self.outsider)
        response = self.client.get(f"/api/groups/{self.group.id}/members/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_non_member_cannot_list_posts(self):
        self.client.force_authenticate(self.outsider)
        response = self.client.get(f"/api/groups/{self.group.id}/posts/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_active_member_can_list_members(self):
        self.client.force_authenticate(self.member)
        response = self.client.get(f"/api/groups/{self.group.id}/members/")
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)

    def test_owner_can_list_members_and_posts(self):
        self.client.force_authenticate(self.owner)

        members_response = self.client.get(f"/api/groups/{self.group.id}/members/")
        self.assertEqual(members_response.status_code, status.HTTP_200_OK, members_response.data)

        posts_response = self.client.get(f"/api/groups/{self.group.id}/posts/")
        self.assertEqual(posts_response.status_code, status.HTTP_200_OK, posts_response.data)
