"""
Regression tests for anonymous exposure of group data.

Production verification found ``GET /api/groups/`` returning the owner's and
creator's email address on every group, and listing private groups, to callers
with no credentials. These tests pin the fixed behaviour:

- anonymous callers see public groups only, in both list and retrieve;
- anonymous and non-managing callers get no email address anywhere;
- people who manage the group (platform staff, owner/creator, group admin)
  keep the contact details their admin screens rely on.
"""

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITransactionTestCase

from community.models import Community
from groups.models import Group, GroupMembership


User = get_user_model()


def _emails_in(payload) -> list:
    """Every string that looks like an address anywhere in the payload."""
    found = []

    def walk(node):
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, str) and "@" in node and "." in node.split("@")[-1]:
            found.append(node)

    walk(payload)
    return found


class AnonymousGroupExposureTests(APITransactionTestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="exposure-owner",
            email="exposure-owner@example.com",
            password="pass1234",
            first_name="Olive",
            last_name="Owner",
        )
        self.outsider = User.objects.create_user(
            username="exposure-outsider",
            email="exposure-outsider@example.com",
            password="pass1234",
        )
        self.staff = User.objects.create_user(
            username="exposure-staff",
            email="exposure-staff@example.com",
            password="pass1234",
            is_staff=True,
        )
        self.community = Community.objects.create(
            name="Exposure Test Community",
            owner=self.owner,
        )
        self.public_group = Group.objects.create(
            name="Public Exposure Group",
            slug="public-exposure-group",
            community=self.community,
            owner=self.owner,
            created_by=self.owner,
            visibility=Group.VISIBILITY_PUBLIC,
        )
        self.private_group = Group.objects.create(
            name="Private Exposure Group",
            slug="private-exposure-group",
            community=self.community,
            owner=self.owner,
            created_by=self.owner,
            visibility=Group.VISIBILITY_PRIVATE,
        )

    # ---------------- visibility ----------------

    def test_anonymous_list_excludes_private_groups(self):
        resp = self.client.get("/api/groups/?page_size=100")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        body = resp.json()
        results = body["results"] if isinstance(body, dict) else body
        slugs = {row["slug"] for row in results}

        self.assertIn(self.public_group.slug, slugs)
        self.assertNotIn(self.private_group.slug, slugs)
        self.assertFalse([r for r in results if r.get("visibility") == "private"])

    def test_anonymous_retrieve_of_private_group_is_not_found(self):
        by_id = self.client.get(f"/api/groups/{self.private_group.pk}/")
        by_slug = self.client.get(f"/api/groups/{self.private_group.slug}/")

        self.assertIn(
            by_id.status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND),
        )
        self.assertIn(
            by_slug.status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND),
        )

    def test_anonymous_subgroups_excludes_private_children(self):
        child_public = Group.objects.create(
            name="Public Child",
            slug="public-child",
            community=self.community,
            owner=self.owner,
            created_by=self.owner,
            visibility=Group.VISIBILITY_PUBLIC,
            parent=self.public_group,
        )
        Group.objects.create(
            name="Private Child",
            slug="private-child",
            community=self.community,
            owner=self.owner,
            created_by=self.owner,
            visibility=Group.VISIBILITY_PRIVATE,
            parent=self.public_group,
        )

        resp = self.client.get(f"/api/groups/{self.public_group.pk}/subgroups/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        body = resp.json()
        results = body["results"] if isinstance(body, dict) else body
        slugs = {row["slug"] for row in results}

        self.assertEqual(slugs, {child_public.slug})

    # ---------------- contact details ----------------

    def test_anonymous_list_exposes_no_email_address(self):
        resp = self.client.get("/api/groups/?page_size=100")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        body = resp.json()
        results = body["results"] if isinstance(body, dict) else body
        row = next(r for r in results if r["slug"] == self.public_group.slug)

        self.assertNotIn("email", row["owner"])
        self.assertNotIn("email", row["created_by"])
        self.assertEqual(_emails_in(results), [])

    def test_anonymous_retrieve_exposes_no_email_address(self):
        resp = self.client.get(f"/api/groups/{self.public_group.pk}/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        body = resp.json()
        self.assertNotIn("email", body["owner"])
        self.assertNotIn("email", body["created_by"])
        self.assertEqual(_emails_in(body), [])

    def test_display_name_never_falls_back_to_the_email_address(self):
        """A user with no first/last name must not be labelled by their email."""
        nameless = User.objects.create_user(
            username="nameless-owner",
            email="nameless-owner@example.com",
            password="pass1234",
        )
        group = Group.objects.create(
            name="Nameless Owner Group",
            slug="nameless-owner-group",
            community=self.community,
            owner=nameless,
            created_by=nameless,
            visibility=Group.VISIBILITY_PUBLIC,
        )

        resp = self.client.get(f"/api/groups/{group.pk}/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        body = resp.json()
        self.assertEqual(body["owner"]["name"], nameless.username)
        self.assertEqual(_emails_in(body), [])

    def test_authenticated_outsider_gets_no_email_address(self):
        self.client.force_authenticate(user=self.outsider)

        resp = self.client.get(f"/api/groups/{self.public_group.pk}/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertNotIn("email", resp.json()["owner"])

    # ---------------- legitimate access is preserved ----------------

    def test_owner_still_receives_contact_details(self):
        self.client.force_authenticate(user=self.owner)

        resp = self.client.get(f"/api/groups/{self.public_group.pk}/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        body = resp.json()
        self.assertEqual(body["owner"]["email"], self.owner.email)
        self.assertEqual(body["created_by"]["email"], self.owner.email)

    def test_platform_staff_still_receives_contact_details(self):
        self.client.force_authenticate(user=self.staff)

        resp = self.client.get(f"/api/groups/{self.public_group.pk}/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.json()["owner"]["email"], self.owner.email)

    def test_group_admin_still_receives_contact_details(self):
        admin_member = User.objects.create_user(
            username="exposure-group-admin",
            email="exposure-group-admin@example.com",
            password="pass1234",
        )
        GroupMembership.objects.create(
            group=self.public_group,
            user=admin_member,
            role=GroupMembership.ROLE_ADMIN,
            status=GroupMembership.STATUS_ACTIVE,
        )
        self.client.force_authenticate(user=admin_member)

        resp = self.client.get(f"/api/groups/{self.public_group.pk}/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.json()["owner"]["email"], self.owner.email)

    def test_group_admin_receives_contact_details_in_the_list(self):
        """The list path reads a membership annotation rather than a per-row query."""
        admin_member = User.objects.create_user(
            username="exposure-list-admin",
            email="exposure-list-admin@example.com",
            password="pass1234",
        )
        GroupMembership.objects.create(
            group=self.public_group,
            user=admin_member,
            role=GroupMembership.ROLE_ADMIN,
            status=GroupMembership.STATUS_ACTIVE,
        )
        self.client.force_authenticate(user=admin_member)

        resp = self.client.get("/api/groups/?page_size=100")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        body = resp.json()
        results = body["results"] if isinstance(body, dict) else body
        managed = next(r for r in results if r["slug"] == self.public_group.slug)
        self.assertEqual(managed["owner"]["email"], self.owner.email)

    def test_plain_member_gets_no_contact_details_in_the_list(self):
        plain_member = User.objects.create_user(
            username="exposure-plain-member",
            email="exposure-plain-member@example.com",
            password="pass1234",
        )
        GroupMembership.objects.create(
            group=self.public_group,
            user=plain_member,
            role=GroupMembership.ROLE_MEMBER,
            status=GroupMembership.STATUS_ACTIVE,
        )
        self.client.force_authenticate(user=plain_member)

        resp = self.client.get("/api/groups/?page_size=100")
        body = resp.json()
        results = body["results"] if isinstance(body, dict) else body
        row = next(r for r in results if r["slug"] == self.public_group.slug)

        self.assertNotIn("email", row["owner"])
        self.assertNotIn("email", row["created_by"])

    def test_authenticated_member_still_sees_private_group(self):
        self.client.force_authenticate(user=self.owner)

        resp = self.client.get(f"/api/groups/{self.private_group.pk}/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.json()["slug"], self.private_group.slug)

    def test_public_group_landing_endpoint_still_works(self):
        self.public_group.public_landing_enabled = True
        self.public_group.save(update_fields=["public_landing_enabled"])

        resp = self.client.get(f"/api/groups/public/{self.public_group.slug}/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)

        body = resp.json()
        self.assertEqual(body["slug"], self.public_group.slug)
        self.assertEqual(_emails_in(body), [])
