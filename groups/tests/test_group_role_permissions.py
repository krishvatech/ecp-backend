"""Group-level admin/moderator permissions.

These cover the split between the two independent privilege axes:

  * ``user.is_staff``          -> Django admin / platform-wide management
  * ``GroupMembership.role``   -> permissions scoped to a single group

A normal (non-staff) user holding ``role=moderator`` must be able to moderate
the group they were assigned to, and nothing else.
"""

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITransactionTestCase

from community.models import Community
from groups.models import Group, GroupMembership


User = get_user_model()


class GroupRolePermissionTests(APITransactionTestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="role-owner", email="role-owner@example.com", password="pass1234"
        )
        self.staff = User.objects.create_user(
            username="role-staff", email="role-staff@example.com", password="pass1234",
            is_staff=True,
        )
        # Deliberately non-staff: this is the case the old code rejected.
        self.moderator = User.objects.create_user(
            username="role-mod", email="role-mod@example.com", password="pass1234"
        )
        self.group_admin = User.objects.create_user(
            username="role-admin", email="role-admin@example.com", password="pass1234"
        )
        self.member = User.objects.create_user(
            username="role-member", email="role-member@example.com", password="pass1234"
        )

        self.community = Community.objects.create(
            name="Role Permission Community", owner=self.owner
        )
        self.group = Group.objects.create(
            name="Python Community",
            slug="python-community",
            community=self.community,
            owner=self.owner,
            created_by=self.owner,
        )
        # A second group the moderator has nothing to do with.
        self.other_group = Group.objects.create(
            name="Rust Community",
            slug="rust-community",
            community=self.community,
            owner=self.owner,
            created_by=self.owner,
        )

        for user, role in (
            (self.moderator, GroupMembership.ROLE_MODERATOR),
            (self.group_admin, GroupMembership.ROLE_ADMIN),
            (self.member, GroupMembership.ROLE_MEMBER),
        ):
            GroupMembership.objects.create(
                group=self.group,
                user=user,
                role=role,
                status=GroupMembership.STATUS_ACTIVE,
            )
        GroupMembership.objects.create(
            group=self.other_group,
            user=self.moderator,
            role=GroupMembership.ROLE_MEMBER,
            status=GroupMembership.STATUS_ACTIVE,
        )

    def _can_i(self, user, group):
        self.client.force_authenticate(user)
        response = self.client.get(f"/api/groups/{group.id}/moderator/can-i/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.data

    # --- 1. Normal member cannot moderate ---------------------------------
    def test_plain_member_cannot_moderate(self):
        data = self._can_i(self.member, self.group)
        self.assertFalse(data["can_moderate_content"])
        self.assertFalse(data["permissions"]["can_moderate_posts"])
        self.assertFalse(data["permissions"]["can_manage_members"])

    # --- 2. Non-staff moderator can moderate its own group ----------------
    def test_non_staff_moderator_can_moderate_assigned_group(self):
        self.assertFalse(self.moderator.is_staff)
        data = self._can_i(self.moderator, self.group)
        self.assertTrue(data["is_moderator"])
        self.assertTrue(data["can_moderate_content"])
        self.assertTrue(data["can_delete_post"])
        self.assertTrue(data["can_hide_post"])
        # Moderation only — no member management.
        self.assertFalse(data["permissions"]["can_manage_members"])

    # --- 3. Moderator rights do not leak to another group -----------------
    def test_moderator_cannot_moderate_another_group(self):
        data = self._can_i(self.moderator, self.other_group)
        self.assertFalse(data["is_moderator"])
        self.assertFalse(data["can_moderate_content"])

    def test_moderator_cannot_set_roles_in_own_group(self):
        self.client.force_authenticate(self.moderator)
        response = self.client.post(
            f"/api/groups/{self.group.id}/set-role/",
            {"user_id": self.member.id, "role": "moderator"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # --- Join requests: moderators may look, not decide -------------------
    def test_moderator_can_view_join_requests(self):
        joiner = User.objects.create_user(
            username="role-joiner", email="role-joiner@example.com", password="pass1234"
        )
        GroupMembership.objects.create(
            group=self.group,
            user=joiner,
            role=GroupMembership.ROLE_MEMBER,
            status=GroupMembership.STATUS_PENDING,
        )
        self.client.force_authenticate(self.moderator)
        response = self.client.get(f"/api/groups/{self.group.id}/member-requests/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 1)

    def _pending_joiner(self, username):
        joiner = User.objects.create_user(
            username=username, email=f"{username}@example.com", password="pass1234"
        )
        GroupMembership.objects.create(
            group=self.group,
            user=joiner,
            role=GroupMembership.ROLE_MEMBER,
            status=GroupMembership.STATUS_PENDING,
        )
        return joiner

    def test_non_staff_moderator_can_approve_join_request(self):
        """Reviewing who joins is moderation, so moderators can act on it."""
        joiner = self._pending_joiner("role-joiner2")
        self.client.force_authenticate(self.moderator)
        response = self.client.post(
            f"/api/groups/{self.group.id}/member-requests/approve/{joiner.id}/"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        membership = GroupMembership.objects.get(group=self.group, user=joiner)
        self.assertEqual(membership.status, GroupMembership.STATUS_ACTIVE)

    def test_non_staff_moderator_can_reject_join_request(self):
        joiner = self._pending_joiner("role-joiner4")
        self.client.force_authenticate(self.moderator)
        response = self.client.post(
            f"/api/groups/{self.group.id}/member-requests/reject/{joiner.id}/"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        membership = GroupMembership.objects.get(group=self.group, user=joiner)
        self.assertEqual(membership.status, GroupMembership.STATUS_REJECTED)

    def test_plain_member_cannot_review_join_requests(self):
        joiner = self._pending_joiner("role-joiner5")
        self.client.force_authenticate(self.member)
        response = self.client.post(
            f"/api/groups/{self.group.id}/member-requests/approve/{joiner.id}/"
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        membership = GroupMembership.objects.get(group=self.group, user=joiner)
        self.assertEqual(membership.status, GroupMembership.STATUS_PENDING)

    def test_moderator_cannot_review_join_requests_of_another_group(self):
        joiner = User.objects.create_user(
            username="role-joiner6", email="role-joiner6@example.com", password="pass1234"
        )
        GroupMembership.objects.create(
            group=self.other_group,
            user=joiner,
            role=GroupMembership.ROLE_MEMBER,
            status=GroupMembership.STATUS_PENDING,
        )
        self.client.force_authenticate(self.moderator)
        response = self.client.post(
            f"/api/groups/{self.other_group.id}/member-requests/approve/{joiner.id}/"
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_group_admin_can_approve_join_request(self):
        joiner = self._pending_joiner("role-joiner3")
        self.client.force_authenticate(self.group_admin)
        response = self.client.post(
            f"/api/groups/{self.group.id}/member-requests/approve/{joiner.id}/"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        membership = GroupMembership.objects.get(group=self.group, user=joiner)
        self.assertEqual(membership.status, GroupMembership.STATUS_ACTIVE)

    # --- 4. Group admin can manage members --------------------------------
    def test_group_admin_can_promote_member_to_moderator(self):
        self.assertFalse(self.group_admin.is_staff)
        self.client.force_authenticate(self.group_admin)
        response = self.client.patch(
            f"/api/groups/{self.group.id}/members/{self.member.id}/role/",
            {"role": "moderator"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.member.refresh_from_db()
        membership = GroupMembership.objects.get(group=self.group, user=self.member)
        self.assertEqual(membership.role, GroupMembership.ROLE_MODERATOR)

    def test_group_admin_can_demote_moderator(self):
        self.client.force_authenticate(self.group_admin)
        response = self.client.patch(
            f"/api/groups/{self.group.id}/members/{self.moderator.id}/role/",
            {"role": "member"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        membership = GroupMembership.objects.get(group=self.group, user=self.moderator)
        self.assertEqual(membership.role, GroupMembership.ROLE_MEMBER)

    def test_group_admin_cannot_mint_another_admin(self):
        """Handing out the admin role stays with the owner / platform staff."""
        self.client.force_authenticate(self.group_admin)
        response = self.client.patch(
            f"/api/groups/{self.group.id}/members/{self.member.id}/role/",
            {"role": "admin"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_group_admin_cannot_manage_another_group(self):
        self.client.force_authenticate(self.group_admin)
        response = self.client.patch(
            f"/api/groups/{self.other_group.id}/members/{self.moderator.id}/role/",
            {"role": "moderator"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # --- 5. Group owner can promote a moderator ---------------------------
    def test_owner_can_promote_normal_user_to_moderator(self):
        self.client.force_authenticate(self.owner)
        response = self.client.post(
            f"/api/groups/{self.group.id}/set-role/",
            {"user_id": self.member.id, "role": "moderator"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        membership = GroupMembership.objects.get(group=self.group, user=self.member)
        self.assertEqual(membership.role, GroupMembership.ROLE_MODERATOR)
        # The promotion must not have granted any platform privilege.
        self.member.refresh_from_db()
        self.assertFalse(self.member.is_staff)
        self.assertFalse(self.member.is_superuser)

    def test_owner_can_assign_admin_role(self):
        self.client.force_authenticate(self.owner)
        response = self.client.patch(
            f"/api/groups/{self.group.id}/members/{self.member.id}/role/",
            {"role": "admin"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_cannot_change_owner_role(self):
        GroupMembership.objects.get_or_create(
            group=self.group,
            user=self.owner,
            defaults={
                "role": GroupMembership.ROLE_MEMBER,
                "status": GroupMembership.STATUS_ACTIVE,
            },
        )
        self.client.force_authenticate(self.staff)
        response = self.client.post(
            f"/api/groups/{self.group.id}/set-role/",
            {"user_id": self.owner.id, "role": "member"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cannot_assign_role_to_non_member(self):
        outsider = User.objects.create_user(
            username="role-outsider", email="role-outsider@example.com", password="pass1234"
        )
        self.client.force_authenticate(self.owner)
        response = self.client.post(
            f"/api/groups/{self.group.id}/set-role/",
            {"user_id": outsider.id, "role": "moderator"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_invalid_role_is_rejected(self):
        self.client.force_authenticate(self.owner)
        response = self.client.post(
            f"/api/groups/{self.group.id}/set-role/",
            {"user_id": self.member.id, "role": "superadmin"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_inactive_member_cannot_be_made_moderator(self):
        membership = GroupMembership.objects.get(group=self.group, user=self.member)
        membership.status = GroupMembership.STATUS_BANNED
        membership.save(update_fields=["status"])

        self.client.force_authenticate(self.owner)
        response = self.client.post(
            f"/api/groups/{self.group.id}/set-role/",
            {"user_id": self.member.id, "role": "moderator"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_banned_moderator_loses_moderation_rights(self):
        membership = GroupMembership.objects.get(group=self.group, user=self.moderator)
        membership.status = GroupMembership.STATUS_BANNED
        membership.save(update_fields=["status"])

        data = self._can_i(self.moderator, self.group)
        self.assertFalse(data["can_moderate_content"])

    # --- 6. Staff keeps every capability it had ---------------------------
    def test_platform_staff_retains_access_without_membership(self):
        self.assertFalse(
            GroupMembership.objects.filter(group=self.group, user=self.staff).exists()
        )
        data = self._can_i(self.staff, self.group)
        self.assertTrue(data["can_moderate_content"])
        self.assertTrue(data["permissions"]["can_manage_members"])
        self.assertTrue(data["permissions"]["can_edit"])
        self.assertTrue(data["is_platform_staff"])

    def test_platform_staff_can_set_roles_in_any_group(self):
        self.client.force_authenticate(self.staff)
        response = self.client.post(
            f"/api/groups/{self.other_group.id}/set-role/",
            {"user_id": self.moderator.id, "role": "moderator"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    # --- 7. Group roles never confer Django admin access ------------------
    def test_group_roles_do_not_grant_django_admin(self):
        for user in (self.moderator, self.group_admin):
            user.refresh_from_db()
            self.assertFalse(user.is_staff, f"{user.username} must not be Django staff")
            self.assertFalse(user.is_superuser)

    def test_promotion_to_moderator_does_not_set_staff_flag(self):
        self.client.force_authenticate(self.owner)
        self.client.patch(
            f"/api/groups/{self.group.id}/members/{self.member.id}/role/",
            {"role": "moderator"},
            format="json",
        )
        self.member.refresh_from_db()
        self.assertFalse(self.member.is_staff)

    # --- Serializer surface ------------------------------------------------
    def test_group_detail_exposes_role_and_permissions(self):
        self.client.force_authenticate(self.moderator)
        response = self.client.get(f"/api/groups/{self.group.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["current_user_role"], "moderator")
        perms = response.data["permissions"]
        self.assertTrue(perms["can_moderate_posts"])
        self.assertFalse(perms["can_edit"])
        self.assertFalse(perms["can_manage_members"])

    def test_group_detail_permissions_for_group_admin(self):
        self.client.force_authenticate(self.group_admin)
        response = self.client.get(f"/api/groups/{self.group.id}/")
        perms = response.data["permissions"]
        self.assertTrue(perms["can_edit"])
        self.assertTrue(perms["can_manage_members"])
        self.assertTrue(perms["can_moderate_posts"])
        self.assertFalse(perms["can_assign_admin_role"])

    def test_group_detail_permissions_for_plain_member(self):
        self.client.force_authenticate(self.member)
        response = self.client.get(f"/api/groups/{self.group.id}/")
        perms = response.data["permissions"]
        self.assertFalse(perms["can_edit"])
        self.assertFalse(perms["can_moderate_posts"])
