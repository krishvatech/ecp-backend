"""Django Admin cannot reactivate, edit or remove a deleted Subscription List.

Permanent deletion only happens through the Marketing Hub endpoint (which also
deletes the Mautic segment); the admin must never undo or bypass it.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from newsletter.models import NewsletterCampaign, NewsletterCategory, NewsletterSubscription

User = get_user_model()


class NewsletterCategoryAdminProtectionTests(TestCase):
    def setUp(self):
        self.admin_user = User.objects.create_superuser("admin-x", "admin-x@example.test", "pw")
        self.client.force_login(self.admin_user)
        self.member = User.objects.create_user("member-x", "member-x@example.test", "pw")
        self.deleted = NewsletterCategory.objects.create(
            name="Old Deals",
            slug="old-deals",
            is_active=False,
            mautic_segment_id="300",
            deletion_state=NewsletterCategory.DeletionState.DELETED,
            deleted_at=timezone.now(),
            deleted_by=self.admin_user,
        )
        self.pending = NewsletterCategory.objects.create(
            name="Half Gone",
            slug="half-gone",
            is_active=False,
            mautic_segment_id="301",
            deletion_state=NewsletterCategory.DeletionState.DELETING,
        )
        self.live = NewsletterCategory.objects.create(name="Live List", slug="live-list", mautic_segment_id="302")

    @staticmethod
    def _change_url(category):
        return reverse("admin:newsletter_newslettercategory_change", args=[category.pk])

    @staticmethod
    def _form(category, **overrides):
        data = {
            "name": category.name,
            "slug": category.slug,
            "description": category.description,
            "mautic_segment_id": category.mautic_segment_id,
            "is_active": "on",
        }
        data.update(overrides)
        return {key: value for key, value in data.items() if value is not None}

    def test_deleted_and_pending_lists_are_view_only(self):
        for category in (self.deleted, self.pending):
            page = self.client.get(self._change_url(category))
            self.assertEqual(page.status_code, 200)
            self.assertFalse(page.context["has_change_permission"])
            self.assertNotContains(page, 'name="_save"')

    def test_admin_post_cannot_reactivate_or_restore_a_deleted_list(self):
        for category in (self.deleted, self.pending):
            state = category.deletion_state
            response = self.client.post(self._change_url(category), self._form(category, deletion_state=""))
            self.assertEqual(response.status_code, 403)
            category.refresh_from_db()
            self.assertFalse(category.is_active)
            self.assertEqual(category.deletion_state, state)

    def test_deleted_list_cannot_be_removed_from_admin(self):
        campaign = NewsletterCampaign.objects.create(name="History", status=NewsletterCampaign.Status.SENT)
        campaign.audiences.add(self.deleted)

        delete_url = reverse("admin:newsletter_newslettercategory_delete", args=[self.deleted.pk])
        self.assertEqual(self.client.get(delete_url).status_code, 403)
        self.assertEqual(self.client.post(delete_url, {"post": "yes"}).status_code, 403)

        changelist = reverse("admin:newsletter_newslettercategory_changelist")
        self.client.post(
            changelist,
            {"action": "delete_selected", "_selected_action": [self.deleted.pk, self.pending.pk], "post": "yes"},
        )
        self.assertTrue(NewsletterCategory.objects.filter(pk__in=[self.deleted.pk, self.pending.pk]).count() == 2)
        self.assertEqual(list(campaign.audiences.values_list("slug", flat=True)), ["old-deals"])

    def test_live_list_stays_editable_but_lifecycle_fields_are_read_only(self):
        NewsletterSubscription.objects.create(user=self.member, category=self.live, is_subscribed=True)
        response = self.client.post(
            self._change_url(self.live),
            self._form(self.live, description="Edited", deletion_state="deleted", deleted_by=str(self.admin_user.pk)),
        )
        self.assertEqual(response.status_code, 302, getattr(response, "context", None) and response.context["errors"])
        self.live.refresh_from_db()
        self.assertEqual(self.live.description, "Edited")
        self.assertEqual(self.live.deletion_state, "")
        self.assertIsNone(self.live.deleted_by)
        self.assertTrue(self.live.is_active)

    def test_live_list_deactivate_and_reactivate_from_admin_still_work(self):
        self.client.post(self._change_url(self.live), self._form(self.live, is_active=None))
        self.live.refresh_from_db()
        self.assertFalse(self.live.is_active)
        self.client.post(self._change_url(self.live), self._form(self.live))
        self.live.refresh_from_db()
        self.assertTrue(self.live.is_active)

    def test_admin_add_reuses_deleted_name_but_rejects_live_duplicate(self):
        add_url = reverse("admin:newsletter_newslettercategory_add")
        reused = self.client.post(add_url, {"name": "Old Deals", "slug": "old-deals-2", "description": "", "is_active": "on"})
        self.assertEqual(reused.status_code, 302)
        duplicate = self.client.post(add_url, {"name": "Live List", "slug": "live-list-2", "description": "", "is_active": "on"})
        self.assertEqual(duplicate.status_code, 200)
        self.assertContains(duplicate, "Newsletter category with this Name already exists.")
        self.assertFalse(NewsletterCategory.objects.filter(slug="live-list-2").exists())

    def test_renaming_a_live_list_to_another_live_name_is_a_form_error(self):
        response = self.client.post(self._change_url(self.live), self._form(self.live, name="Half Gone"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Newsletter category with this Name already exists.")
        self.live.refresh_from_db()
        self.assertEqual(self.live.name, "Live List")

    def test_changelist_shows_deletion_state(self):
        page = self.client.get(reverse("admin:newsletter_newslettercategory_changelist"), {"deletion_state": "deleted"})
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Old Deals")
        self.assertNotContains(page, "Live List")
