from datetime import timedelta

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from blogs.models import BlogCategory, BlogPost, BlogTag

from .factories import (
    BlogAPITestCase,
    make_post,
    make_published_post,
    make_superuser,
    make_user,
)

ADMIN_LIST_URL = reverse("blogs:admin-post-list")
PUBLIC_LIST_URL = reverse("blogs:post-list")

# 1x1 transparent GIF
TINY_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01"
    b"\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)


def admin_detail_url(pk):
    return reverse("blogs:admin-post-detail", kwargs={"pk": pk})


def publish_url(pk):
    return reverse("blogs:admin-post-publish", kwargs={"pk": pk})


def unpublish_url(pk):
    return reverse("blogs:admin-post-unpublish", kwargs={"pk": pk})


class AdminBlogApiTests(BlogAPITestCase):
    def setUp(self):
        super().setUp()
        self.admin = make_superuser()
        self.other_admin = make_superuser("second-admin")
        self.reader = make_user("reader")
        self.client.force_authenticate(self.admin)

    def _ids(self, response):
        return {item["id"] for item in response.data["results"]}

    def test_list_includes_drafts_and_published(self):
        draft = make_post(title="Draft")
        live = make_published_post(title="Live")
        response = self.client.get(ADMIN_LIST_URL)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self._ids(response), {draft.id, live.id})
        self.assertIn("wp_post_id", response.data["results"][0])

    def test_list_status_filter(self):
        draft = make_post(title="Draft")
        live = make_published_post(title="Live")
        self.assertEqual(self._ids(self.client.get(ADMIN_LIST_URL, {"status": "draft"})), {draft.id})
        self.assertEqual(
            self._ids(self.client.get(ADMIN_LIST_URL, {"status": "published"})), {live.id}
        )
        bad = self.client.get(ADMIN_LIST_URL, {"status": "archived"})
        self.assertEqual(bad.status_code, status.HTTP_400_BAD_REQUEST)

    def test_list_search_and_term_filters(self):
        category = BlogCategory.objects.create(name="Research")
        tag = BlogTag.objects.create(name="Asia")
        match = make_post(title="Asian research draft")
        match.categories.add(category)
        match.tags.add(tag)
        make_post(title="Unrelated")
        self.assertEqual(self._ids(self.client.get(ADMIN_LIST_URL, {"search": "asian"})), {match.id})
        self.assertEqual(
            self._ids(self.client.get(ADMIN_LIST_URL, {"category": "research"})), {match.id}
        )
        self.assertEqual(self._ids(self.client.get(ADMIN_LIST_URL, {"tag": tag.id})), {match.id})

    def test_admin_can_manage_posts_created_by_another_admin(self):
        post = make_post(title="Theirs", created_by=self.other_admin)
        response = self.client.patch(admin_detail_url(post.id), {"excerpt": "edited"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["updated_by"]["id"], self.admin.id)

    def test_create_draft_sets_audit_fields_server_side(self):
        category = BlogCategory.objects.create(name="Research")
        tag = BlogTag.objects.create(name="Asia")
        author = make_user("writer", first_name="Wri", last_name="Ter")
        response = self.client.post(
            ADMIN_LIST_URL,
            {
                "title": "  New article  ",
                "content_html": "<p>Hello</p>",
                "excerpt": "Teaser",
                "author_id": author.id,
                "category_ids": [category.id],
                "tag_ids": [tag.id],
                "seo_title": "SEO title",
                "canonical_url": "https://example.com/new-article",
                # Spoof attempts; all must be ignored.
                "created_by": self.reader.id,
                "updated_by": self.reader.id,
                "status": "published",
                "published_at": "2020-01-01T00:00:00Z",
                "created_at": "2020-01-01T00:00:00Z",
                "wp_post_id": 99,
                "imported_from_wordpress": True,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        post = BlogPost.objects.get(pk=response.data["id"])
        self.assertEqual(post.title, "New article")
        self.assertEqual(post.slug, "new-article")
        self.assertEqual(post.status, BlogPost.STATUS_DRAFT)
        self.assertIsNone(post.published_at)
        self.assertEqual(post.created_by, self.admin)
        self.assertEqual(post.updated_by, self.admin)
        self.assertEqual(post.author, author)
        self.assertIsNone(post.wp_post_id)
        self.assertFalse(post.imported_from_wordpress)
        self.assertGreater(post.created_at.year, 2020)
        self.assertEqual(list(post.categories.all()), [category])
        self.assertEqual(list(post.tags.all()), [tag])
        self.assertEqual(response.data["categories"][0]["slug"], "research")
        self.assertEqual(response.data["author"]["full_name"], "Wri Ter")

    def test_create_with_explicit_slug(self):
        response = self.client.post(
            ADMIN_LIST_URL, {"title": "T", "slug": "custom-slug"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["slug"], "custom-slug")

    def test_create_rejects_blank_title(self):
        response = self.client.post(ADMIN_LIST_URL, {"title": "   "}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("title", response.data)

    def test_create_rejects_duplicate_or_reserved_slug(self):
        make_post(slug="taken")
        for slug in ("taken", "TAKEN", "admin"):
            response = self.client.post(
                ADMIN_LIST_URL, {"title": "T", "slug": slug}, format="json"
            )
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, slug)
            self.assertIn("slug", response.data)

    def test_invalid_category_and_tag_ids_rejected(self):
        response = self.client.post(
            ADMIN_LIST_URL,
            {"title": "T", "category_ids": [999999], "tag_ids": [999999]},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("category_ids", response.data)
        self.assertIn("tag_ids", response.data)
        self.assertFalse(BlogPost.objects.exists())

    def test_update_sets_updated_by_and_keeps_slug_on_title_change(self):
        post = make_post(title="Old title", created_by=self.other_admin, updated_by=self.other_admin)
        response = self.client.patch(
            admin_detail_url(post.id), {"title": "New title"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        post.refresh_from_db()
        self.assertEqual(post.title, "New title")
        self.assertEqual(post.slug, "old-title")
        self.assertEqual(post.created_by, self.other_admin)
        self.assertEqual(post.updated_by, self.admin)

    def test_update_slug_collision_rejected(self):
        make_post(slug="existing")
        post = make_post(slug="mine")
        response = self.client.patch(admin_detail_url(post.id), {"slug": "existing"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        blank = self.client.patch(admin_detail_url(post.id), {"slug": ""}, format="json")
        self.assertEqual(blank.status_code, status.HTTP_400_BAD_REQUEST)
        same = self.client.patch(admin_detail_url(post.id), {"slug": "mine"}, format="json")
        self.assertEqual(same.status_code, status.HTTP_200_OK)
        renamed = self.client.patch(admin_detail_url(post.id), {"slug": "renamed"}, format="json")
        self.assertEqual(renamed.data["slug"], "renamed")

    def test_update_cannot_change_status_or_published_at(self):
        post = make_post()
        response = self.client.patch(
            admin_detail_url(post.id),
            {"status": "published", "published_at": "2020-01-01T00:00:00Z"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        post.refresh_from_db()
        self.assertEqual(post.status, BlogPost.STATUS_DRAFT)
        self.assertIsNone(post.published_at)

    def test_published_post_cannot_be_emptied(self):
        post = make_published_post()
        response = self.client.patch(admin_detail_url(post.id), {"content_html": " "}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("content_html", response.data)

    def test_put_and_delete_not_allowed(self):
        post = make_post()
        self.assertEqual(
            self.client.put(admin_detail_url(post.id), {"title": "x"}, format="json").status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
        self.assertEqual(
            self.client.delete(admin_detail_url(post.id)).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
        self.assertTrue(BlogPost.objects.filter(pk=post.pk).exists())

    def test_publish_flow(self):
        post = make_post(title="To publish", updated_by=self.other_admin)
        response = self.client.post(publish_url(post.id))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "published")
        self.assertIsNotNone(response.data["published_at"])
        self.assertEqual(response.data["updated_by"]["id"], self.admin.id)

        self.client.force_authenticate(self.reader)
        slugs = [p["slug"] for p in self.client.get(PUBLIC_LIST_URL).data["results"]]
        self.assertIn(post.slug, slugs)

    def test_repeat_publish_keeps_timestamp(self):
        post = make_post()
        first = self.client.post(publish_url(post.id)).data["published_at"]
        second = self.client.post(publish_url(post.id))
        self.assertEqual(second.status_code, status.HTTP_200_OK)
        self.assertEqual(second.data["published_at"], first)
        self.assertEqual(second.data["status"], "published")

    def test_publish_preserves_historical_timestamp(self):
        historical = timezone.now() - timedelta(days=400)
        post = make_post(published_at=historical)
        self.client.post(publish_url(post.id))
        post.refresh_from_db()
        self.assertEqual(post.published_at, historical)

    def test_publish_rejects_incomplete_post(self):
        post = make_post(content_html="")
        response = self.client.post(publish_url(post.id))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("content_html", response.data)
        post.refresh_from_db()
        self.assertEqual(post.status, BlogPost.STATUS_DRAFT)

    def test_unpublish_flow_and_repeat(self):
        post = make_published_post(updated_by=self.other_admin)
        stamp = post.published_at
        response = self.client.post(unpublish_url(post.id))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "draft")
        self.assertEqual(response.data["updated_by"]["id"], self.admin.id)
        repeat = self.client.post(unpublish_url(post.id))
        self.assertEqual(repeat.status_code, status.HTTP_200_OK)
        post.refresh_from_db()
        self.assertEqual(post.status, BlogPost.STATUS_DRAFT)
        self.assertEqual(post.published_at, stamp)

        self.client.force_authenticate(self.reader)
        self.assertEqual(self.client.get(PUBLIC_LIST_URL).data["results"], [])
        detail = self.client.get(reverse("blogs:post-detail", kwargs={"slug": post.slug}))
        self.assertEqual(detail.status_code, status.HTTP_404_NOT_FOUND)

    def test_unknown_post_returns_404(self):
        self.assertEqual(
            self.client.post(publish_url(999999)).status_code, status.HTTP_404_NOT_FOUND
        )

    @override_settings(
        STORAGES={
            "default": {"BACKEND": "django.core.files.storage.InMemoryStorage"},
            "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
        }
    )
    def test_featured_image_upload_and_clear(self):
        post = make_post()
        upload = SimpleUploadedFile("Cover Photo.gif", TINY_GIF, content_type="image/gif")
        response = self.client.patch(
            admin_detail_url(post.id), {"featured_image": upload}, format="multipart"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        post.refresh_from_db()
        self.assertTrue(post.featured_image.name.startswith("blogs/featured/cover-photo-"))

        not_image = SimpleUploadedFile("evil.gif", b"<script>", content_type="image/gif")
        bad = self.client.patch(
            admin_detail_url(post.id), {"featured_image": not_image}, format="multipart"
        )
        self.assertEqual(bad.status_code, status.HTTP_400_BAD_REQUEST)

        cleared = self.client.patch(
            admin_detail_url(post.id), {"featured_image": None}, format="json"
        )
        self.assertEqual(cleared.status_code, status.HTTP_200_OK)
        self.assertIsNone(cleared.data["featured_image"])
