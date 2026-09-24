from datetime import timedelta

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone
from rest_framework import status

from blogs.models import BlogCategory, BlogTag

from .factories import BlogAPITestCase, make_post, make_published_post, make_user

LIST_URL = reverse("blogs:post-list")

WORDPRESS_AND_AUDIT_FIELDS = {
    "wp_post_id",
    "wp_source_url",
    "wp_author_id",
    "wp_modified_at",
    "imported_from_wordpress",
    "created_by",
    "updated_by",
    "status",
}


def detail_url(slug):
    return reverse("blogs:post-detail", kwargs={"slug": slug})


class PublicBlogApiTests(BlogAPITestCase):
    def setUp(self):
        super().setUp()
        self.user = make_user("reader")
        self.client.force_authenticate(self.user)
        self.published = make_published_post(
            title="Published story",
            excerpt="Short summary",
            wp_post_id=555,
            wp_source_url="https://example.com/old",
            imported_from_wordpress=True,
        )
        self.draft = make_post(title="Secret draft")

    def _slugs(self, response):
        return [item["slug"] for item in response.data["results"]]

    def test_unauthenticated_requests_are_rejected(self):
        self.client.force_authenticate(None)
        for url in (LIST_URL, detail_url(self.published.slug)):
            response = self.client.get(url)
            self.assertIn(
                response.status_code,
                (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
            )

    def test_list_contains_published_only(self):
        response = self.client.get(LIST_URL)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self._slugs(response), [self.published.slug])

    def test_published_detail_accessible(self):
        response = self.client.get(detail_url(self.published.slug))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["content_html"], "<p>Body</p>")
        self.assertEqual(response.data["title"], "Published story")

    def test_draft_detail_is_indistinguishable_from_missing(self):
        draft_response = self.client.get(detail_url(self.draft.slug))
        missing_response = self.client.get(detail_url("does-not-exist"))
        self.assertEqual(draft_response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(draft_response.data, missing_response.data)

    def test_unpublished_post_disappears(self):
        self.published.unpublish()
        self.assertEqual(self._slugs(self.client.get(LIST_URL)), [])
        response = self.client.get(detail_url(self.published.slug))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_list_sorted_newest_published_first(self):
        older = make_published_post(
            title="Older", published_at=timezone.now() - timedelta(days=30)
        )
        newest = make_published_post(
            title="Newest", published_at=timezone.now() + timedelta(minutes=1)
        )
        self.assertEqual(
            self._slugs(self.client.get(LIST_URL)),
            [newest.slug, self.published.slug, older.slug],
        )

    def test_pagination(self):
        for i in range(21):
            make_published_post(title=f"Bulk {i}")
        first = self.client.get(LIST_URL)
        self.assertEqual(first.data["count"], 22)
        self.assertEqual(len(first.data["results"]), 20)
        self.assertIsNotNone(first.data["next"])
        second = self.client.get(LIST_URL, {"page": 2})
        self.assertEqual(len(second.data["results"]), 2)

    def test_search(self):
        make_published_post(title="Cross-border deals")
        make_post(title="Cross-border draft")
        response = self.client.get(LIST_URL, {"search": "cross-border"})
        self.assertEqual(self._slugs(response), ["cross-border-deals"])

    def test_category_filter_by_slug_and_id(self):
        category = BlogCategory.objects.create(name="Research")
        tagged = make_published_post(title="Research note")
        tagged.categories.add(category)
        self.draft.categories.add(category)
        for value in (category.slug, str(category.id)):
            response = self.client.get(LIST_URL, {"category": value})
            self.assertEqual(self._slugs(response), [tagged.slug])

    def test_tag_filter(self):
        tag = BlogTag.objects.create(name="Europe")
        tagged = make_published_post(title="Europe note")
        tagged.tags.add(tag)
        response = self.client.get(LIST_URL, {"tag": "europe"})
        self.assertEqual(self._slugs(response), [tagged.slug])

    def test_list_payload_shape_hides_admin_fields(self):
        item = self.client.get(LIST_URL).data["results"][0]
        self.assertEqual(
            set(item),
            {"id", "title", "slug", "excerpt", "featured_image", "author",
             "legacy_author_name", "published_at", "categories", "tags"},
        )
        self.assertNotIn("content_html", item)

    def test_detail_hides_wordpress_and_audit_fields(self):
        data = self.client.get(detail_url(self.published.slug)).data
        self.assertFalse(WORDPRESS_AND_AUDIT_FIELDS & set(data))
        for field in ("seo_title", "seo_description", "canonical_url"):
            self.assertIn(field, data)

    def test_author_serializer_exposes_no_private_fields(self):
        author = make_user("private-author", first_name="Ada", last_name="Lovelace")
        post = make_published_post(title="Authored", author=author)
        data = self.client.get(detail_url(post.slug)).data
        self.assertEqual(set(data["author"]), {"id", "full_name", "avatar_url"})
        self.assertEqual(data["author"]["full_name"], "Ada Lovelace")
        self.assertNotIn("private-author", str(data))

    def test_author_without_name_does_not_fall_back_to_username(self):
        author = make_user("jane.doe")
        post = make_published_post(title="Nameless", author=author)
        data = self.client.get(detail_url(post.slug)).data
        self.assertEqual(data["author"]["full_name"], "")

    def test_legacy_author_name_exposed_when_no_author(self):
        post = make_published_post(title="Legacy", legacy_author_name="Old Writer")
        data = self.client.get(detail_url(post.slug)).data
        self.assertIsNone(data["author"])
        self.assertEqual(data["legacy_author_name"], "Old Writer")

    def test_public_api_is_read_only(self):
        self.assertEqual(
            self.client.post(LIST_URL, {"title": "x"}).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )
        self.assertEqual(
            self.client.patch(detail_url(self.published.slug), {"title": "x"}).status_code,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    def _count_list_queries(self):
        with CaptureQueriesContext(connection) as ctx:
            self.client.get(LIST_URL)
        return len(ctx.captured_queries)

    def test_list_query_count_does_not_grow_with_posts(self):
        category = BlogCategory.objects.create(name="Counted")
        tag = BlogTag.objects.create(name="Counted")

        def add_post(i):
            author = make_user(f"counted-{i}", first_name="C", last_name=str(i))
            post = make_published_post(title=f"Counted {i}", author=author)
            post.categories.add(category)
            post.tags.add(tag)

        add_post(0)
        self.client.get(LIST_URL)  # warm-up: absorbs one-off per-user middleware queries
        baseline = self._count_list_queries()
        for i in range(1, 6):
            add_post(i)
        self.assertEqual(self._count_list_queries(), baseline)
