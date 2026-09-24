from datetime import timedelta

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from blogs.models import BlogCategory, BlogPost, BlogTag

from .factories import make_post, make_user


class BlogTermModelTests(TestCase):
    def test_create_category(self):
        category = BlogCategory.objects.create(name="  M&A Insights  ")
        self.assertEqual(category.name, "M&A Insights")
        self.assertEqual(str(category), "M&A Insights")

    def test_category_slug_auto_generated(self):
        category = BlogCategory.objects.create(name="Deal Making")
        self.assertEqual(category.slug, "deal-making")

    def test_category_explicit_slug_preserved(self):
        category = BlogCategory.objects.create(name="Deal Making", slug="deals")
        self.assertEqual(category.slug, "deals")

    def test_category_auto_slug_avoids_existing_slug(self):
        BlogCategory.objects.create(name="Other", slug="deal-making")
        category = BlogCategory.objects.create(name="Deal Making")
        self.assertEqual(category.slug, "deal-making-2")

    def test_duplicate_category_slug_rejected(self):
        BlogCategory.objects.create(name="First", slug="shared")
        with self.assertRaises(IntegrityError), transaction.atomic():
            BlogCategory.objects.create(name="Second", slug="shared")

    def test_duplicate_category_name_rejected_case_insensitively(self):
        BlogCategory.objects.create(name="Valuation")
        with self.assertRaises(IntegrityError), transaction.atomic():
            BlogCategory.objects.create(name="VALUATION", slug="valuation-upper")

    def test_blank_category_name_fails_validation(self):
        with self.assertRaises(ValidationError):
            BlogCategory(name="   ").full_clean()

    def test_create_tag_and_slug_generation(self):
        tag = BlogTag.objects.create(name="Private Equity")
        self.assertEqual(tag.slug, "private-equity")
        self.assertEqual(str(tag), "Private Equity")
        second = BlogTag.objects.create(name="Private-Equity")
        self.assertEqual(second.slug, "private-equity-2")

    def test_symbol_only_name_gets_fallback_slug(self):
        self.assertEqual(BlogTag.objects.create(name="&&&").slug, "tag")


class BlogPostModelTests(TestCase):
    def test_draft_creation_defaults(self):
        post = BlogPost.objects.create(title="Draft idea")
        self.assertEqual(post.status, BlogPost.STATUS_DRAFT)
        self.assertIsNone(post.published_at)
        self.assertFalse(post.imported_from_wordpress)
        self.assertEqual(str(post), "Draft idea")

    def test_title_is_trimmed(self):
        post = make_post(title="  Spaced title  ")
        self.assertEqual(post.title, "Spaced title")

    def test_automatic_slug_and_collision_suffix(self):
        first = make_post(title="M&A Market Update")
        second = make_post(title="M&A Market Update")
        self.assertEqual(first.slug, "m-a-market-update")
        self.assertEqual(second.slug, "m-a-market-update-2")

    def test_explicit_slug_preserved(self):
        post = make_post(title="Anything", slug="legacy-wp-slug")
        self.assertEqual(post.slug, "legacy-wp-slug")

    def test_duplicate_explicit_slug_rejected(self):
        make_post(slug="taken")
        with self.assertRaises(IntegrityError), transaction.atomic():
            make_post(slug="taken")

    def test_reserved_slug_never_auto_generated(self):
        self.assertEqual(make_post(title="Admin").slug, "admin-2")

    def test_title_change_does_not_change_slug(self):
        post = make_post(title="Original title")
        post.title = "Completely new title"
        post.save()
        post.refresh_from_db()
        self.assertEqual(post.slug, "original-title")

    def test_wp_post_id_unique_when_present(self):
        make_post(wp_post_id=101, imported_from_wordpress=True)
        with self.assertRaises(IntegrityError), transaction.atomic():
            make_post(wp_post_id=101, imported_from_wordpress=True)

    def test_multiple_null_wp_post_ids_allowed(self):
        make_post()
        make_post()
        self.assertEqual(BlogPost.objects.filter(wp_post_id__isnull=True).count(), 2)

    def test_categories_and_tags_attach(self):
        post = make_post()
        category = BlogCategory.objects.create(name="Research")
        tag = BlogTag.objects.create(name="Europe")
        post.categories.add(category)
        post.tags.add(tag)
        self.assertEqual(list(post.categories.all()), [category])
        self.assertEqual(list(post.tags.all()), [tag])
        self.assertEqual(list(category.posts.all()), [post])

    def test_featured_image_and_author_optional_with_legacy_author(self):
        post = make_post(legacy_author_name="Historic Writer")
        post.full_clean()
        self.assertFalse(post.featured_image)
        self.assertIsNone(post.author)
        self.assertEqual(post.legacy_author_name, "Historic Writer")

    def test_author_is_separate_from_audit_fields(self):
        author = make_user("writer")
        editor = make_user("editor")
        post = make_post(author=author, created_by=editor, updated_by=editor)
        self.assertEqual(post.author, author)
        self.assertEqual(post.created_by, editor)

    def test_publish_sets_timestamp_once(self):
        post = make_post()
        post.publish()
        first = post.published_at
        self.assertEqual(post.status, BlogPost.STATUS_PUBLISHED)
        self.assertIsNotNone(first)
        post.publish()
        post.refresh_from_db()
        self.assertEqual(post.published_at, first)

    def test_publish_preserves_historical_published_at(self):
        historical = timezone.now() - timedelta(days=900)
        post = make_post(published_at=historical)
        post.publish()
        post.refresh_from_db()
        self.assertEqual(post.published_at, historical)

    def test_unpublish_keeps_published_at(self):
        post = make_post()
        post.publish()
        stamp = post.published_at
        post.unpublish()
        post.refresh_from_db()
        self.assertEqual(post.status, BlogPost.STATUS_DRAFT)
        self.assertEqual(post.published_at, stamp)

    def test_publish_requires_content(self):
        post = make_post(content_html="   ")
        with self.assertRaises(ValidationError) as ctx:
            post.publish()
        self.assertIn("content_html", ctx.exception.message_dict)
        post.refresh_from_db()
        self.assertEqual(post.status, BlogPost.STATUS_DRAFT)

    def test_full_clean_rejects_published_without_content(self):
        post = BlogPost(title="T", slug="t", status=BlogPost.STATUS_PUBLISHED)
        with self.assertRaises(ValidationError):
            post.full_clean()

    def test_invalid_status_rejected_by_validation(self):
        post = BlogPost(title="T", slug="t", status="archived")
        with self.assertRaises(ValidationError) as ctx:
            post.full_clean()
        self.assertIn("status", ctx.exception.message_dict)

    def test_published_manager_only_returns_published(self):
        draft = make_post(title="Draft")
        live = make_post(title="Live")
        live.publish()
        self.assertEqual(list(BlogPost.published.all()), [live])
        self.assertIn(draft, BlogPost.objects.all())
