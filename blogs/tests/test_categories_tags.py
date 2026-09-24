from django.urls import reverse
from rest_framework import status

from blogs.models import BlogCategory, BlogTag

from .factories import BlogAPITestCase, make_superuser, make_user

CATEGORY_LIST_URL = reverse("blogs:admin-category-list")
TAG_LIST_URL = reverse("blogs:admin-tag-list")


class TaxonomyApiCases:
    """Shared cases run against both the category and tag endpoints."""

    model = None
    list_url = None
    detail_route = None

    def setUp(self):
        super().setUp()
        self.admin = make_superuser()
        self.client.force_authenticate(self.admin)

    def detail_url(self, pk):
        return reverse(self.detail_route, kwargs={"pk": pk})

    def test_superuser_creates_with_generated_slug(self):
        response = self.client.post(self.list_url, {"name": "  Deal Flow  "}, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        self.assertEqual(response.data["name"], "Deal Flow")
        self.assertEqual(response.data["slug"], "deal-flow")
        self.assertTrue(self.model.objects.filter(slug="deal-flow").exists())

    def test_explicit_slug_preserved(self):
        response = self.client.post(
            self.list_url, {"name": "Deal Flow", "slug": "deals"}, format="json"
        )
        self.assertEqual(response.data["slug"], "deals")

    def test_blank_name_rejected(self):
        response = self.client.post(self.list_url, {"name": "   "}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("name", response.data)

    def test_duplicate_name_rejected_case_insensitively(self):
        self.model.objects.create(name="Valuation")
        response = self.client.post(self.list_url, {"name": "valuation"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("name", response.data)

    def test_duplicate_slug_rejected(self):
        self.model.objects.create(name="First", slug="shared")
        response = self.client.post(
            self.list_url, {"name": "Second", "slug": "Shared"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("slug", response.data)

    def test_patch_renames_without_changing_slug(self):
        term = self.model.objects.create(name="Old Name")
        response = self.client.patch(self.detail_url(term.pk), {"name": "New Name"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        term.refresh_from_db()
        self.assertEqual(term.name, "New Name")
        self.assertEqual(term.slug, "old-name")

    def test_patch_keeping_own_name_and_slug_is_allowed(self):
        term = self.model.objects.create(name="Stable")
        response = self.client.patch(
            self.detail_url(term.pk), {"name": "Stable", "slug": "stable"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_list_and_search(self):
        self.model.objects.create(name="Alpha")
        self.model.objects.create(name="Beta")
        response = self.client.get(self.list_url, {"search": "alp"})
        self.assertEqual([t["name"] for t in response.data["results"]], ["Alpha"])

    def test_delete_not_allowed(self):
        term = self.model.objects.create(name="Keep")
        response = self.client.delete(self.detail_url(term.pk))
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertTrue(self.model.objects.filter(pk=term.pk).exists())

    def test_normal_user_cannot_create(self):
        self.client.force_authenticate(make_user("reader"))
        response = self.client.post(self.list_url, {"name": "Nope"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(self.model.objects.filter(name="Nope").exists())


class CategoryApiTests(TaxonomyApiCases, BlogAPITestCase):
    model = BlogCategory
    list_url = CATEGORY_LIST_URL
    detail_route = "blogs:admin-category-detail"


class TagApiTests(TaxonomyApiCases, BlogAPITestCase):
    model = BlogTag
    list_url = TAG_LIST_URL
    detail_route = "blogs:admin-tag-detail"
