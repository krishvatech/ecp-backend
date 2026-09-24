"""Permission matrix for every blog endpoint.

Only Django superusers may manage blogs. Staff without ``is_superuser`` are
treated as normal readers.
"""
from django.urls import reverse
from rest_framework import status

from blogs.models import BlogCategory, BlogPost, BlogTag

from .factories import BlogAPITestCase, make_post, make_published_post, make_superuser, make_user

DENIED = (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)


class BlogPermissionMatrixTests(BlogAPITestCase):
    def setUp(self):
        super().setUp()
        self.reader = make_user("reader")
        self.staff = make_user("staff-only", is_staff=True)
        self.superuser = make_superuser()
        self.draft = make_post(title="Draft")
        self.live = make_published_post(title="Live")
        self.category = BlogCategory.objects.create(name="Research")
        self.tag = BlogTag.objects.create(name="Europe")

    def _management_requests(self):
        pk = self.draft.pk
        return [
            ("get", reverse("blogs:admin-post-list"), None),
            ("post", reverse("blogs:admin-post-list"), {"title": "Hack"}),
            ("get", reverse("blogs:admin-post-detail", kwargs={"pk": pk}), None),
            ("patch", reverse("blogs:admin-post-detail", kwargs={"pk": pk}), {"title": "Hack"}),
            ("post", reverse("blogs:admin-post-publish", kwargs={"pk": pk}), None),
            ("post", reverse("blogs:admin-post-unpublish", kwargs={"pk": self.live.pk}), None),
            ("get", reverse("blogs:admin-category-list"), None),
            ("post", reverse("blogs:admin-category-list"), {"name": "Hack"}),
            (
                "patch",
                reverse("blogs:admin-category-detail", kwargs={"pk": self.category.pk}),
                {"name": "Hack renamed"},
            ),
            ("get", reverse("blogs:admin-tag-list"), None),
            ("post", reverse("blogs:admin-tag-list"), {"name": "Hack"}),
            (
                "patch",
                reverse("blogs:admin-tag-detail", kwargs={"pk": self.tag.pk}),
                {"name": "Hack renamed"},
            ),
        ]

    def _assert_management_denied(self):
        for method, url, body in self._management_requests():
            response = getattr(self.client, method)(url, body, format="json")
            self.assertIn(response.status_code, DENIED, f"{method.upper()} {url}")
        self.draft.refresh_from_db()
        self.live.refresh_from_db()
        self.assertEqual(self.draft.title, "Draft")
        self.assertEqual(self.draft.status, BlogPost.STATUS_DRAFT)
        self.assertEqual(self.live.status, BlogPost.STATUS_PUBLISHED)
        self.assertFalse(BlogPost.objects.filter(title="Hack").exists())
        self.assertFalse(BlogCategory.objects.filter(name__startswith="Hack").exists())
        self.assertFalse(BlogTag.objects.filter(name__startswith="Hack").exists())

    def _assert_reader_access(self):
        list_response = self.client.get(reverse("blogs:post-list"))
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual([p["slug"] for p in list_response.data["results"]], [self.live.slug])
        live = self.client.get(reverse("blogs:post-detail", kwargs={"slug": self.live.slug}))
        self.assertEqual(live.status_code, status.HTTP_200_OK)
        draft = self.client.get(reverse("blogs:post-detail", kwargs={"slug": self.draft.slug}))
        self.assertEqual(draft.status_code, status.HTTP_404_NOT_FOUND)

    def test_anonymous_denied_everywhere(self):
        self._assert_management_denied()
        for url in (
            reverse("blogs:post-list"),
            reverse("blogs:post-detail", kwargs={"slug": self.live.slug}),
        ):
            self.assertIn(self.client.get(url).status_code, DENIED)

    def test_normal_user_reads_published_only_and_cannot_manage(self):
        self.client.force_authenticate(self.reader)
        self._assert_reader_access()
        self._assert_management_denied()

    def test_staff_without_superuser_gets_no_management_access(self):
        self.client.force_authenticate(self.staff)
        self._assert_reader_access()
        self._assert_management_denied()

    def test_superuser_reads_published_api_like_everyone_else(self):
        self.client.force_authenticate(self.superuser)
        self._assert_reader_access()

    def test_superuser_can_use_every_management_endpoint(self):
        self.client.force_authenticate(self.superuser)
        expected = {"get": status.HTTP_200_OK, "patch": status.HTTP_200_OK}
        for method, url, body in self._management_requests():
            response = getattr(self.client, method)(url, body, format="json")
            wanted = expected.get(method)
            if method == "post":
                wanted = status.HTTP_200_OK if "publish" in url else status.HTTP_201_CREATED
            self.assertEqual(response.status_code, wanted, f"{method.upper()} {url}: {response.data}")
