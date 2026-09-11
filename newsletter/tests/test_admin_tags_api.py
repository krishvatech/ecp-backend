from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError


User = get_user_model()


TAG_LIST = {
    "total": 3,
    "tags": {
        "1": {"id": 1, "tag": "Newsletter", "description": None},
        "2": {"id": 2, "tag": "vip", "description": None},
        "3": {"id": 3, "tag": "Webinar", "description": None},
    },
}


class NewsletterAdminTagDirectoryAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="tag-staff",
            email="tag-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="tag-normal",
            email="tag-normal@example.test",
            password="test-password",
        )
        self.list_url = reverse("newsletter-admin-tag-directory")
        self.detail_url = reverse("newsletter-admin-tag-detail", args=["2"])

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    # ------------------------------------------------------------------ auth

    def test_tag_directory_requires_authentication(self):
        response = self.client.get(self.list_url)
        self.assertIn(response.status_code, (401, 403))

    def test_tag_directory_rejects_non_staff(self):
        self._authenticate(self.normal_user)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 403)

    def test_tag_detail_rejects_non_staff(self):
        self._authenticate(self.normal_user)
        response = self.client.patch(self.detail_url, {"tag": "x"}, format="json")
        self.assertEqual(response.status_code, 403)

    # ------------------------------------------------------------------ list

    @patch("newsletter.tag_services.MauticClient")
    def test_tag_directory_lists_sorted_tags(self, client_cls):
        client = MagicMock()
        client.list_tags.return_value = TAG_LIST
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 3)
        self.assertEqual(
            [tag["tag"] for tag in response.data["results"]],
            ["Newsletter", "vip", "Webinar"],
        )

    @patch("newsletter.tag_services.MauticClient")
    def test_tag_search_filters_locally(self, client_cls):
        # Mautic 7.1.3 ignores `search` on /api/tags, so filtering happens in ECP.
        client = MagicMock()
        client.list_tags.return_value = TAG_LIST
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.get(self.list_url, {"search": "web"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["tag"], "Webinar")

    @patch("newsletter.tag_services.MauticClient")
    def test_tag_directory_pages_results(self, client_cls):
        client = MagicMock()
        client.list_tags.return_value = TAG_LIST
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.get(self.list_url, {"page": 2, "page_size": 2})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["num_pages"], 2)
        self.assertEqual(len(response.data["results"]), 1)

    @patch("newsletter.tag_services.MauticClient")
    def test_tag_directory_surfaces_provider_failure(self, client_cls):
        client = MagicMock()
        client.list_tags.side_effect = TemporaryMauticError("Mautic API request failed")
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 502)

    # ---------------------------------------------------------------- create

    @patch("newsletter.tag_services.MauticClient")
    def test_create_tag(self, client_cls):
        client = MagicMock()
        client.create_tag.return_value = {"id": 4, "tag": "Launch", "description": None}
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.post(self.list_url, {"tag": "Launch"}, format="json")

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["tag"], "Launch")
        client.create_tag.assert_called_once_with({"tag": "Launch"})

    @patch("newsletter.tag_services.MauticClient")
    def test_create_tag_requires_name(self, client_cls):
        client_cls.return_value = MagicMock()

        self._authenticate(self.staff)
        response = self.client.post(self.list_url, {"tag": "   "}, format="json")

        self.assertEqual(response.status_code, 400)

    @patch("newsletter.tag_services.MauticClient")
    def test_create_tag_rejects_unsupported_field(self, client_cls):
        # Mautic's tag form does not bind `description`, so ECP refuses it outright
        # rather than pretending the value was saved.
        client_cls.return_value = MagicMock()

        self._authenticate(self.staff)
        response = self.client.post(
            self.list_url,
            {"tag": "Launch", "description": "ignored by Mautic"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("description", response.data["detail"])

    @patch("newsletter.tag_services.MauticClient")
    def test_newly_created_tag_is_visible_to_the_contact_tag_picker(self, client_cls):
        """A tag created in Settings comes straight back from Mautic's tag list."""
        client = MagicMock()
        client.create_tag.return_value = {"id": 4, "tag": "Launch", "description": None}
        client.list_tags.return_value = {
            "total": 4,
            "tags": dict(TAG_LIST["tags"], **{"4": {"id": 4, "tag": "Launch"}}),
        }
        client_cls.return_value = client

        self._authenticate(self.staff)
        self.client.post(self.list_url, {"tag": "Launch"}, format="json")

        with patch("newsletter.contact_services.MauticClient") as picker_cls:
            picker_cls.return_value = client
            picker = self.client.get(reverse("newsletter-admin-tag-list"))

        self.assertEqual(picker.status_code, 200)
        self.assertIn("Launch", [tag["tag"] for tag in picker.data["results"]])

    # ---------------------------------------------------------------- update

    @patch("newsletter.tag_services.MauticClient")
    def test_rename_tag(self, client_cls):
        client = MagicMock()
        client.update_tag.return_value = {"id": 2, "tag": "VIP", "description": None}
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.patch(self.detail_url, {"tag": "VIP"}, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["tag"], "VIP")
        client.update_tag.assert_called_once_with("2", {"tag": "VIP"})

    # ---------------------------------------------------------------- delete

    @patch("newsletter.tag_services.MauticClient")
    def test_delete_tag(self, client_cls):
        client = MagicMock()
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["deleted"])
        client.delete_tag.assert_called_once_with("2")

    @patch("newsletter.tag_services.MauticClient")
    def test_delete_tag_in_use_surfaces_provider_error(self, client_cls):
        # Mautic returns a server error when the tag is still applied to contacts.
        client = MagicMock()
        client.delete_tag.side_effect = TemporaryMauticError(
            "Mautic tag deletion (HTTP 500)"
        )
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 502)
        self.assertIn("detail", response.data)

    @patch("newsletter.tag_services.MauticClient")
    def test_missing_tag_returns_404(self, client_cls):
        client = MagicMock()
        client.get_tag.side_effect = PermanentMauticError("Mautic tag lookup (HTTP 404)")
        client_cls.return_value = client

        self._authenticate(self.staff)
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 404)
