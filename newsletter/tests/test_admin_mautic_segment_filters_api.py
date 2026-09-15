from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.models import NewsletterCategory


User = get_user_model()


def filter_metadata():
    """The shape the campaign-builder bridge really returns for this instance."""
    return {
        "source": "runtime-mautic-segment-filter-choices",
        "objects": ["lead", "company"],
        "glue": [{"value": "and", "label": "and"}, {"value": "or", "label": "or"}],
        "operators": [
            {"value": "=", "label": "equals", "requiresValue": True, "multiple": False},
            {"value": "like", "label": "like", "requiresValue": True, "multiple": False},
            {"value": "gte", "label": "greater than or equal", "requiresValue": True, "multiple": False},
            {"value": "empty", "label": "empty", "requiresValue": False, "multiple": False},
            {"value": "in", "label": "including any of", "requiresValue": True, "multiple": True},
        ],
        "fields": [
            {
                "alias": "city",
                "object": "lead",
                "label": "City",
                "type": "text",
                "control": "text",
                "multiple": False,
                "operators": [
                    {"value": "=", "label": "equals"},
                    {"value": "like", "label": "like"},
                    {"value": "empty", "label": "empty"},
                ],
            },
            {
                "alias": "points",
                "object": "lead",
                "label": "Points",
                "type": "number",
                "control": "number",
                "multiple": False,
                "operators": [
                    {"value": "=", "label": "equals"},
                    {"value": "gte", "label": "greater than or equal"},
                ],
            },
            {
                "alias": "tags",
                "object": "lead",
                "label": "Tags",
                "type": "tags",
                "control": "select",
                "multiple": True,
                "choiceMode": "inline",
                "choices": [{"value": "4", "label": "QA Tag"}],
                "operators": [{"value": "in", "label": "including any of"}],
            },
            {
                "alias": "companycity",
                "object": "company",
                "label": "Company City",
                "type": "text",
                "control": "text",
                "multiple": False,
                "operators": [{"value": "=", "label": "equals"}],
            },
        ],
    }


class NewsletterAdminMauticSegmentFilterMetadataTests(TestCase):
    """Filter metadata comes from the provider; ECP keeps no catalog."""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="segment-meta-staff",
            email="segment-meta-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="segment-meta-normal",
            email="segment-meta-normal@example.test",
            password="test-password",
        )
        self.url = reverse("newsletter-admin-mautic-segment-filter-metadata")

    def test_metadata_requires_authentication(self):
        response = self.client.get(self.url)

        self.assertIn(response.status_code, (401, 403))

    @patch("newsletter.admin_views.MauticClient")
    def test_metadata_rejects_non_staff(self, client_cls):
        self.client.force_authenticate(user=self.normal_user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 403)
        client_cls.return_value.get_segment_filter_metadata.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_metadata_is_returned_for_staff(self, client_cls):
        client_cls.return_value.get_segment_filter_metadata.return_value = filter_metadata()
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["objects"], ["lead", "company"])
        self.assertEqual(len(response.data["fields"]), 4)
        city = next(f for f in response.data["fields"] if f["alias"] == "city")
        self.assertEqual([o["value"] for o in city["operators"]], ["=", "like", "empty"])
        self.assertEqual(city["control"], "text")

    @patch("newsletter.admin_views.MauticClient")
    def test_metadata_passes_a_search_term_to_the_provider(self, client_cls):
        client_cls.return_value.get_segment_filter_metadata.return_value = filter_metadata()
        self.client.force_authenticate(user=self.staff)

        self.client.get(self.url, {"search": "city"})

        client_cls.return_value.get_segment_filter_metadata.assert_called_once_with("city")

    @patch("newsletter.admin_views.MauticClient")
    def test_provider_failure_is_normalized(self, client_cls):
        client_cls.return_value.get_segment_filter_metadata.side_effect = (
            TemporaryMauticError("Mautic API request failed (HTTP 503)")
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 502)


class NewsletterAdminMauticSegmentFilterWriteTests(TestCase):
    """Creating and updating dynamic segments through official REST."""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="segment-filter-staff",
            email="segment-filter-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)
        self.list_url = reverse("newsletter-admin-mautic-segment-list")
        self.detail_url = reverse(
            "newsletter-admin-mautic-segment-detail",
            args=["19"],
        )

    @staticmethod
    def _segment(**overrides):
        data = {
            "id": 19,
            "name": "QA Dynamic Segment Filters",
            "alias": "qa-dynamic-segment-filters",
            "isPublished": False,
            "filters": [],
        }
        data.update(overrides)
        return data

    @staticmethod
    def _row(field="city", operator="=", value="Surat", **overrides):
        row = {
            "glue": "and",
            "field": field,
            "object": "lead",
            "type": "text",
            "operator": operator,
            "properties": {"filter": value},
        }
        row.update(overrides)
        return row

    def _create(self, client_cls, filters):
        client_cls.return_value.get_segment_filter_metadata.return_value = filter_metadata()
        client_cls.return_value.create_segment.return_value = self._segment(filters=filters)

        return self.client.post(
            self.list_url,
            {"name": "QA Dynamic Segment Filters", "filters": filters},
            format="json",
        )

    @patch("newsletter.admin_views.MauticClient")
    def test_create_with_valid_filters_is_forwarded(self, client_cls):
        response = self._create(
            client_cls,
            [self._row(), self._row(field="points", operator="gte", value=10, type="number", glue="or")],
        )

        self.assertEqual(response.status_code, 201, getattr(response, "data", None))
        payload = client_cls.return_value.create_segment.call_args.args[0]
        self.assertEqual(len(payload["filters"]), 2)
        self.assertEqual(payload["filters"][0]["properties"], {"filter": "Surat"})
        self.assertEqual(payload["filters"][1]["operator"], "gte")
        self.assertTrue(response.data["is_dynamic"])

    @patch("newsletter.admin_views.MauticClient")
    def test_create_without_filters_stays_static(self, client_cls):
        client_cls.return_value.create_segment.return_value = self._segment()

        response = self.client.post(
            self.list_url,
            {"name": "Static QA"},
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        payload = client_cls.return_value.create_segment.call_args.args[0]
        self.assertEqual(payload["filters"], [])
        # No filters submitted: the provider's filter metadata is not even fetched.
        client_cls.return_value.get_segment_filter_metadata.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_unknown_field_is_rejected(self, client_cls):
        response = self._create(client_cls, [self._row(field="not_a_field")])

        self.assertEqual(response.status_code, 400)
        self.assertIn("not available in this Mautic instance", response.data["detail"])
        client_cls.return_value.create_segment.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_operator_the_field_does_not_accept_is_rejected(self, client_cls):
        response = self._create(client_cls, [self._row(operator="gte")])

        self.assertEqual(response.status_code, 400)
        self.assertIn('operator "gte" is not available for "City"', response.data["detail"])
        client_cls.return_value.create_segment.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_missing_value_is_rejected(self, client_cls):
        response = self._create(client_cls, [self._row(properties={})])

        self.assertEqual(response.status_code, 400)
        self.assertIn("needs a value", response.data["detail"])
        client_cls.return_value.create_segment.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_operator_without_a_value_is_accepted(self, client_cls):
        response = self._create(client_cls, [self._row(operator="empty", properties={})])

        self.assertEqual(response.status_code, 201, getattr(response, "data", None))
        payload = client_cls.return_value.create_segment.call_args.args[0]
        self.assertEqual(payload["filters"][0]["properties"], {})

    @patch("newsletter.admin_views.MauticClient")
    def test_bad_glue_is_rejected(self, client_cls):
        response = self._create(client_cls, [self._row(glue="maybe")])

        self.assertEqual(response.status_code, 400)
        self.assertIn("glue must be and or or", response.data["detail"])

    @patch("newsletter.admin_views.MauticClient")
    def test_wrong_object_for_a_field_is_rejected(self, client_cls):
        response = self._create(client_cls, [self._row(object="company")])

        self.assertEqual(response.status_code, 400)
        client_cls.return_value.create_segment.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_company_fields_are_accepted_under_their_own_object(self, client_cls):
        response = self._create(
            client_cls,
            [self._row(field="companycity", object="company", value="Surat")],
        )

        self.assertEqual(response.status_code, 201, getattr(response, "data", None))
        payload = client_cls.return_value.create_segment.call_args.args[0]
        self.assertEqual(payload["filters"][0]["object"], "company")

    @patch("newsletter.admin_views.MauticClient")
    def test_filters_must_be_a_list(self, client_cls):
        client_cls.return_value.get_segment_filter_metadata.return_value = filter_metadata()

        response = self.client.post(
            self.list_url,
            {"name": "QA", "filters": {"field": "city"}},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        client_cls.return_value.create_segment.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_the_first_row_is_always_joined_with_and(self, client_cls):
        response = self._create(
            client_cls,
            [self._row(glue="or"), self._row(field="points", operator="gte", value=5, type="number", glue="or")],
        )

        self.assertEqual(response.status_code, 201)
        payload = client_cls.return_value.create_segment.call_args.args[0]
        self.assertEqual(payload["filters"][0]["glue"], "and")
        self.assertEqual(payload["filters"][1]["glue"], "or")

    @patch("newsletter.admin_views.MauticClient")
    def test_update_replaces_the_filter_set(self, client_cls):
        client_cls.return_value.get_segment_filter_metadata.return_value = filter_metadata()
        client_cls.return_value.update_segment.return_value = self._segment(
            filters=[self._row(operator="like", value="Sur")]
        )

        response = self.client.patch(
            self.detail_url,
            {"filters": [self._row(operator="like", value="Sur")]},
            format="json",
        )

        self.assertEqual(response.status_code, 200, getattr(response, "data", None))
        payload = client_cls.return_value.update_segment.call_args.args[1]
        self.assertEqual(payload["filters"][0]["operator"], "like")
        self.assertEqual(payload["filters"][0]["properties"], {"filter": "Sur"})

    @patch("newsletter.admin_views.MauticClient")
    def test_update_can_clear_filters_back_to_static(self, client_cls):
        client_cls.return_value.get_segment_filter_metadata.return_value = filter_metadata()
        client_cls.return_value.update_segment.return_value = self._segment(filters=[])

        response = self.client.patch(self.detail_url, {"filters": []}, format="json")

        self.assertEqual(response.status_code, 200)
        payload = client_cls.return_value.update_segment.call_args.args[1]
        self.assertEqual(payload["filters"], [])
        self.assertTrue(response.data["is_static"])

    @patch("newsletter.admin_views.MauticClient")
    def test_update_of_other_fields_leaves_filters_alone(self, client_cls):
        client_cls.return_value.update_segment.return_value = self._segment(name="Renamed")

        response = self.client.patch(self.detail_url, {"name": "Renamed"}, format="json")

        self.assertEqual(response.status_code, 200)
        payload = client_cls.return_value.update_segment.call_args.args[1]
        self.assertNotIn("filters", payload)
        client_cls.return_value.get_segment_filter_metadata.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_provider_rejection_is_reported_as_bad_request(self, client_cls):
        client_cls.return_value.get_segment_filter_metadata.return_value = filter_metadata()
        client_cls.return_value.create_segment.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 400): filters: The collection is invalid."
        )

        response = self._create(client_cls, [self._row()])

        self.assertEqual(response.status_code, 400)

    @patch("newsletter.admin_views.MauticClient")
    def test_metadata_failure_stops_the_write(self, client_cls):
        client_cls.return_value.get_segment_filter_metadata.side_effect = (
            TemporaryMauticError("Mautic API request failed (HTTP 503)")
        )

        response = self.client.post(
            self.list_url,
            {"name": "QA", "filters": [self._row()]},
            format="json",
        )

        self.assertEqual(response.status_code, 502)
        client_cls.return_value.create_segment.assert_not_called()


class NewsletterAdminMauticSegmentFilterHydrationTests(TestCase):
    """What is read back is what Mautic will evaluate."""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="segment-hydration-staff",
            email="segment-hydration-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)
        self.detail_url = reverse(
            "newsletter-admin-mautic-segment-detail",
            args=["19"],
        )

    @patch("newsletter.admin_views.MauticClient")
    def test_saved_filters_are_returned_in_provider_shape(self, client_cls):
        saved = [
            {
                "glue": "and",
                "field": "city",
                "object": "lead",
                "type": "text",
                "operator": "=",
                "properties": {"filter": "Surat"},
            },
            {
                "glue": "or",
                "field": "points",
                "object": "lead",
                "type": "number",
                "operator": "gte",
                "properties": {"filter": "10"},
            },
        ]
        client_cls.return_value.get_segment.return_value = {"id": 19, "filters": saved}

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["filters"], saved)
        self.assertTrue(response.data["is_dynamic"])
        self.assertEqual(response.data["filter_count"], 2)

    @patch("newsletter.admin_views.MauticClient")
    def test_a_stale_legacy_value_never_reaches_the_editor(self, client_cls):
        """A PATCH can leave the legacy top-level value out of date.

        ContactSegmentFilterCrate reads properties.filter first, so that is the
        value the segment actually matches on, and the only one ECP shows.
        """
        client_cls.return_value.get_segment.return_value = {
            "id": 19,
            "filters": [
                {
                    "glue": "and",
                    "field": "city",
                    "object": "lead",
                    "type": "text",
                    "operator": "like",
                    "properties": {"filter": "Sur"},
                    "filter": "Surat",
                    "display": None,
                }
            ],
        }

        response = self.client.get(self.detail_url)

        row = response.data["filters"][0]
        self.assertEqual(row["properties"], {"filter": "Sur"})
        self.assertNotIn("filter", row)
        self.assertNotIn("display", row)

    @patch("newsletter.admin_views.MauticClient")
    def test_a_legacy_row_without_properties_still_reads(self, client_cls):
        client_cls.return_value.get_segment.return_value = {
            "id": 19,
            "filters": [
                {
                    "glue": "and",
                    "field": "city",
                    "object": "lead",
                    "type": "text",
                    "operator": "=",
                    "filter": "Surat",
                }
            ],
        }

        response = self.client.get(self.detail_url)

        self.assertEqual(response.data["filters"][0]["properties"], {"filter": "Surat"})

    @patch("newsletter.admin_views.MauticClient")
    def test_a_segment_with_no_filters_is_static(self, client_cls):
        client_cls.return_value.get_segment.return_value = {"id": 19, "filters": []}

        response = self.client.get(self.detail_url)

        self.assertTrue(response.data["is_static"])
        self.assertEqual(response.data["filters"], [])


class NewsletterAdminMauticSegmentProtectionTests(TestCase):
    """Subscription List segments stay ECP-owned, filters or not."""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="segment-protect-staff",
            email="segment-protect-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(user=self.staff)
        # A Subscription List that owns a Mautic segment.
        self.category = NewsletterCategory.objects.create(
            name="QA Protected Subscription List",
            slug="qa-protected-subscription-list",
            mautic_segment_id="1",
        )
        self.detail_url = reverse(
            "newsletter-admin-mautic-segment-detail",
            args=["1"],
        )

    @patch("newsletter.admin_views.MauticClient")
    def test_a_mapped_segment_cannot_be_given_filters(self, client_cls):
        response = self.client.patch(
            self.detail_url,
            {
                "filters": [
                    {
                        "glue": "and",
                        "field": "city",
                        "object": "lead",
                        "type": "text",
                        "operator": "=",
                        "properties": {"filter": "Surat"},
                    }
                ]
            },
            format="json",
        )

        self.assertEqual(response.status_code, 409)
        client_cls.return_value.update_segment.assert_not_called()
        client_cls.return_value.get_segment_filter_metadata.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_a_mapped_segment_cannot_be_deleted(self, client_cls):
        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 409)
        client_cls.return_value.delete_segment.assert_not_called()


class NewsletterAdminMauticSegmentDeleteTests(TestCase):
    """Deleting a native segment must report what actually happened.

    Mautic answers a delete with HTTP 200 and the serialized entity whose id it
    has already nulled; ECP used to read that as a malformed response and tell
    the operator the deletion had failed while the segment was in fact gone.
    """

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="segment-delete-staff",
            email="segment-delete-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="segment-delete-normal",
            email="segment-delete-normal@example.test",
            password="test-password",
        )
        self.client.force_authenticate(user=self.staff)
        self.detail_url = reverse(
            "newsletter-admin-mautic-segment-detail",
            args=["20"],
        )

    @staticmethod
    def _deleted_entity():
        """What Mautic really returns: the entity, with its id nulled."""
        return {
            "id": None,
            "name": "QA Segment Delete Test",
            "alias": "qa-segment-delete-test",
            "isPublished": False,
        }

    @patch("newsletter.admin_views.MauticClient")
    def test_a_successful_delete_is_reported_as_success(self, client_cls):
        client_cls.return_value.delete_segment.return_value = self._deleted_entity()

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 204)
        client_cls.return_value.delete_segment.assert_called_once_with("20")

    @patch("newsletter.admin_views.MauticClient")
    def test_the_provider_is_asked_to_delete_exactly_once(self, client_cls):
        client_cls.return_value.delete_segment.return_value = self._deleted_entity()

        self.client.delete(self.detail_url)

        self.assertEqual(client_cls.return_value.delete_segment.call_count, 1)
        client_cls.return_value.update_segment.assert_not_called()
        client_cls.return_value.create_segment.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_deleting_an_unknown_segment_is_not_found(self, client_cls):
        """A repeated delete: Mautic answers 404 Item was not found."""
        client_cls.return_value.delete_segment.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404): Item was not found."
        )

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 404)

    @patch("newsletter.admin_views.MauticClient")
    def test_a_provider_permission_error_is_not_reported_as_success(self, client_cls):
        client_cls.return_value.delete_segment.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 403): Access denied."
        )

        response = self.client.delete(self.detail_url)

        self.assertNotEqual(response.status_code, 204)
        self.assertEqual(response.status_code, 502)

    @patch("newsletter.admin_views.MauticClient")
    def test_a_provider_conflict_is_reported_as_bad_request(self, client_cls):
        client_cls.return_value.delete_segment.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 409): dependent records"
        )

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 400)

    @patch("newsletter.admin_views.MauticClient")
    def test_a_provider_failure_is_not_reported_as_success(self, client_cls):
        client_cls.return_value.delete_segment.side_effect = TemporaryMauticError(
            "Mautic API request failed (HTTP 503)"
        )

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 502)

    @patch("newsletter.admin_views.MauticClient")
    def test_a_malformed_provider_response_still_fails(self, client_cls):
        client_cls.return_value.delete_segment.side_effect = TemporaryMauticError(
            "Mautic segment deletion returned an invalid response"
        )

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 502)

    def test_delete_requires_authentication(self):
        self.client.force_authenticate(user=None)

        response = self.client.delete(self.detail_url)

        self.assertIn(response.status_code, (401, 403))

    @patch("newsletter.admin_views.MauticClient")
    def test_delete_rejects_non_staff(self, client_cls):
        self.client.force_authenticate(user=self.normal_user)

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 403)
        client_cls.return_value.delete_segment.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_a_subscription_list_segment_is_blocked_before_the_provider_is_called(
        self, client_cls
    ):
        NewsletterCategory.objects.create(
            name="QA Delete Protection List",
            slug="qa-delete-protection-list",
            mautic_segment_id="20",
        )

        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, 409)
        client_cls.return_value.delete_segment.assert_not_called()


def country_catalog():
    """A slice of what the bridge returns for a reference catalog."""
    return {
        "type": "country",
        "total": 4,
        "choices": [
            {"value": "Albania", "label": "Albania"},
            {"value": "India", "label": "India"},
            {"value": "Indonesia", "label": "Indonesia"},
            {"value": "Zimbabwe", "label": "Zimbabwe"},
        ],
    }


class NewsletterAdminMauticSegmentFilterChoicesTests(TestCase):
    """Reference catalogs are served from the provider, a page at a time."""

    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="segment-choices-staff",
            email="segment-choices-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="segment-choices-normal",
            email="segment-choices-normal@example.test",
            password="test-password",
        )
        self.url = reverse("newsletter-admin-mautic-segment-filter-choices")

    def test_choices_require_authentication(self):
        response = self.client.get(self.url, {"source": "country"})

        self.assertIn(response.status_code, (401, 403))

    @patch("newsletter.admin_views.MauticClient")
    def test_choices_reject_non_staff(self, client_cls):
        self.client.force_authenticate(user=self.normal_user)

        response = self.client.get(self.url, {"source": "country"})

        self.assertEqual(response.status_code, 403)
        client_cls.return_value.get_field_type_choices.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_a_supported_source_returns_a_bounded_page(self, client_cls):
        client_cls.return_value.get_field_type_choices.return_value = country_catalog()
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(self.url, {"source": "country", "limit": 2})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["source"], "country")
        self.assertEqual(response.data["total"], 4)
        self.assertEqual(response.data["limit"], 2)
        self.assertEqual(response.data["hasMore"], True)
        self.assertEqual(
            [choice["value"] for choice in response.data["results"]],
            ["Albania", "India"],
        )
        client_cls.return_value.get_field_type_choices.assert_called_once_with("country")

    @patch("newsletter.admin_views.MauticClient")
    def test_the_next_page_continues_and_ends(self, client_cls):
        client_cls.return_value.get_field_type_choices.return_value = country_catalog()
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(
            self.url, {"source": "country", "start": 2, "limit": 2}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["start"], 2)
        self.assertEqual(response.data["hasMore"], False)
        self.assertEqual(
            [choice["value"] for choice in response.data["results"]],
            ["Indonesia", "Zimbabwe"],
        )

    @patch("newsletter.admin_views.MauticClient")
    def test_every_published_source_is_accepted(self, client_cls):
        client_cls.return_value.get_field_type_choices.return_value = country_catalog()
        self.client.force_authenticate(user=self.staff)

        for source in ("country", "region", "timezone", "locale"):
            with self.subTest(source=source):
                response = self.client.get(self.url, {"source": source})

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data["source"], source)

    @patch("newsletter.admin_views.MauticClient")
    def test_an_unsupported_source_is_rejected_before_the_provider_is_called(
        self, client_cls
    ):
        self.client.force_authenticate(user=self.staff)

        for source in ("", "segment_field", "lead", "../country"):
            with self.subTest(source=source):
                response = self.client.get(self.url, {"source": source})

                self.assertEqual(response.status_code, 400)

        client_cls.return_value.get_field_type_choices.assert_not_called()

    @patch("newsletter.admin_views.MauticClient")
    def test_a_search_narrows_the_provider_catalog(self, client_cls):
        client_cls.return_value.get_field_type_choices.return_value = country_catalog()
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(self.url, {"source": "country", "search": "ind"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [choice["value"] for choice in response.data["results"]],
            ["India", "Indonesia"],
        )
        self.assertEqual(response.data["total"], 2)
        self.assertEqual(response.data["hasMore"], False)

    @patch("newsletter.admin_views.MauticClient")
    def test_a_saved_value_is_resolved_without_paging(self, client_cls):
        client_cls.return_value.get_field_type_choices.return_value = country_catalog()
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(
            self.url, {"source": "country", "values": ["India", "Zimbabwe"]}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [choice["value"] for choice in response.data["results"]],
            ["India", "Zimbabwe"],
        )
        self.assertEqual(response.data["hasMore"], False)

    @patch("newsletter.admin_views.MauticClient")
    def test_a_saved_value_the_provider_no_longer_offers_simply_returns_nothing(
        self, client_cls
    ):
        client_cls.return_value.get_field_type_choices.return_value = country_catalog()
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(self.url, {"source": "country", "values": ["Atlantis"]})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["results"], [])

    @patch("newsletter.admin_views.MauticClient")
    def test_the_page_size_is_bounded_however_it_is_asked_for(self, client_cls):
        client_cls.return_value.get_field_type_choices.return_value = country_catalog()
        self.client.force_authenticate(user=self.staff)

        for asked, expected in ((99999, 200), (0, 1), (-5, 1), ("nonsense", 25)):
            with self.subTest(limit=asked):
                response = self.client.get(
                    self.url, {"source": "country", "limit": asked}
                )

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data["limit"], expected)

    @patch("newsletter.admin_views.MauticClient")
    def test_a_nonsense_offset_does_not_fail_the_request(self, client_cls):
        client_cls.return_value.get_field_type_choices.return_value = country_catalog()
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(self.url, {"source": "country", "start": "-40"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["start"], 0)

    @patch("newsletter.admin_views.MauticClient")
    def test_a_permanent_provider_error_is_a_gateway_failure_not_a_client_error(
        self, client_cls
    ):
        # The source was already checked against what the bridge publishes, so a
        # 404 or 400 from the provider means the bridge itself is wrong, not the
        # caller. The segment module reports every provider fault the same way.
        for message in (
            "Mautic API request failed (HTTP 404)",
            "Mautic API request failed (HTTP 400)",
        ):
            with self.subTest(message=message):
                client_cls.return_value.get_field_type_choices.side_effect = (
                    PermanentMauticError(message)
                )
                self.client.force_authenticate(user=self.staff)

                response = self.client.get(self.url, {"source": "country"})

                self.assertEqual(response.status_code, 502)
                self.assertIn("detail", response.data)

    @patch("newsletter.admin_views.MauticClient")
    def test_a_provider_outage_is_a_temporary_failure(self, client_cls):
        client_cls.return_value.get_field_type_choices.side_effect = TemporaryMauticError(
            "Mautic API request failed (HTTP 503)"
        )
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(self.url, {"source": "country"})

        self.assertEqual(response.status_code, 502)

    @patch("newsletter.admin_views.MauticClient")
    def test_a_malformed_provider_catalog_is_survivable(self, client_cls):
        client_cls.return_value.get_field_type_choices.return_value = {
            "choices": [
                {"label": "no value at all"},
                "not a row",
                {"value": "India", "label": "India"},
            ]
        }
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(self.url, {"source": "country"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [choice["value"] for choice in response.data["results"]], ["India"]
        )

    @patch("newsletter.admin_views.MauticClient")
    def test_no_catalog_is_served_when_the_provider_returns_none(self, client_cls):
        # ECP keeps no fallback list of its own: an empty provider means an
        # empty answer, never a hardcoded catalog.
        client_cls.return_value.get_field_type_choices.return_value = {"choices": []}
        self.client.force_authenticate(user=self.staff)

        response = self.client.get(self.url, {"source": "country"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["results"], [])
        self.assertEqual(response.data["total"], 0)
