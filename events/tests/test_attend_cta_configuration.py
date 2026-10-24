"""IPDT-776: safe and backward-compatible per-event Attend CTA configuration.

No database access is required for these serializer validation tests. The new
columns still need a reviewed migration in the deployment environment.
"""
from django.test import SimpleTestCase
from rest_framework import serializers

from events.models import Event
from events.serializers import EventSerializer, PublicEventSerializer


class AttendConfigurationSerializerTests(SimpleTestCase):
    def test_defaults_do_not_override_existing_registration(self):
        event = Event()
        self.assertEqual(event.attend_primary_button_url, "")
        self.assertEqual(event.attend_secondary_button_text, "")
        self.assertEqual(event.attend_primary_button_text, "Register Here")

    def test_event_detail_and_public_serializers_expose_configuration(self):
        fields = {
            "price_label",
            "attend_primary_button_text",
            "attend_primary_button_url",
            "attend_secondary_button_text",
        }
        self.assertTrue(fields.issubset(EventSerializer().fields.keys()))
        self.assertTrue(fields.issubset(PublicEventSerializer().fields.keys()))

    def test_https_destination_accepted_and_blank_clears(self):
        serializer = EventSerializer()
        self.assertEqual(
            serializer.validate_attend_primary_button_url(
                " https://manda.sg/event/m-and-a-in-asia-2026/#maa-pricing "
            ),
            "https://manda.sg/event/m-and-a-in-asia-2026/#maa-pricing",
        )
        self.assertEqual(serializer.validate_attend_primary_button_url(""), "")

    def test_unsafe_destinations_rejected(self):
        serializer = EventSerializer()
        for url in (
            "javascript:alert(1)",
            "http://manda.sg/register",
            "ftp://example.org/register",
            "https://user:password@example.org/register",
        ):
            with self.subTest(url=url), self.assertRaises(serializers.ValidationError):
                serializer.validate_attend_primary_button_url(url)
