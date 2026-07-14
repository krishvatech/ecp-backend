from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient

from community.models import Community
from events.models import Event, EventBadgeLabel, EventRegistration


class EventBadgeLabelSoftDeleteTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username='badge-owner',
            email='badge-owner@example.com',
            password='pass1234',
        )
        self.participant = User.objects.create_user(
            username='badge-participant',
            email='badge-participant@example.com',
            password='pass1234',
        )
        self.community = Community.objects.create(
            name='Badge Test Community',
            owner=self.owner,
        )
        self.event = Event.objects.create(
            title='Badge Test Event',
            slug='badge-test-event',
            community=self.community,
            created_by=self.owner,
        )
        self.registration = EventRegistration.objects.create(
            event=self.event,
            user=self.participant,
        )
        self.label = EventBadgeLabel.objects.create(
            event=self.event,
            name='VIP',
            color='#123456',
        )
        self.registration.badge_labels.add(self.label)
        self.client = APIClient()
        self.client.force_authenticate(self.owner)

    def test_delete_deactivates_label_and_preserves_assignment(self):
        response = self.client.delete(
            f'/api/event-badge-labels/{self.label.id}/',
            {'reason': 'No longer used'},
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.label.refresh_from_db()
        self.assertFalse(self.label.is_active)
        self.assertEqual(self.label.deactivation_reason, 'No longer used')
        self.assertEqual(self.label.deactivated_by_id, self.owner.id)
        self.assertTrue(self.registration.badge_labels.filter(id=self.label.id).exists())

        list_response = self.client.get(
            '/api/event-badge-labels/',
            {'event_id': self.event.id},
        )
        self.assertEqual(list_response.status_code, 200)
        results = list_response.data.get('results', list_response.data)
        self.assertEqual(results, [])

    def test_deactivated_label_cannot_be_assigned(self):
        self.label.is_active = False
        self.label.save(update_fields=['is_active'])

        response = self.client.post(
            f'/api/event-registrations/{self.registration.id}/assign-labels/',
            {'label_ids': [self.label.id]},
            format='json',
        )
        self.assertEqual(response.status_code, 400)

    def test_recreating_same_label_restores_existing_row(self):
        self.label.is_active = False
        self.label.save(update_fields=['is_active'])

        response = self.client.post(
            '/api/event-badge-labels/',
            {
                'event_id': self.event.id,
                'name': 'VIP',
                'color': '#abcdef',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['restored'])
        self.label.refresh_from_db()
        self.assertTrue(self.label.is_active)
        self.assertEqual(self.label.color, '#abcdef')
        self.assertEqual(
            EventBadgeLabel.objects.filter(event=self.event, name='VIP').count(),
            1,
        )
        self.assertTrue(self.registration.badge_labels.filter(id=self.label.id).exists())
