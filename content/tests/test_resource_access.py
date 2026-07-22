from datetime import timedelta
from unittest.mock import patch, MagicMock

from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from content.models import Resource
from community.models import Community
from events.models import Event, EventRegistration
from orders.models import Order, OrderItem


class ResourceAccessTests(APITestCase):
    def setUp(self):
        # Create normal user
        self.user = User.objects.create_user(
            username="normal-user",
            email="normal-user@example.com",
            password="test-pass-123",
        )
        
        # Create another normal user
        self.other_user = User.objects.create_user(
            username="other-user",
            email="other-user@example.com",
            password="other-pass-123",
        )

        # Create staff/owner
        self.owner = User.objects.create_user(
            username="resource-owner",
            email="resource-owner@example.com",
            password="test-pass-123",
            is_staff=True,
        )
        
        # Create community
        self.community = Community.objects.create(
            name="Test Community",
            owner=self.owner,
        )
        # Add user to community
        self.user.community.add(self.community)

    def _create_resource(self, **overrides):
        values = {
            "community": self.community,
            "title": "Test resource",
            "description": "Test description",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com/resource",
            "is_published": True,
            "uploaded_by": self.owner,
        }
        values.update(overrides)
        return Resource.all_objects.create(**values)

    @patch('requests.get')
    def test_free_event_confirmed_registration(self, mock_get):
        """Case 1: Free event + active confirmed registration is allowed"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"fake file data"
        mock_response.headers = {'content-type': 'application/pdf'}
        mock_get.return_value = mock_response

        # Create free event
        event = Event.objects.create(
            community=self.community,
            title="Free Event",
            is_free=True,
            created_by=self.owner
        )
        
        # Create resource
        resource = self._create_resource(event=event, type=Resource.TYPE_FILE, file="event_resources/Free_Event/test.pdf")

        # Register user (active, confirmed, not banned)
        EventRegistration.objects.create(
            user=self.user,
            event=event,
            status="registered",
            attendee_status="confirmed",
            is_banned=False
        )

        self.client.force_authenticate(self.user)

        # 1. Resource in list
        response = self.client.get("/api/content/resources/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertIn(resource.id, ids)

        # 2. Detail allowed
        detail_response = self.client.get(f"/api/content/resources/{resource.id}/")
        self.assertEqual(detail_response.status_code, status.HTTP_200_OK)

        # 3. Download allowed
        download_response = self.client.get(f"/api/content/resources/{resource.id}/download/")
        self.assertEqual(download_response.status_code, status.HTTP_200_OK)

    def test_free_event_cancelled_registration(self):
        """Case 2: Free event + cancelled registration is denied"""
        event = Event.objects.create(
            community=self.community,
            title="Free Event",
            is_free=True,
            created_by=self.owner
        )
        resource = self._create_resource(event=event)
        
        # Cancelled registration
        EventRegistration.objects.create(
            user=self.user,
            event=event,
            status="cancelled",
            attendee_status="confirmed",
            is_banned=False
        )
        
        self.client.force_authenticate(self.user)
        
        # 1. List denied
        response = self.client.get("/api/content/resources/")
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertNotIn(resource.id, ids)
        
        # 2. Detail denied
        detail_response = self.client.get(f"/api/content/resources/{resource.id}/")
        self.assertEqual(detail_response.status_code, status.HTTP_404_NOT_FOUND)
        
        # 3. Download denied
        download_response = self.client.get(f"/api/content/resources/{resource.id}/download/")
        self.assertEqual(download_response.status_code, status.HTTP_404_NOT_FOUND)

    def test_paid_event_payment_pending(self):
        """Case 3 & 5: Paid event + registration exists but attendee_status payment_pending is denied"""
        event = Event.objects.create(
            community=self.community,
            title="Paid Event",
            is_free=False,
            created_by=self.owner
        )
        resource = self._create_resource(event=event)
        
        # Registration is payment_pending
        EventRegistration.objects.create(
            user=self.user,
            event=event,
            status="registered",
            attendee_status="payment_pending",
            is_banned=False
        )
        
        self.client.force_authenticate(self.user)
        
        response = self.client.get("/api/content/resources/")
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertNotIn(resource.id, ids)
        
        detail_response = self.client.get(f"/api/content/resources/{resource.id}/")
        self.assertEqual(detail_response.status_code, status.HTTP_404_NOT_FOUND)

    def test_paid_event_order_pending(self):
        """Case 4: Paid event + Order.status pending is denied"""
        event = Event.objects.create(
            community=self.community,
            title="Paid Event",
            is_free=False,
            created_by=self.owner
        )
        resource = self._create_resource(event=event)
        
        # Registration confirmed but order is pending
        EventRegistration.objects.create(
            user=self.user,
            event=event,
            status="registered",
            attendee_status="confirmed",
            is_banned=False
        )
        
        order = Order.objects.create(
            user=self.user,
            status="pending",
            paid_at=None
        )
        OrderItem.objects.create(
            order=order,
            event=event,
            unit_price=10.0,
            line_total=10.0
        )
        
        self.client.force_authenticate(self.user)
        
        response = self.client.get("/api/content/resources/")
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertNotIn(resource.id, ids)
        
        detail_response = self.client.get(f"/api/content/resources/{resource.id}/")
        self.assertEqual(detail_response.status_code, status.HTTP_404_NOT_FOUND)

    @patch('requests.get')
    def test_paid_event_paid_order(self, mock_get):
        """Case 6: Paid event + admin-confirmed paid order is allowed"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"fake file data"
        mock_response.headers = {'content-type': 'application/pdf'}
        mock_get.return_value = mock_response

        event = Event.objects.create(
            community=self.community,
            title="Paid Event",
            is_free=False,
            created_by=self.owner
        )
        resource = self._create_resource(event=event, type=Resource.TYPE_FILE, file="event_resources/Paid_Event/test.pdf")
        
        # Registration confirmed
        EventRegistration.objects.create(
            user=self.user,
            event=event,
            status="registered",
            attendee_status="confirmed",
            is_banned=False
        )
        
        # Paid order
        order = Order.objects.create(
            user=self.user,
            status="paid",
            paid_at=timezone.now()
        )
        OrderItem.objects.create(
            order=order,
            event=event,
            unit_price=10.0,
            line_total=10.0
        )
        
        self.client.force_authenticate(self.user)
        
        # 1. Resource in list
        response = self.client.get("/api/content/resources/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertIn(resource.id, ids)

        # 2. Detail allowed
        detail_response = self.client.get(f"/api/content/resources/{resource.id}/")
        self.assertEqual(detail_response.status_code, status.HTTP_200_OK)

        # 3. Download allowed
        download_response = self.client.get(f"/api/content/resources/{resource.id}/download/")
        self.assertEqual(download_response.status_code, status.HTTP_200_OK)

    def test_paid_event_cancelled_registration_old_paid_order(self):
        """Case 7: Paid event + cancelled registration but old paid order exists is denied"""
        event = Event.objects.create(
            community=self.community,
            title="Paid Event",
            is_free=False,
            created_by=self.owner
        )
        resource = self._create_resource(event=event)
        
        # Cancelled registration
        EventRegistration.objects.create(
            user=self.user,
            event=event,
            status="cancelled",
            attendee_status="confirmed",
            is_banned=False
        )
        
        # Old paid order
        order = Order.objects.create(
            user=self.user,
            status="paid",
            paid_at=timezone.now()
        )
        OrderItem.objects.create(
            order=order,
            event=event,
            unit_price=10.0,
            line_total=10.0
        )
        
        self.client.force_authenticate(self.user)
        
        response = self.client.get("/api/content/resources/")
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertNotIn(resource.id, ids)
        
        detail_response = self.client.get(f"/api/content/resources/{resource.id}/")
        self.assertEqual(detail_response.status_code, status.HTTP_404_NOT_FOUND)

    def test_paid_event_other_user(self):
        """Case 8: Paid event + paid registration for another user is denied"""
        event = Event.objects.create(
            community=self.community,
            title="Paid Event",
            is_free=False,
            created_by=self.owner
        )
        resource = self._create_resource(event=event)
        
        # Registration and Order for other_user
        EventRegistration.objects.create(
            user=self.other_user,
            event=event,
            status="registered",
            attendee_status="confirmed",
            is_banned=False
        )
        order = Order.objects.create(
            user=self.other_user,
            status="paid",
            paid_at=timezone.now()
        )
        OrderItem.objects.create(
            order=order,
            event=event,
            unit_price=10.0,
            line_total=10.0
        )
        
        # Authenticate self.user (who has no registration or order)
        self.client.force_authenticate(self.user)
        
        response = self.client.get("/api/content/resources/")
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertNotIn(resource.id, ids)

    def test_soft_deleted_resource(self):
        """Case 10: Soft-deleted resource is denied even with a paid order"""
        event = Event.objects.create(
            community=self.community,
            title="Paid Event",
            is_free=False,
            created_by=self.owner
        )
        # Create resource that is soft-deleted
        resource = self._create_resource(event=event, is_deleted=True, deleted_at=timezone.now())
        
        EventRegistration.objects.create(
            user=self.user,
            event=event,
            status="registered",
            attendee_status="confirmed",
            is_banned=False
        )
        order = Order.objects.create(
            user=self.user,
            status="paid",
            paid_at=timezone.now()
        )
        OrderItem.objects.create(
            order=order,
            event=event,
            unit_price=10.0,
            line_total=10.0
        )
        
        self.client.force_authenticate(self.user)
        
        response = self.client.get("/api/content/resources/")
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertNotIn(resource.id, ids)
        
        detail_response = self.client.get(f"/api/content/resources/{resource.id}/")
        self.assertEqual(detail_response.status_code, status.HTTP_404_NOT_FOUND)

    def test_unpublished_resource(self):
        """Case 11: Unpublished resource is denied for normal users"""
        event = Event.objects.create(
            community=self.community,
            title="Paid Event",
            is_free=False,
            created_by=self.owner
        )
        # Create unpublished resource
        resource = self._create_resource(event=event, is_published=False)
        
        EventRegistration.objects.create(
            user=self.user,
            event=event,
            status="registered",
            attendee_status="confirmed",
            is_banned=False
        )
        order = Order.objects.create(
            user=self.user,
            status="paid",
            paid_at=timezone.now()
        )
        OrderItem.objects.create(
            order=order,
            event=event,
            unit_price=10.0,
            line_total=10.0
        )
        
        self.client.force_authenticate(self.user)
        
        response = self.client.get("/api/content/resources/")
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertNotIn(resource.id, ids)

    def test_community_resource_access(self):
        """Case 12: Community-level resource is accessible by community members"""
        # Create community level resource (event=None)
        resource = self._create_resource(event=None)
        
        # User is in community, so they should be able to access it
        self.client.force_authenticate(self.user)
        response = self.client.get("/api/content/resources/")
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertIn(resource.id, ids)
        
        # Check other_user who is NOT in the community
        self.client.force_authenticate(self.other_user)
        response = self.client.get("/api/content/resources/")
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertNotIn(resource.id, ids)

    def test_archived_event_resource_denied(self):
        """Case 13: Archived/deleted event resources are denied"""
        event = Event.objects.create(
            community=self.community,
            title="Archived Event",
            status="archived",
            created_by=self.owner
        )
        resource = self._create_resource(event=event)
        
        EventRegistration.objects.create(
            user=self.user,
            event=event,
            status="registered",
            attendee_status="confirmed",
            is_banned=False
        )
        
        self.client.force_authenticate(self.user)
        response = self.client.get("/api/content/resources/")
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertNotIn(resource.id, ids)
