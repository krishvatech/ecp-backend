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


class ResourcePermissionsRegressionTests(APITestCase):
    def setUp(self):
        from django.contrib.auth.models import Group
        
        # 1. Platform Admin
        self.platform_admin = User.objects.create_user(
            username="platform-admin",
            email="platform-admin@example.com",
            password="test-pass-123",
            is_staff=True,
            is_superuser=True,
        )
        self.platform_admin_group, _ = Group.objects.get_or_create(name='platform_admin')
        self.platform_admin.groups.add(self.platform_admin_group)
        
        # 2. Staff user (non platform-admin)
        self.staff_user = User.objects.create_user(
            username="staff-user",
            email="staff-user@example.com",
            password="test-pass-123",
            is_staff=True,
        )

        # 3. Community Owner / creator (non platform-admin)
        self.community_owner = User.objects.create_user(
            username="comm-owner",
            email="comm-owner@example.com",
            password="test-pass-123",
        )
        
        # 4. Community Member (non platform-admin)
        self.community_member = User.objects.create_user(
            username="comm-member",
            email="comm-member@example.com",
            password="test-pass-123",
        )
        
        # 5. Normal User
        self.normal_user = User.objects.create_user(
            username="norm-user",
            email="norm-user@example.com",
            password="test-pass-123",
        )

        # Community & Event setup
        self.community = Community.objects.create(
            name="Target Community",
            owner=self.community_owner,
        )
        self.community_member.community.add(self.community)
        self.normal_user.community.add(self.community)
        self.staff_user.community.add(self.community)
        self.platform_admin.community.add(self.community)
        
        self.event = Event.objects.create(
            community=self.community,
            title="Event 1",
            is_free=True,
            created_by=self.community_owner
        )

    def test_guest_permissions(self):
        # List denied (401)
        response = self.client.get("/api/content/resources/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        # Create denied (401)
        response = self.client.post("/api/content/resources/", {"title": "Guest Resource"})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_normal_user_cannot_write(self):
        self.client.force_authenticate(self.normal_user)
        
        # Create returns 403
        response = self.client.post("/api/content/resources/", {
            "title": "Test Resource",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com",
            "event_id": self.event.id
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Setup resource to test update/delete
        resource = Resource.objects.create(
            community=self.community,
            event=self.event,
            title="Existing Resource",
            type=Resource.TYPE_LINK,
            link_url="https://example.com",
            is_published=True,
            uploaded_by=self.platform_admin
        )
        
        # Update returns 403
        response = self.client.put(f"/api/content/resources/{resource.id}/", {
            "title": "Updated",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com",
            "event_id": self.event.id
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Delete returns 403
        response = self.client.delete(f"/api/content/resources/{resource.id}/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_community_member_cannot_create(self):
        self.client.force_authenticate(self.community_member)
        response = self.client.post("/api/content/resources/", {
            "title": "Member Resource",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com",
            "event_id": self.event.id
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_community_owner_cannot_write(self):
        self.client.force_authenticate(self.community_owner)
        
        # Create returns 403
        response = self.client.post("/api/content/resources/", {
            "title": "Owner Resource",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com",
            "event_id": self.event.id
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        resource = Resource.objects.create(
            community=self.community,
            event=self.event,
            title="Owner Existing",
            type=Resource.TYPE_LINK,
            link_url="https://example.com",
            is_published=True,
            uploaded_by=self.platform_admin
        )

        # Update returns 403
        response = self.client.put(f"/api/content/resources/{resource.id}/", {
            "title": "Updated Title",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com",
            "event_id": self.event.id
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Delete returns 403
        response = self.client.delete(f"/api/content/resources/{resource.id}/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_original_uploader_cannot_write(self):
        # Create resource uploaded by normal user (maybe previously allowed)
        resource = Resource.objects.create(
            community=self.community,
            event=self.event,
            title="Uploaded by norm",
            type=Resource.TYPE_LINK,
            link_url="https://example.com",
            is_published=True,
            uploaded_by=self.normal_user
        )
        
        self.client.force_authenticate(self.normal_user)
        
        # Update returns 403
        response = self.client.put(f"/api/content/resources/{resource.id}/", {
            "title": "Hack title",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com",
            "event_id": self.event.id
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Delete returns 403
        response = self.client.delete(f"/api/content/resources/{resource.id}/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_staff_user_read_only(self):
        self.client.force_authenticate(self.staff_user)
        
        # Setup resource
        resource = Resource.objects.create(
            community=self.community,
            event=self.event,
            title="Staff Read Test",
            type=Resource.TYPE_LINK,
            link_url="https://example.com",
            is_published=True,
            uploaded_by=self.platform_admin
        )
        
        # 1. Without registration: list succeeds but is empty (since staff user is treated same as normal user)
        response = self.client.get("/api/content/resources/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertNotIn(resource.id, ids)
        
        # Detail returns 404
        response = self.client.get(f"/api/content/resources/{resource.id}/")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        
        # 2. Add registration for staff user
        EventRegistration.objects.create(
            user=self.staff_user,
            event=self.event,
            status="registered",
            attendee_status="confirmed",
            is_banned=False
        )
        
        # List succeeds and contains the resource
        response = self.client.get("/api/content/resources/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ids = [r["id"] for r in response.data.get("results", response.data)]
        self.assertIn(resource.id, ids)
        
        # Detail succeeds (200)
        response = self.client.get(f"/api/content/resources/{resource.id}/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # 3. Write requests still return 403
        # Create returns 403
        response = self.client.post("/api/content/resources/", {
            "title": "Staff Write",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com",
            "event_id": self.event.id
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Update returns 403
        response = self.client.put(f"/api/content/resources/{resource.id}/", {
            "title": "Staff Update",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com",
            "event_id": self.event.id
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Delete returns 403
        response = self.client.delete(f"/api/content/resources/{resource.id}/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_platform_admin_full_crud(self):
        self.client.force_authenticate(self.platform_admin)
        
        # 1. Create succeeds
        response = self.client.post("/api/content/resources/", {
            "title": "Admin Created",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com",
            "event_id": self.event.id
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        resource_id = response.data["id"]
        
        # 2. List succeeds
        response = self.client.get("/api/content/resources/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # 3. Update succeeds
        response = self.client.put(f"/api/content/resources/{resource_id}/", {
            "title": "Admin Updated",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com/updated",
            "event_id": self.event.id
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["title"], "Admin Updated")
        
        # 4. Soft Delete succeeds
        response = self.client.delete(f"/api/content/resources/{resource_id}/")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        
        # 5. Row remains in database but normal query excludes it
        retained = Resource.all_objects.get(pk=resource_id)
        self.assertTrue(retained.is_deleted)
        self.assertFalse(Resource.objects.filter(pk=resource_id).exists())

    def test_missing_event_during_create(self):
        self.client.force_authenticate(self.platform_admin)
        
        # Missing event_id -> receives 400
        response = self.client.post("/api/content/resources/", {
            "title": "No Event",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("An event is required for every resource.", str(response.data))

    def test_client_submits_only_community_id(self):
        self.client.force_authenticate(self.platform_admin)
        
        # Only community_id -> receives 400
        response = self.client.post("/api/content/resources/", {
            "title": "Community Only",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com",
            "community_id": self.community.id
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("An event is required for every resource.", str(response.data))

    def test_client_submits_mismatched_community(self):
        self.client.force_authenticate(self.platform_admin)
        
        other_community = Community.objects.create(
            name="Other Comm",
            owner=self.community_owner
        )
        
        # Client submits event AND other mismatched community
        response = self.client.post("/api/content/resources/", {
            "title": "Mismatched",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com",
            "event_id": self.event.id,
            "community_id": other_community.id
        })
        
        # Saved community MUST equal event.community (i.e. self.community)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["community_id"], self.community.id)
