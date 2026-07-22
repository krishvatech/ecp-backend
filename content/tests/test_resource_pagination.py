from datetime import timedelta
from unittest.mock import patch, MagicMock
from django.contrib.auth.models import User, Group
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from content.models import Resource
from community.models import Community
from events.models import Event, EventRegistration
from orders.models import Order, OrderItem


class ResourcePaginationTests(APITestCase):
    def setUp(self):
        # Create normal user
        self.user = User.objects.create_user(
            username="normal-user",
            email="normal-user@example.com",
            password="test-pass-123",
        )

        # Create staff user
        self.staff_user = User.objects.create_user(
            username="staff-user",
            email="staff-user@example.com",
            password="staff-pass-123",
            is_staff=True,
        )

        # Create platform admin
        self.platform_admin = User.objects.create_user(
            username="platform-admin",
            email="platform-admin@example.com",
            password="admin-pass-123",
        )
        self.platform_admin_group, _ = Group.objects.get_or_create(name='platform_admin')
        self.platform_admin.groups.add(self.platform_admin_group)

        # Create community
        self.community = Community.objects.create(
            name="Pagination Test Community",
            owner=self.platform_admin,
        )
        
        # Add normal user to community
        self.user.community.add(self.community)
        self.staff_user.community.add(self.community)

    def _create_resource(self, **overrides):
        values = {
            "community": self.community,
            "title": "Test Resource",
            "description": "Test Description",
            "type": Resource.TYPE_LINK,
            "link_url": "https://example.com/resource",
            "is_published": True,
            "uploaded_by": self.platform_admin,
        }
        values.update(overrides)
        return Resource.all_objects.create(**values)

    def test_a_platform_admin_basic_pagination(self):
        """Create 25 active Resources and check platform admin pagination pages."""
        event = Event.objects.create(
            community=self.community,
            title="Pagination Event",
            is_free=True,
            created_by=self.platform_admin,
        )
        for i in range(25):
            self._create_resource(title=f"Resource {i}", event=event)

        self.client.force_authenticate(self.platform_admin)

        # Page 1
        response = self.client.get("/api/content/resources/?limit=10&offset=0")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 25)
        self.assertEqual(len(response.data["results"]), 10)

        # Page 2
        response2 = self.client.get("/api/content/resources/?limit=10&offset=10")
        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        self.assertEqual(response2.data["count"], 25)
        self.assertEqual(len(response2.data["results"]), 10)

        # Page 3
        response3 = self.client.get("/api/content/resources/?limit=10&offset=20")
        self.assertEqual(response3.status_code, status.HTTP_200_OK)
        self.assertEqual(response3.data["count"], 25)
        self.assertEqual(len(response3.data["results"]), 5)

    def test_b_no_overlap(self):
        """Confirm pages do not overlap and include all 25 resources."""
        event = Event.objects.create(
            community=self.community,
            title="Pagination Event",
            is_free=True,
            created_by=self.platform_admin,
        )
        resources = [self._create_resource(title=f"Resource {i}", event=event) for i in range(25)]
        resource_ids = {r.id for r in resources}

        self.client.force_authenticate(self.platform_admin)

        r1 = self.client.get("/api/content/resources/?limit=10&offset=0").data["results"]
        r2 = self.client.get("/api/content/resources/?limit=10&offset=10").data["results"]
        r3 = self.client.get("/api/content/resources/?limit=10&offset=20").data["results"]

        ids_p1 = {item["id"] for item in r1}
        ids_p2 = {item["id"] for item in r2}
        ids_p3 = {item["id"] for item in r3}

        # Check no overlap
        self.assertTrue(ids_p1.isdisjoint(ids_p2))
        self.assertTrue(ids_p1.isdisjoint(ids_p3))
        self.assertTrue(ids_p2.isdisjoint(ids_p3))

        # Check union
        all_paginated_ids = all_paginated_ids = ids_p1.union(ids_p2).union(ids_p3)
        self.assertEqual(all_paginated_ids, resource_ids)

    def test_c_stable_timestamp_ordering(self):
        """Create several resources with the same created_at and verify stable ordering using ID as tie-breaker."""
        event = Event.objects.create(
            community=self.community,
            title="Pagination Event",
            is_free=True,
            created_by=self.platform_admin,
        )
        fixed_time = timezone.now() - timedelta(days=1)
        r_list = []
        for i in range(5):
            r = self._create_resource(title=f"Resource {i}", event=event)
            Resource.objects.filter(id=r.id).update(created_at=fixed_time)
            r.refresh_from_db()
            r_list.append(r)

        self.client.force_authenticate(self.platform_admin)

        # 1. Newest ordering (ordering=-created_at,-id)
        response_newest = self.client.get("/api/content/resources/?ordering=-created_at,-id&limit=5&offset=0")
        self.assertEqual(response_newest.status_code, status.HTTP_200_OK)
        results_newest = response_newest.data["results"]
        newest_ids = [item["id"] for item in results_newest]
        # Should be ordered by descending ID since created_at is identical
        expected_newest = sorted([r.id for r in r_list], reverse=True)
        self.assertEqual(newest_ids, expected_newest)

        # 2. Oldest ordering (ordering=created_at,id)
        response_oldest = self.client.get("/api/content/resources/?ordering=created_at,id&limit=5&offset=0")
        self.assertEqual(response_oldest.status_code, status.HTTP_200_OK)
        results_oldest = response_oldest.data["results"]
        oldest_ids = [item["id"] for item in results_oldest]
        expected_oldest = sorted([r.id for r in r_list])
        self.assertEqual(oldest_ids, expected_oldest)

        # 3. Repeated requests return same order
        response_repeat = self.client.get("/api/content/resources/?ordering=-created_at,-id&limit=5&offset=0")
        repeat_ids = [item["id"] for item in response_repeat.data["results"]]
        self.assertEqual(repeat_ids, newest_ids)

    def test_d_soft_deleted_resources(self):
        """Verify soft-deleted resources are excluded from count, pages, type filtering, and searches."""
        event = Event.objects.create(
            community=self.community,
            title="Pagination Event",
            is_free=True,
            created_by=self.platform_admin,
        )
        # 3 active resources, 2 soft-deleted
        self._create_resource(title="Active File 1", event=event, type="file")
        self._create_resource(title="Active File 2", event=event, type="file")
        self._create_resource(title="Active Link 1", event=event, type="link")
        
        del1 = self._create_resource(title="Deleted File 1", event=event, type="file")
        del1.soft_delete(user=self.platform_admin, reason="outdated")
        del2 = self._create_resource(title="Deleted Video 1", event=event, type="video")
        del2.soft_delete(user=self.platform_admin, reason="outdated")

        self.client.force_authenticate(self.platform_admin)

        response = self.client.get("/api/content/resources/")
        self.assertEqual(response.data["count"], 3)
        results_ids = [item["id"] for item in response.data["results"]]
        self.assertNotIn(del1.id, results_ids)
        self.assertNotIn(del2.id, results_ids)

        # Search excludes deleted
        resp_search = self.client.get("/api/content/resources/?search=Deleted")
        self.assertEqual(resp_search.data["count"], 0)

        # Type filter excludes deleted
        resp_type = self.client.get("/api/content/resources/?type=video")
        self.assertEqual(resp_type.data["count"], 0)

    def test_e_unpublished_resources(self):
        """Confirm unpublished resources visibility adheres to user role rules."""
        event = Event.objects.create(
            community=self.community,
            title="Pagination Event",
            is_free=True,
            created_by=self.platform_admin,
        )
        # Create published and unpublished resources
        pub = self._create_resource(title="Published Link", event=event, is_published=True)
        unpub = self._create_resource(title="Unpublished Link", event=event, is_published=False)

        # Register normal user
        EventRegistration.objects.create(
            user=self.user,
            event=event,
            status="registered",
            attendee_status="confirmed",
            is_banned=False
        )

        # Ordinary user gets only published
        self.client.force_authenticate(self.user)
        res_user = self.client.get("/api/content/resources/")
        user_ids = [item["id"] for item in res_user.data["results"]]
        self.assertIn(pub.id, user_ids)
        self.assertNotIn(unpub.id, user_ids)

        # Admin gets both
        self.client.force_authenticate(self.platform_admin)
        res_admin = self.client.get("/api/content/resources/")
        admin_ids = [item["id"] for item in res_admin.data["results"]]
        self.assertIn(pub.id, admin_ids)
        self.assertIn(unpub.id, admin_ids)

    def test_f_search_pagination(self):
        """Test pagination and count with search active, excluding unauthorized/deleted."""
        event = Event.objects.create(
            community=self.community,
            title="Pagination Event",
            is_free=True,
            created_by=self.platform_admin,
        )
        # Create 15 matching titles, 5 non-matching
        for i in range(15):
            self._create_resource(title=f"Target Search Resource {i}", event=event)
        for i in range(5):
            self._create_resource(title=f"Other Resource {i}", event=event)

        # 1 deleted matching resource
        del_res = self._create_resource(title="Target Search Deleted", event=event)
        del_res.soft_delete(user=self.platform_admin, reason="test")

        self.client.force_authenticate(self.platform_admin)

        # Page 1 search
        response1 = self.client.get("/api/content/resources/?search=Target Search&limit=10&offset=0")
        self.assertEqual(response1.data["count"], 15)
        self.assertEqual(len(response1.data["results"]), 10)
        for item in response1.data["results"]:
            self.assertIn("Target Search", item["title"])

        # Page 2 search
        response2 = self.client.get("/api/content/resources/?search=Target Search&limit=10&offset=10")
        self.assertEqual(response2.data["count"], 15)
        self.assertEqual(len(response2.data["results"]), 5)

    def test_g_type_filter_pagination(self):
        """Verify type filters return expected counts and results."""
        event = Event.objects.create(
            community=self.community,
            title="Pagination Event",
            is_free=True,
            created_by=self.platform_admin,
        )
        self._create_resource(title="File 1", event=event, type="file")
        self._create_resource(title="File 2", event=event, type="file")
        self._create_resource(title="Link 1", event=event, type="link")
        self._create_resource(title="Video 1", event=event, type="video")

        self.client.force_authenticate(self.platform_admin)

        resp_file = self.client.get("/api/content/resources/?type=file")
        self.assertEqual(resp_file.data["count"], 2)
        self.assertEqual(resp_file.data["results"][0]["type"], "file")

        resp_link = self.client.get("/api/content/resources/?type=link")
        self.assertEqual(resp_link.data["count"], 1)

        resp_video = self.client.get("/api/content/resources/?type=video")
        self.assertEqual(resp_video.data["count"], 1)

    def test_h_normal_user_access_before_pagination(self):
        """Confirm a normal user only receives resources from eligible (confirmed free, paid-confirmed) events."""
        # Community setup and events
        free_ev = Event.objects.create(community=self.community, title="Free Event", is_free=True)
        paid_ev = Event.objects.create(community=self.community, title="Paid Event", is_free=False)
        unregistered_ev = Event.objects.create(community=self.community, title="Unregistered", is_free=True)

        res_free = self._create_resource(title="Free Resource", event=free_ev)
        res_paid = self._create_resource(title="Paid Resource", event=paid_ev)
        res_unreg = self._create_resource(title="Unreg Resource", event=unregistered_ev)

        # 1. Register for free event - confirmed
        EventRegistration.objects.create(
            user=self.user, event=free_ev, status="registered", attendee_status="confirmed", is_banned=False
        )

        # 2. Register for paid event - status registered, attendee_status payment_pending (no paid order yet)
        reg_paid = EventRegistration.objects.create(
            user=self.user, event=paid_ev, status="registered", attendee_status="payment_pending", is_banned=False
        )

        self.client.force_authenticate(self.user)

        # Should only see Free Resource
        response1 = self.client.get("/api/content/resources/")
        self.assertEqual(response1.data["count"], 1)
        self.assertEqual(response1.data["results"][0]["id"], res_free.id)

        # Now update paid event registration to paid
        # Set up a paid order
        order = Order.objects.create(user=self.user, status="paid", paid_at=timezone.now())
        OrderItem.objects.create(order=order, event=paid_ev, price=50.0)
        
        reg_paid.attendee_status = "confirmed"
        reg_paid.save()

        # Should see both Free and Paid resources
        response2 = self.client.get("/api/content/resources/")
        self.assertEqual(response2.data["count"], 2)
        resource_ids = {item["id"] for item in response2.data["results"]}
        self.assertIn(res_free.id, resource_ids)
        self.assertIn(res_paid.id, resource_ids)
        self.assertNotIn(res_unreg.id, resource_ids)

    def test_i_ordinary_staff_access(self):
        """Confirm that standard staff follows the exact same eligibility rules as end-users."""
        free_ev = Event.objects.create(community=self.community, title="Free Event", is_free=True)
        res_free = self._create_resource(title="Free Resource", event=free_ev)

        self.client.force_authenticate(self.staff_user)

        # Not registered yet
        response = self.client.get("/api/content/resources/")
        self.assertEqual(response.data["count"], 0)

        # Registered & confirmed
        EventRegistration.objects.create(
            user=self.staff_user, event=free_ev, status="registered", attendee_status="confirmed", is_banned=False
        )

        response2 = self.client.get("/api/content/resources/")
        self.assertEqual(response2.data["count"], 1)
        self.assertEqual(response2.data["results"][0]["id"], res_free.id)

    def test_j_platform_admin_access(self):
        """Confirm platform admin receives all active resources directly without registration checks."""
        free_ev = Event.objects.create(community=self.community, title="Free Event", is_free=True)
        res_free = self._create_resource(title="Free Resource", event=free_ev)

        self.client.force_authenticate(self.platform_admin)

        response = self.client.get("/api/content/resources/")
        self.assertEqual(response.data["count"], 1)
        self.assertEqual(response.data["results"][0]["id"], res_free.id)

    def test_k_maximum_limit(self):
        """Verify that requests for large limits are capped at the view's max_limit configuration (100)."""
        event = Event.objects.create(
            community=self.community,
            title="Pagination Event",
            is_free=True,
            created_by=self.platform_admin,
        )
        # Create 120 resources
        for i in range(120):
            self._create_resource(title=f"Resource {i}", event=event)

        self.client.force_authenticate(self.platform_admin)

        response = self.client.get("/api/content/resources/?limit=1000")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["count"], 120)
        self.assertEqual(len(response.data["results"]), 100) # max_limit is 100
