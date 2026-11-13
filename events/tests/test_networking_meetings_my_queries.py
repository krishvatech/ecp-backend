"""
"My meetings" loads people and tables in bulk, without changing what it returns
(Sentry ECP-BACKEND-J: one query per person, and four per table, for every meeting).
"""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import connection
from django.db.models import Q
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from community.models import Community
from events.models import Event, EventRegistration, NetworkingMeeting, NetworkingTable
from events.serializers import NetworkingMeetingSerializer, NetworkingTableSerializer
from users.models import UserProfile


class MyMeetingsTestBase(TestCase):
    url_template = "/api/events/{event_id}/networking-meetings/my/"

    def setUp(self):
        self.User = get_user_model()
        self.now = timezone.now()
        owner = self.User.objects.create_user(username="meet-owner", password="pass")
        community = Community.objects.create(name="Meetings community", owner=owner)
        self.event = self.make_event(owner, community, "Meetings summit")
        self.other_event = self.make_event(owner, community, "Other summit")

        self.viewer, self.viewer_reg = self.add_person("viewer", job_title="Viewer title", company="Viewer co")
        self.client = APIClient()
        self.client.force_authenticate(self.viewer)
        self.url = self.url_template.format(event_id=self.event.id)
        self.table_count = 0
        self.person_count = 0

    def make_event(self, owner, community, title):
        event = Event(
            title=title, community=community, created_by=owner, format="in_person", status="published",
            start_time=self.now + timedelta(days=1), end_time=self.now + timedelta(days=2),
        )
        event.skip_saleor_sync = True
        event.save()
        return event

    def add_person(self, name, job_title="", company="", event=None, first_name=None):
        user = self.User.objects.create_user(
            username=f"meet-{name}", email=f"{name}@example.com",
            first_name=name.title() if first_name is None else first_name, last_name="Person",
        )
        UserProfile.objects.update_or_create(user=user, defaults={"job_title": job_title, "company": company})
        registration = EventRegistration.objects.create(event=event or self.event, user=user, status="registered")
        return user, registration

    def add_table(self, name=None):
        self.table_count += 1
        return NetworkingTable.objects.create(
            event=self.event, table_number=self.table_count, name=name or f"Table {self.table_count}",
        )

    def add_meeting(self, requester, recipient, starts_in_minutes=60, table=None, status="pending",
                    suggested_by=None, event=None):
        start = self.now + timedelta(minutes=starts_in_minutes)
        return NetworkingMeeting.objects.create(
            event=event or self.event, requester=requester, recipient=recipient, duration_minutes=15,
            start_time=start, end_time=start + timedelta(minutes=15), table=table, status=status,
            suggested_by=suggested_by,
            suggested_start_time=start + timedelta(hours=1) if suggested_by else None,
            suggested_end_time=start + timedelta(hours=1, minutes=15) if suggested_by else None,
        )

    def add_meeting_with_new_person(self, table=None, status="pending", suggested=False, viewer_requests=True):
        self.person_count += 1
        _, other_reg = self.add_person(f"other{self.person_count}", job_title="Analyst", company="Firm")
        requester, recipient = (self.viewer_reg, other_reg) if viewer_requests else (other_reg, self.viewer_reg)
        return self.add_meeting(
            requester, recipient, starts_in_minutes=30 * self.person_count, table=table, status=status,
            suggested_by=other_reg if suggested else None,
        )

    def get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.content[:300])
        return response.data

    def query_count(self):
        with CaptureQueriesContext(connection) as queries:
            self.get()
        return len(queries)

    def reference(self, user=None):
        """What the endpoint returned before the fix: the same serializer with no preloading."""
        user = user or self.viewer
        meetings = NetworkingMeeting.objects.filter(event=self.event).filter(
            Q(requester__user=user) | Q(recipient__user=user)
        ).order_by("-created_at")
        return NetworkingMeetingSerializer(meetings, many=True).data


class MyMeetingsQueryCountTests(MyMeetingsTestBase):
    def add_mixed_meetings(self, count):
        for i in range(count):
            self.add_meeting_with_new_person(
                table=self.add_table() if i % 2 == 0 else None,
                status="accepted" if i % 3 == 0 else "pending",
                suggested=(i % 4 == 1),
                viewer_requests=(i % 2 == 0),
            )

    def test_query_count_does_not_grow_with_meetings(self):
        self.add_mixed_meetings(2)
        self.get()  # warm-up: the first request fills process-wide caches
        few = self.query_count()

        self.add_mixed_meetings(10)
        many = self.query_count()

        self.assertEqual(len(self.get()), 12)
        self.assertEqual(few, many, f"{few} queries for 2 meetings, {many} for 12")

    def test_query_count_stays_small(self):
        self.add_mixed_meetings(8)
        self.get()
        self.assertLessEqual(self.query_count(), 10)


class MyMeetingsOutputTests(MyMeetingsTestBase):
    def test_output_matches_the_unoptimised_serializer(self):
        busy_table = self.add_table("Busy table")
        free_table = self.add_table("Free table")
        # An accepted meeting that hasn't ended blocks its table; a declined one doesn't.
        self.add_meeting_with_new_person(table=busy_table, status="accepted")
        self.add_meeting_with_new_person(table=free_table, status="declined", viewer_requests=False)
        self.add_meeting_with_new_person(status="suggested", suggested=True)
        self.add_meeting_with_new_person(viewer_requests=False)

        data = self.get()

        self.assertEqual(len(data), 4)
        self.assertEqual(data, self.reference())

    def test_people_details(self):
        _, ana_reg = self.add_person("ana", job_title="Partner", company="Deal Co")
        meeting = self.add_meeting(ana_reg, self.viewer_reg, status="suggested", suggested_by=ana_reg)

        row = self.get()[0]

        self.assertEqual(row["id"], meeting.id)
        self.assertEqual(row["requester_user_name"], "meet-ana")
        self.assertEqual(row["recipient_user_name"], "meet-viewer")
        self.assertEqual(row["suggested_by_user_name"], "meet-ana")
        self.assertEqual(row["requester_detail"], {
            "id": ana_reg.id, "user_id": ana_reg.user_id, "display_name": "Ana Person",
            "company": "Deal Co", "job_title": "Partner", "avatar_url": None,
        })
        self.assertEqual(row["recipient_detail"]["display_name"], "Viewer Person")
        self.assertEqual(row["recipient_detail"]["company"], "Viewer co")

    def test_wordpress_avatar_and_username_fallback(self):
        user, reg = self.add_person("noname", first_name="")
        user.last_name = ""
        user.save(update_fields=["last_name"])
        UserProfile.objects.filter(user=user).update(wordpress_avatar_url="https://example.com/a.png")
        self.add_meeting(self.viewer_reg, reg)

        detail = self.get()[0]["recipient_detail"]

        self.assertEqual(detail["display_name"], "meet-noname")
        self.assertEqual(detail["avatar_url"], "https://example.com/a.png")

    def test_user_without_a_profile_is_still_listed(self):
        user, reg = self.add_person("noprofile", job_title="Gone", company="Gone")
        UserProfile.objects.filter(user=user).delete()
        self.add_meeting(reg, self.viewer_reg)

        data = self.get()

        detail = data[0]["requester_detail"]
        self.assertEqual((detail["company"], detail["job_title"], detail["avatar_url"]), (None, None, None))
        self.assertEqual(data, self.reference())

    def test_table_availability(self):
        busy_table = self.add_table("Busy table")
        free_table = self.add_table("Free table")
        busy = self.add_meeting_with_new_person(table=busy_table, status="accepted")
        # A finished accepted meeting no longer blocks its table.
        finished = self.add_meeting_with_new_person(table=free_table, status="accepted")
        NetworkingMeeting.objects.filter(pk=finished.pk).update(
            start_time=self.now - timedelta(hours=2), end_time=self.now - timedelta(hours=1),
        )

        rows = {row["id"]: row for row in self.get()}

        busy_row = rows[busy.id]["table"]
        self.assertEqual((busy_row["active_meeting_count"], busy_row["is_in_use"]), (1, True))
        self.assertEqual(busy_row["available_after"], busy.end_time)
        free_row = rows[finished.id]["table"]
        self.assertEqual(
            (free_row["active_meeting_count"], free_row["is_in_use"], free_row["available_after"]),
            (0, False, None),
        )
        self.assertEqual(rows[finished.id]["table_name"], "Free table")

    def test_only_the_viewers_meetings_in_this_event_newest_first(self):
        _, a_reg = self.add_person("a")
        _, b_reg = self.add_person("b")
        self.add_meeting(a_reg, b_reg)  # not the viewer's
        _, elsewhere_reg = self.add_person("elsewhere", event=self.other_event)
        viewer_elsewhere = EventRegistration.objects.create(event=self.other_event, user=self.viewer)
        self.add_meeting(viewer_elsewhere, elsewhere_reg, event=self.other_event)  # other event
        first = self.add_meeting(self.viewer_reg, a_reg)
        second = self.add_meeting(b_reg, self.viewer_reg)
        NetworkingMeeting.objects.filter(pk=first.pk).update(created_at=self.now - timedelta(minutes=5))

        self.assertEqual([row["id"] for row in self.get()], [second.id, first.id])


class NetworkingTableSerializerAnnotationTests(MyMeetingsTestBase):
    def annotated(self, table):
        from events.networking_views import _tables_with_availability
        return _tables_with_availability(NetworkingTable.objects.filter(pk=table.pk)).get()

    def test_annotated_table_without_active_meetings_needs_no_queries(self):
        table = self.add_table()
        annotated = self.annotated(table)

        with self.assertNumQueries(0):
            data = NetworkingTableSerializer(annotated).data

        self.assertEqual(
            (data["active_meeting_count"], data["is_in_use"], data["available_after"]), (0, False, None),
        )

    def test_annotation_matches_counting_one_table_at_a_time(self):
        table = self.add_table()
        for status in ("accepted", "accepted", "pending", "declined"):
            self.add_meeting_with_new_person(table=table, status=status)

        annotated = self.annotated(table)
        plain = NetworkingTable.objects.get(pk=table.pk)

        self.assertEqual(NetworkingTableSerializer(annotated).data, NetworkingTableSerializer(plain).data)
        self.assertEqual(NetworkingTableSerializer(annotated).data["active_meeting_count"], 2)
