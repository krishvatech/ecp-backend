"""
API views for 1:1 networking meetings.
"""
from rest_framework import viewsets, status, views, generics
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework.permissions import IsAuthenticated, BasePermission, SAFE_METHODS
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.db.models import Q, Max
from django.conf import settings
from datetime import timedelta

from events.models import (
    Event,
    EventRegistration,
    EventNetworkingSettings,
    NetworkingTable,
    NetworkingMeeting,
)
from events.serializers import (
    EventNetworkingSettingsSerializer,
    NetworkingTableSerializer,
    NetworkingMeetingSerializer,
    NetworkingMeetingCreateSerializer,
    NetworkingMeetingSuggestSerializer,
)
from events.services.networking_meetings import (
    get_available_networking_slots,
    check_duplicate_pending_meeting,
    check_attendee_meeting_overlaps,
    check_table_availability,
)
from events.tasks import (
    send_networking_meeting_request_email,
    send_networking_meeting_accepted_email,
    send_networking_meeting_declined_email,
    send_networking_meeting_suggested_email,
    send_networking_meeting_cancelled_email,
    send_networking_meeting_reminder_email,
)


class IsEventOwner(BasePermission):
    """Only event owner/organizer/admin can manage event settings and tables."""

    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True

        event = obj if isinstance(obj, Event) else obj.event
        user = request.user

        return bool(
            user
            and user.is_authenticated
            and (
                event.created_by_id == user.id
                or user.is_superuser
            )
        )


class EventNetworkingSettingsView(views.APIView):
    """
    GET and PATCH networking settings for an event.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, event_id):
        event = get_object_or_404(Event, id=event_id)
        try:
            settings = EventNetworkingSettings.objects.get(event=event)
            serializer = EventNetworkingSettingsSerializer(settings)
            return Response(serializer.data)
        except EventNetworkingSettings.DoesNotExist:
            return Response(
                {"detail": "Networking settings not configured for this event."},
                status=status.HTTP_404_NOT_FOUND
            )

    def patch(self, request, event_id):
        event = get_object_or_404(Event, id=event_id)

        # Check permission
        if event.created_by_id != request.user.id and not request.user.is_superuser:
            raise PermissionDenied("Only event owner can update settings.")

        try:
            settings = EventNetworkingSettings.objects.get(event=event)
        except EventNetworkingSettings.DoesNotExist:
            # Create if doesn't exist
            settings = EventNetworkingSettings.objects.create(event=event)

        serializer = EventNetworkingSettingsSerializer(settings, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class NetworkingTableViewSet(viewsets.ModelViewSet):
    """
    CRUD for networking tables.
    Only event owner/organizer/admin can manage tables.
    """
    serializer_class = NetworkingTableSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        event_id = self.kwargs.get('event_id')
        return NetworkingTable.objects.filter(event_id=event_id)

    def get_event(self):
        if not hasattr(self, "_event"):
            event_id = self.kwargs.get('event_id')
            self._event = get_object_or_404(Event, id=event_id)
        return self._event

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["event"] = self.get_event()
        return context

    def check_owner_permission(self):
        event = self.get_event()
        if event.created_by_id != self.request.user.id and not self.request.user.is_superuser:
            raise PermissionDenied("Only event owner can manage tables.")

    def list(self, request, *args, **kwargs):
        event = self.get_event()
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        self.check_owner_permission()
        event = self.get_event()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            with transaction.atomic():
                table_number = serializer.validated_data.get('table_number')
                if not table_number:
                    max_table = NetworkingTable.objects.filter(event=event).aggregate(Max('table_number'))['table_number__max']
                    table_number = (max_table or 0) + 1
                    serializer.validated_data['table_number'] = table_number

                serializer.save(event=event)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        self.check_owner_permission()
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        self.check_owner_permission()
        return super().partial_update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        self.check_owner_permission()
        return super().destroy(request, *args, **kwargs)


class NetworkingMeetingAvailabilityView(views.APIView):
    """
    GET available networking slots.

    Query params:
    - recipient_registration_id: ID of recipient
    - duration_minutes: desired duration
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, event_id):
        event = get_object_or_404(Event, id=event_id)

        # Get current user's registration (or create temporary one for non-registered users)
        requester_reg, _ = EventRegistration.objects.get_or_create(
            event=event,
            user=request.user,
            defaults={'status': 'registered'}
        )

        # Get query params
        recipient_id = request.query_params.get('recipient_registration_id')
        duration_str = request.query_params.get('duration_minutes')

        if not recipient_id or not duration_str:
            return Response(
                {"detail": "recipient_registration_id and duration_minutes are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            duration = int(duration_str)
            recipient_reg = EventRegistration.objects.get(id=recipient_id, event=event)
        except (ValueError, EventRegistration.DoesNotExist):
            return Response(
                {"detail": "Invalid recipient_registration_id or duration_minutes."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check requester != recipient
        if requester_reg.id == recipient_reg.id:
            return Response(
                {"detail": "Cannot request meeting with yourself."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            slots = get_available_networking_slots(
                event=event,
                requester_registration=requester_reg,
                recipient_registration=recipient_reg,
                duration_minutes=duration
            )
            return Response({"available_slots": slots})
        except DjangoValidationError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class NetworkingMeetingListCreateView(generics.ListCreateAPIView):
    """
    List and create networking meetings.
    """
    serializer_class = NetworkingMeetingSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        event_id = self.kwargs.get('event_id')
        user = self.request.user
        return NetworkingMeeting.objects.filter(
            event_id=event_id
        ).filter(
            Q(requester__user=user) | Q(recipient__user=user)
        )

    def create(self, request, *args, **kwargs):
        event_id = self.kwargs.get('event_id')
        event = get_object_or_404(Event, id=event_id)

        # Get or create requester registration (allow non-registered users)
        requester_reg, _ = EventRegistration.objects.get_or_create(
            event=event,
            user=request.user,
            defaults={'status': 'registered'}
        )

        serializer = NetworkingMeetingCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        recipient_id = serializer.validated_data['recipient_registration_id']
        duration_minutes = serializer.validated_data['duration_minutes']
        start_time = serializer.validated_data['start_time']
        message = serializer.validated_data.get('message', '')

        # Get recipient registration
        try:
            recipient_reg = EventRegistration.objects.get(id=recipient_id, event=event)
        except EventRegistration.DoesNotExist:
            return Response(
                {"detail": "Recipient registration not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Check requester != recipient
        if requester_reg.id == recipient_reg.id:
            return Response(
                {"detail": "Cannot request a meeting with yourself."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check for duplicate pending/suggested meeting between same attendees
        existing_meeting = check_duplicate_pending_meeting(requester_reg, recipient_reg)
        if existing_meeting:
            return Response(
                {"detail": f"You already have an active meeting request with this attendee ({existing_meeting.get_status_display()})."},
                status=status.HTTP_409_CONFLICT
            )

        # Calculate end_time from duration
        end_time = start_time + timedelta(minutes=duration_minutes)

        # Check for overlapping accepted meetings
        requester_overlaps = check_attendee_meeting_overlaps(requester_reg, start_time, end_time)
        if requester_overlaps:
            return Response(
                {"detail": "You already have an accepted meeting at this time."},
                status=status.HTTP_409_CONFLICT
            )

        recipient_overlaps = check_attendee_meeting_overlaps(recipient_reg, start_time, end_time)
        if recipient_overlaps:
            return Response(
                {"detail": "The recipient already has an accepted meeting at this time."},
                status=status.HTTP_409_CONFLICT
            )

        # Check meeting is not in the past
        if start_time < timezone.now():
            return Response(
                {"detail": "Cannot request a meeting in the past."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Re-check availability before creating
        try:
            slots = get_available_networking_slots(
                event=event,
                requester_registration=requester_reg,
                recipient_registration=recipient_reg,
                duration_minutes=duration_minutes
            )

            # Check if requested slot is available
            slot_available = any(
                slot['start_time'] == start_time.isoformat()
                for slot in slots
            )

            if not slot_available:
                return Response(
                    {"detail": "Requested slot is not available. The time may conflict with an event session or another attendee's schedule."},
                    status=status.HTTP_409_CONFLICT
                )
        except DjangoValidationError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create meeting (PENDING status, no table assigned yet)
        with transaction.atomic():
            meeting = NetworkingMeeting.objects.create(
                event=event,
                requester=requester_reg,
                recipient=recipient_reg,
                duration_minutes=duration_minutes,
                start_time=start_time,
                end_time=end_time,
                status='pending',
                message=message,
                table=None
            )

            # Send notification and email after transaction commits
            def on_create_success():
                # Create in-app notification
                from friends.models import Notification
                from events.tasks import build_networking_meeting_url
                requester_name = requester_reg.user.get_full_name() or requester_reg.user.username
                companion_url = build_networking_meeting_url(meeting)
                Notification.objects.create(
                    recipient=recipient_reg.user,
                    actor=requester_reg.user,
                    kind="event",
                    title=f"{requester_name} requested a meeting",
                    description=f"{duration_minutes}-minute meeting at {meeting.start_time.strftime('%b %d, %I:%M %p')}",
                    state="pending",
                    data={
                        "type": "networking_meeting_request",
                        "meeting_id": meeting.id,
                        "event_id": meeting.event_id,
                        "event_slug": meeting.event.slug,
                        "tab": "meetings",
                        "action_url": companion_url,
                    }
                )

                # Send email to recipient
                send_networking_meeting_request_email.delay(meeting.id)

            transaction.on_commit(on_create_success)

        response_serializer = NetworkingMeetingSerializer(meeting)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)


class NetworkingMeetingMyView(views.APIView):
    """
    GET meetings where current user is requester or recipient.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, event_id):
        event = get_object_or_404(Event, id=event_id)

        # Get or create registration (allow non-registered users to view their meetings)
        EventRegistration.objects.get_or_create(
            event=event,
            user=request.user,
            defaults={'status': 'registered'}
        )

        # Get all meetings where user is involved
        from django.db.models import Q
        meetings = NetworkingMeeting.objects.filter(
            event=event
        ).filter(
            Q(requester__user=request.user) | Q(recipient__user=request.user)
        ).order_by('-created_at')

        serializer = NetworkingMeetingSerializer(meetings, many=True)
        return Response(serializer.data)


class NetworkingMeetingAcceptView(views.APIView):
    """
    Accept a pending networking meeting request.
    Only recipient can accept.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, meeting_id):
        meeting = get_object_or_404(NetworkingMeeting, id=meeting_id)

        # Only recipient can accept
        if meeting.recipient.user_id != request.user.id:
            raise PermissionDenied("Only recipient can accept this meeting.")

        # Must be PENDING
        if meeting.status != 'pending':
            return Response(
                {"detail": f"Cannot accept meeting with status '{meeting.status}'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Assign lowest free active table with proper locking to prevent race conditions
        with transaction.atomic():
            # Lock the meeting row to ensure only one thread processes it
            meeting = NetworkingMeeting.objects.select_for_update().get(id=meeting.id)

            # Check for overlapping ACCEPTED meetings (exclude current pending meeting)
            requester_overlaps = check_attendee_meeting_overlaps(
                meeting.requester, meeting.start_time, meeting.end_time, exclude_meeting_id=meeting.id
            )
            if requester_overlaps:
                return Response(
                    {"detail": "Requester has another accepted meeting at this time."},
                    status=status.HTTP_409_CONFLICT
                )

            recipient_overlaps = check_attendee_meeting_overlaps(
                meeting.recipient, meeting.start_time, meeting.end_time, exclude_meeting_id=meeting.id
            )
            if recipient_overlaps:
                return Response(
                    {"detail": "Recipient has another accepted meeting at this time."},
                    status=status.HTTP_409_CONFLICT
                )

            # Find free table with proper locking
            free_table = NetworkingTable.objects.select_for_update().filter(
                event=meeting.event,
                is_active=True
            ).exclude(
                networking_meetings__status='accepted',
                networking_meetings__start_time__lt=meeting.end_time,
                networking_meetings__end_time__gt=meeting.start_time
            ).first()

            if not free_table:
                return Response(
                    {"detail": "No free networking tables available at this time. Please try a different time slot."},
                    status=status.HTTP_409_CONFLICT
                )

            # Verify table is actually free (double-check after lock)
            table_conflicts = check_table_availability(free_table, meeting.start_time, meeting.end_time)
            if table_conflicts:
                return Response(
                    {"detail": "Selected table became unavailable. Please try again."},
                    status=status.HTTP_409_CONFLICT
                )

            meeting.table = free_table
            meeting.status = 'accepted'
            meeting.accepted_at = timezone.now()
            meeting.save()

            # Send notifications and emails after transaction commits
            def on_accept_success():
                from friends.models import Notification
                from events.tasks import build_networking_meeting_url
                requester_name = meeting.requester.user.get_full_name() or meeting.requester.user.username
                recipient_name = meeting.recipient.user.get_full_name() or meeting.recipient.user.username
                companion_url = build_networking_meeting_url(meeting)

                # Notify requester (they see their request was accepted)
                Notification.objects.create(
                    recipient=meeting.requester.user,
                    actor=meeting.recipient.user,
                    kind="event",
                    title="accepted your meeting request",
                    description=f"{recipient_name} accepted your meeting request.",
                    state="accepted",
                    data={
                        "type": "networking_meeting_accepted",
                        "meeting_id": meeting.id,
                        "event_id": meeting.event_id,
                        "event_slug": meeting.event.slug,
                        "action_url": companion_url,
                        "tab": "meetings",
                    }
                )

                # Notify recipient (confirmation)
                Notification.objects.create(
                    recipient=meeting.recipient.user,
                    actor=meeting.requester.user,
                    kind="event",
                    title="meeting request accepted",
                    description=f"You accepted {requester_name}'s meeting request.",
                    state="accepted",
                    data={
                        "type": "networking_meeting_accepted",
                        "meeting_id": meeting.id,
                        "event_id": meeting.event_id,
                        "event_slug": meeting.event.slug,
                        "action_url": companion_url,
                        "tab": "meetings",
                    }
                )

                # Send accepted email to both parties
                send_networking_meeting_accepted_email.delay(meeting.id)

                # Schedule reminder email 5 minutes before meeting
                meeting_reminder_time = meeting.start_time - timedelta(minutes=5)
                if meeting_reminder_time > timezone.now():
                    send_networking_meeting_reminder_email.apply_async(
                        args=[meeting.id],
                        eta=meeting_reminder_time
                    )

            transaction.on_commit(on_accept_success)

        serializer = NetworkingMeetingSerializer(meeting)
        return Response(serializer.data)


class NetworkingMeetingDeclineView(views.APIView):
    """
    Decline a pending or suggested networking meeting.
    Only recipient can decline.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, meeting_id):
        meeting = get_object_or_404(NetworkingMeeting, id=meeting_id)

        # Only recipient can decline
        if meeting.recipient.user_id != request.user.id:
            raise PermissionDenied("Only recipient can decline this meeting.")

        # Must be PENDING or SUGGESTED
        if meeting.status not in ['pending', 'suggested']:
            status_display = dict(NetworkingMeeting.STATUS_CHOICES).get(meeting.status, meeting.status)
            return Response(
                {"detail": f"Cannot decline a {status_display.lower()} meeting. Only pending or suggested requests can be declined."},
                status=status.HTTP_400_BAD_REQUEST
            )

        with transaction.atomic():
            meeting.status = 'declined'
            meeting.declined_at = timezone.now()
            meeting.save()

            # Send notification and email after transaction commits
            def on_decline_success():
                from friends.models import Notification
                from events.tasks import build_networking_meeting_url
                recipient_name = meeting.recipient.user.get_full_name() or meeting.recipient.user.username
                companion_url = build_networking_meeting_url(meeting)

                # Notify requester that their request was declined
                Notification.objects.create(
                    recipient=meeting.requester.user,
                    actor=meeting.recipient.user,
                    kind="event",
                    title=f"{recipient_name} declined your meeting request",
                    description=f"{meeting.start_time.strftime('%b %d, %I:%M %p')} • {meeting.duration_minutes} min",
                    state="declined",
                    data={
                        "type": "networking_meeting_declined",
                        "meeting_id": meeting.id,
                        "event_id": meeting.event_id,
                        "event_slug": meeting.event.slug,
                        "tab": "meetings",
                        "action_url": companion_url,
                    }
                )

                # Send declined email to requester
                send_networking_meeting_declined_email.delay(meeting.id)

            transaction.on_commit(on_decline_success)

        serializer = NetworkingMeetingSerializer(meeting)
        return Response(serializer.data)


class NetworkingMeetingSuggestView(views.APIView):
    """
    Suggest an alternative meeting slot.
    Requester or recipient can suggest.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, meeting_id):
        meeting = get_object_or_404(NetworkingMeeting, id=meeting_id)

        # Requester or recipient can suggest
        user_is_requester = meeting.requester.user_id == request.user.id
        user_is_recipient = meeting.recipient.user_id == request.user.id

        if not (user_is_requester or user_is_recipient):
            raise PermissionDenied("Only requester or recipient can suggest alternatives.")

        serializer = NetworkingMeetingSuggestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        suggested_start = serializer.validated_data['suggested_start_time']
        suggested_end = serializer.validated_data['suggested_end_time']

        # Check suggested duration matches original duration
        suggested_duration = int((suggested_end - suggested_start).total_seconds() / 60)
        if suggested_duration != meeting.duration_minutes:
            return Response(
                {"detail": f"Suggested meeting duration must be {meeting.duration_minutes} minutes (you suggested {suggested_duration} minutes)."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Re-check availability for suggested slot
        try:
            slots = get_available_networking_slots(
                event=meeting.event,
                requester_registration=meeting.requester,
                recipient_registration=meeting.recipient,
                duration_minutes=meeting.duration_minutes
            )

            slot_available = any(
                slot['start_time'] == suggested_start.isoformat()
                for slot in slots
            )

            if not slot_available:
                return Response(
                    {"detail": "The suggested time slot conflicts with an event session, event schedule, or existing meeting."},
                    status=status.HTTP_409_CONFLICT
                )
        except DjangoValidationError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Determine who is suggesting
        suggested_by = meeting.requester if user_is_requester else meeting.recipient
        other_party = meeting.recipient if user_is_requester else meeting.requester

        with transaction.atomic():
            meeting.suggested_start_time = suggested_start
            meeting.suggested_end_time = suggested_end
            meeting.suggested_by = suggested_by
            meeting.status = 'suggested'
            meeting.table = None
            meeting.save()

            # Send notification and email after transaction commits
            def on_suggest_success():
                from friends.models import Notification
                from events.tasks import build_networking_meeting_url
                suggester_name = suggested_by.user.get_full_name() or suggested_by.user.username
                companion_url = build_networking_meeting_url(meeting)

                # Notify the other party about the suggestion
                Notification.objects.create(
                    recipient=other_party.user,
                    actor=suggested_by.user,
                    kind="event",
                    title="suggested a different meeting time",
                    description=f"{suggester_name} suggested a different time for your meeting.",
                    state="pending",
                    data={
                        "type": "networking_meeting_suggested",
                        "meeting_id": meeting.id,
                        "event_id": meeting.event_id,
                        "event_slug": meeting.event.slug,
                        "action_url": companion_url,
                        "tab": "meetings",
                    }
                )

                # Send suggested email to the other party
                send_networking_meeting_suggested_email.delay(meeting.id)

            transaction.on_commit(on_suggest_success)

        serializer = NetworkingMeetingSerializer(meeting)
        return Response(serializer.data)


class NetworkingMeetingCancelView(views.APIView):
    """
    Cancel a networking meeting.
    Requester or recipient can cancel.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, meeting_id):
        meeting = get_object_or_404(NetworkingMeeting, id=meeting_id)

        # Requester or recipient can cancel
        user_is_requester = meeting.requester.user_id == request.user.id
        user_is_recipient = meeting.recipient.user_id == request.user.id

        if not (user_is_requester or user_is_recipient):
            raise PermissionDenied("Only requester or recipient can cancel this meeting.")

        # Can cancel PENDING, ACCEPTED, or SUGGESTED
        if meeting.status not in ['pending', 'accepted', 'suggested']:
            return Response(
                {"detail": f"Cannot cancel meeting with status '{meeting.status}'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        with transaction.atomic():
            meeting.status = 'cancelled'
            meeting.cancelled_at = timezone.now()
            meeting.save()

            # Send notifications and emails after transaction commits
            def on_cancel_success():
                from friends.models import Notification
                from events.tasks import build_networking_meeting_url
                canceller = meeting.requester if user_is_requester else meeting.recipient
                other_party = meeting.recipient if user_is_requester else meeting.requester
                canceller_name = canceller.user.get_full_name() or canceller.user.username
                frontend_url = getattr(settings, 'FRONTEND_URL', '').rstrip('/') or 'http://localhost:5173'
                directory_url = f"{frontend_url}/events/{meeting.event.slug}/companion?tab=directory"

                # Notify the other party that meeting was cancelled
                Notification.objects.create(
                    recipient=other_party.user,
                    actor=canceller.user,
                    kind="event",
                    title="cancelled the meeting",
                    description=f"{canceller_name} cancelled your meeting.",
                    state="cancelled",
                    data={
                        "type": "networking_meeting_cancelled",
                        "meeting_id": meeting.id,
                        "event_id": meeting.event_id,
                        "event_slug": meeting.event.slug,
                        "action_url": directory_url,
                        "tab": "directory",
                    }
                )

                # Send cancelled email to both parties
                send_networking_meeting_cancelled_email.delay(meeting.id)

            transaction.on_commit(on_cancel_success)

        serializer = NetworkingMeetingSerializer(meeting)
        return Response(serializer.data)


class NetworkingMeetingRescheduleView(views.APIView):
    """
    Reschedule an accepted or suggested meeting to new slot.
    Either participant can reschedule.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, meeting_id):
        meeting = get_object_or_404(NetworkingMeeting, id=meeting_id)

        # Requester or recipient can reschedule
        user_is_requester = meeting.requester.user_id == request.user.id
        user_is_recipient = meeting.recipient.user_id == request.user.id

        if not (user_is_requester or user_is_recipient):
            raise PermissionDenied("Only requester or recipient can reschedule.")

        # Only ACCEPTED or SUGGESTED meetings can be rescheduled
        if meeting.status not in ['accepted', 'suggested']:
            status_display = dict(NetworkingMeeting.STATUS_CHOICES).get(meeting.status, meeting.status)
            return Response(
                {"detail": f"Cannot reschedule a {status_display.lower()} meeting. Only accepted or suggested meetings can be rescheduled."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = NetworkingMeetingSuggestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        new_start = serializer.validated_data['suggested_start_time']
        new_end = serializer.validated_data['suggested_end_time']

        # Check duration matches
        new_duration = int((new_end - new_start).total_seconds() / 60)
        if new_duration != meeting.duration_minutes:
            return Response(
                {"detail": f"New duration ({new_duration}m) must match original ({meeting.duration_minutes}m)."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check availability for new slot
        try:
            slots = get_available_networking_slots(
                event=meeting.event,
                requester_registration=meeting.requester,
                recipient_registration=meeting.recipient,
                duration_minutes=meeting.duration_minutes
            )

            slot_available = any(
                slot['start_time'] == new_start.isoformat()
                for slot in slots
            )

            if not slot_available:
                return Response(
                    {"detail": "New slot is not available."},
                    status=status.HTTP_409_CONFLICT
                )
        except DjangoValidationError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

        with transaction.atomic():
            # Lock the meeting row
            meeting = NetworkingMeeting.objects.select_for_update().get(id=meeting.id)

            # Update times
            meeting.start_time = new_start
            meeting.end_time = new_end
            meeting.status = 'accepted'
            meeting.accepted_at = timezone.now()

            # Check for overlaps at new time before reassigning table
            requester_overlaps = check_attendee_meeting_overlaps(
                meeting.requester, new_start, new_end, exclude_meeting_id=meeting.id
            )
            if requester_overlaps:
                return Response(
                    {"detail": "Requester has a conflicting meeting at the new time."},
                    status=status.HTTP_409_CONFLICT
                )

            recipient_overlaps = check_attendee_meeting_overlaps(
                meeting.recipient, new_start, new_end, exclude_meeting_id=meeting.id
            )
            if recipient_overlaps:
                return Response(
                    {"detail": "Recipient has a conflicting meeting at the new time."},
                    status=status.HTTP_409_CONFLICT
                )

            # Find OTHER accepted meetings that conflict with new time and get their table IDs
            conflicting_table_ids = NetworkingMeeting.objects.filter(
                event=meeting.event,
                status='accepted',
                start_time__lt=new_end,
                end_time__gt=new_start
            ).exclude(id=meeting.id).values_list('table_id', flat=True).distinct()

            # Reassign table with proper locking, excluding tables with conflicting meetings
            free_table = NetworkingTable.objects.select_for_update().filter(
                event=meeting.event,
                is_active=True
            ).exclude(id__in=conflicting_table_ids).first()

            if not free_table:
                return Response(
                    {"detail": "No free table available at the new time."},
                    status=status.HTTP_409_CONFLICT
                )

            meeting.table = free_table
            meeting.save()

        # Send accepted email to both parties (reschedule confirmation)
        send_networking_meeting_accepted_email.delay(meeting.id)

        serializer = NetworkingMeetingSerializer(meeting)
        return Response(serializer.data)
