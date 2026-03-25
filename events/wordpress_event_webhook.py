"""
WordPress Events Calendar webhook endpoint handler.

Receives and processes event sync events from WordPress.
Validates webhook signatures and triggers event sync.
Handles both metadata sync and go-live/end-live triggers.
"""
import json
import logging
import hmac
import hashlib
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.conf import settings

from .wordpress_event_sync import get_wordpress_event_sync_service
from .models import Event

logger = logging.getLogger(__name__)


class WordPressEventWebhookView(APIView):
    """Handle incoming WordPress webhooks for event sync."""

    permission_classes = [AllowAny]
    authentication_classes = []  # No auth required — webhook signature validates the source

    def _validate_signature(self, payload_bytes: bytes, signature: str) -> bool:
        """
        Validate webhook signature using HMAC-SHA256.
        """
        secret = getattr(settings, "WP_IMAA_WEBHOOK_SECRET_KEY", "") or ""
        if not secret:
            logger.warning("WP_IMAA_WEBHOOK_SECRET_KEY not configured")
            return False

        expected_sig = "sha256=" + hmac.new(
            secret.encode(),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected_sig, signature)

    def post(self, request, *args, **kwargs):
        """
        Handle WordPress webhook POST request.

        Expected payloads:

        1. Event metadata sync (create/update/delete):
        {
            "action": "created|updated|deleted",
            "event": { ...full tribe/v1 event object... }
        }

        2. Go-live trigger (from admin button):
        {
            "action": "live_start",
            "wp_event_id": 2117,
            "live_action": "start"
        }

        3. End-live trigger:
        {
            "action": "live_end",
            "wp_event_id": 2117,
            "live_action": "end"
        }
        """
        try:
            # Validate HMAC signature
            signature = request.headers.get("X-Webhook-Signature", "")
            payload_bytes = request.body

            if not self._validate_signature(payload_bytes, signature):
                logger.warning("Invalid WordPress event webhook signature")
                return Response(
                    {"error": "Invalid signature"},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            payload = request.data

            # Route by action type
            action = payload.get("action", "").lower()

            if action in ("live_start", "live_end"):
                return self._handle_live_action(payload, action)
            elif action in ("created", "updated", "deleted"):
                return self._handle_event_sync(payload, action)
            else:
                logger.warning(f"Unknown webhook action: {action}")
                return Response(
                    {"error": f"Unknown action: {action}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        except json.JSONDecodeError:
            logger.error("Invalid JSON in WordPress event webhook")
            return Response(
                {"error": "Invalid JSON"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error processing WordPress event webhook: {str(e)}", exc_info=True)
            return Response(
                {"error": "Internal error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _handle_event_sync(self, payload: dict, action: str) -> Response:
        """Handle event metadata sync (create/update/delete)."""
        wp_event = payload.get("event")

        if not wp_event:
            logger.warning(f"Missing event data in WordPress webhook (action={action})")
            return Response(
                {"error": "Missing event data"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Sync the event
        service = get_wordpress_event_sync_service()
        event, sync_action = service.sync_from_wp_data(wp_event)

        if sync_action in ("created", "updated", "cancelled"):
            logger.info(f"Synced WordPress event: {wp_event.get('id')} → {sync_action}")
            return Response(
                {
                    "status": "ok",
                    "action": sync_action,
                    "event_id": event.id if event else None,
                    "wp_event_id": wp_event.get("id")
                },
                status=status.HTTP_200_OK
            )
        else:
            # "skipped" or "error"
            logger.info(f"WordPress event sync result: {sync_action} (wp_id={wp_event.get('id')})")
            return Response(
                {
                    "status": "ok",
                    "action": sync_action,
                    "event_id": event.id if event else None
                },
                status=status.HTTP_200_OK
            )

    def _handle_live_action(self, payload: dict, action: str) -> Response:
        """
        Handle go-live / end-live triggers from WordPress.

        The WordPress admin clicks "Start Live Event" or "End Live Event" button,
        which sends a webhook to trigger the meeting on the platform.
        """
        wp_event_id = payload.get("wp_event_id")
        live_action = payload.get("live_action", "").lower()

        if not wp_event_id:
            logger.warning(f"Missing wp_event_id in live action webhook")
            return Response(
                {"error": "Missing wp_event_id"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if live_action not in ("start", "end"):
            logger.warning(f"Invalid live_action: {live_action}")
            return Response(
                {"error": "Invalid live_action"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Find the Django event by WordPress ID
        try:
            event = Event.objects.get(wordpress_event_id=wp_event_id)
        except Event.DoesNotExist:
            logger.warning(f"Event not found for WP ID {wp_event_id}")
            return Response(
                {"error": f"Event not found for WP ID {wp_event_id}"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Perform the live status change
        try:
            from .views import EventViewSet
            from django.http import QueryDict
            from rest_framework.request import Request as DRFRequest

            # Use the event's creator as the host user
            host_user = event.created_by

            # Call the live_status logic
            # We'll need to extract this into a reusable helper function in views.py
            result = self._perform_live_status_change(event, live_action, host_user)

            logger.info(f"Event {event.id} (WP {wp_event_id}) live action: {live_action} → {result}")
            return Response(
                {
                    "status": "ok",
                    "action": live_action,
                    "event_id": event.id,
                    "new_status": event.status
                },
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Failed to perform live action '{live_action}' on event {event.id}: {e}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _perform_live_status_change(self, event: Event, action: str, host_user) -> str:
        """
        Perform the actual live status change (start or end meeting).

        This logic is extracted from EventViewSet.live_status() to be reusable
        for both API calls and webhook triggers.

        Returns: new status string ("live", "ended", etc.)
        """
        from django.db import transaction
        from django.utils import timezone
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        import logging

        logger = logging.getLogger(__name__)

        if action == "start":
            with transaction.atomic():
                event = Event.objects.select_for_update().get(id=event.id)

                # Set live fields
                event.status = "live"
                event.is_live = True
                event.live_started_at = timezone.now()
                event.live_ended_at = None
                event.active_speaker_id = host_user.id if host_user else None
                event.attending_count = 0
                event.idle_started_at = None
                event.ended_by_host = False
                event.save(
                    update_fields=[
                        "status", "is_live", "live_started_at", "live_ended_at",
                        "active_speaker_id", "attending_count", "idle_started_at",
                        "ended_by_host"
                    ]
                )

                # Broadcast to WebSocket channel
                channel_layer = get_channel_layer()
                async_to_sync(channel_layer.group_send)(
                    f"event_{event.id}",
                    {
                        "type": "broadcast_message",
                        "message": {
                            "type": "meeting_started",
                            "event_id": event.id,
                            "status": "live",
                            "started_at": event.live_started_at.isoformat() if event.live_started_at else None,
                        }
                    }
                )

                # If waiting room enabled, broadcast waiting room enforcement
                if event.waiting_room_enabled:
                    async_to_sync(channel_layer.group_send)(
                        f"event_{event.id}",
                        {
                            "type": "broadcast_message",
                            "message": {"type": "waiting_room_enforced"}
                        }
                    )

                logger.info(f"Event {event.id} started live (triggered by WP webhook)")
                return event.status

        elif action == "end":
            with transaction.atomic():
                event = Event.objects.select_for_update().get(id=event.id)

                # Revoke any active break Celery task
                if event.break_celery_task_id:
                    from celery.app import current_app
                    try:
                        current_app.control.revoke(event.break_celery_task_id)
                    except Exception as e:
                        logger.warning(f"Failed to revoke break task {event.break_celery_task_id}: {e}")

                # Stop RTK recording if active
                if event.is_recording:
                    try:
                        from .utils import _stop_rtk_recording_for_event_manual
                        _stop_rtk_recording_for_event_manual(event)
                    except Exception as e:
                        logger.warning(f"Failed to stop RTK recording for event {event.id}: {e}")

                # Set ended fields
                event.status = "ended"
                event.is_live = False
                event.live_ended_at = timezone.now()
                event.ended_by_host = True
                event.save(
                    update_fields=[
                        "status", "is_live", "live_ended_at", "ended_by_host"
                    ]
                )

                # Broadcast to WebSocket channel
                channel_layer = get_channel_layer()
                lounge_available = event.lounge_enabled_after
                lounge_closing_time = None
                if lounge_available:
                    lounge_closing_time = (
                        event.live_ended_at.timestamp() + (event.lounge_after_buffer * 60)
                    ) if event.live_ended_at else None

                async_to_sync(channel_layer.group_send)(
                    f"event_{event.id}",
                    {
                        "type": "broadcast_message",
                        "message": {
                            "type": "meeting_ended",
                            "event_id": event.id,
                            "status": "ended",
                            "ended_at": event.live_ended_at.isoformat() if event.live_ended_at else None,
                            "lounge_available": lounge_available,
                            "lounge_closing_time": lounge_closing_time,
                        }
                    }
                )

                logger.info(f"Event {event.id} ended (triggered by WP webhook)")
                return event.status

        return event.status
