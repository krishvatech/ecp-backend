import json
import logging
import hmac
import hashlib
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.conf import settings
from .models import Event
from .saleor_sync import sync_event_from_saleor_data

logger = logging.getLogger(__name__)

class SaleorProductWebhookView(APIView):
    """
    Handle Saleor webhooks for product events (created, updated, deleted).
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    def _validate_signature(self, payload_bytes, signature):
        """
        Validate Saleor webhook signature.
        Saleor sends 'X-Saleor-Signature' header which is HMAC-SHA256 of payload.
        """
        secret = getattr(settings, "SALEOR_WEBHOOK_SECRET", "")
        if not secret:
            # If no secret configured, we skip validation (warning logged)
            logger.warning("SALEOR_WEBHOOK_SECRET not configured, skipping signature validation.")
            return True
        
        # Note: Saleor signature is just the hex digest, sometimes prefixed with 'sha1=' or 'sha256='
        # In recent versions it's HMAC-SHA256.
        expected_sig = hmac.new(
            secret.encode(),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected_sig, signature)

    def post(self, request, *args, **kwargs):
        signature = request.headers.get("X-Saleor-Signature", "")
        payload_bytes = request.body
        
        if not self._validate_signature(payload_bytes, signature):
            logger.warning("Invalid Saleor webhook signature")
            return Response({"error": "Invalid signature"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            return Response({"error": "Invalid JSON"}, status=status.HTTP_400_BAD_REQUEST)

        # Saleor webhooks usually send the event type in a header or payload
        # Common event types: PRODUCT_CREATED, PRODUCT_UPDATED, PRODUCT_DELETED
        event_type = request.headers.get("X-Saleor-Event", "").upper()
        
        # If not in header, try to infer from payload (some older versions or custom configs)
        if not event_type:
             # Just a guess based on common patterns
             pass

        logger.info(f"Received Saleor webhook: {event_type}")
        # Log keys for debugging structure
        logger.debug(f"Payload keys: {list(payload.keys())}")

        if event_type in ("PRODUCT_CREATED", "PRODUCT_UPDATED"):
            # Saleor can send data directly or wrapped in a list/dict
            product_data = payload
            if isinstance(payload, list) and len(payload) > 0:
                product_data = payload[0]
            elif isinstance(payload, dict):
                if "event" in payload and "product" in payload["event"]:
                    product_data = payload["event"]["product"]
                elif "product" in payload:
                    product_data = payload["product"]
            
            # If still missing ID, maybe it's under a different key or we need to look deeper
            if not product_data.get("id") and isinstance(product_data, dict):
                 # Try to find any key that looks like a product ID or the first key if it's a single-key dict
                 pass

            event_instance, action = sync_event_from_saleor_data(product_data)
            if event_instance:
                return Response({
                    "status": "ok",
                    "action": action,
                    "event_id": event_instance.id
                }, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Sync failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        elif event_type == "PRODUCT_DELETED":
            product_id = payload.get("id")
            if isinstance(payload, dict):
                if "event" in payload and "product" in payload["event"]:
                    product_id = payload["event"]["product"].get("id")
                elif "product" in payload:
                    product_id = payload["product"].get("id")
            
            if product_id:
                try:
                    event = Event.objects.get(saleor_product_id=product_id)
                    event.status = "cancelled"
                    event.skip_saleor_sync = True
                    event.save(update_fields=["status"])
                    logger.info(f"Cancelled Event {event.id} due to Saleor product deletion")
                    return Response({"status": "ok", "action": "cancelled"}, status=status.HTTP_200_OK)
                except Event.DoesNotExist:
                    return Response({"status": "ok", "action": "none"}, status=status.HTTP_200_OK)
        
        return Response({"status": "ignored"}, status=status.HTTP_200_OK)
