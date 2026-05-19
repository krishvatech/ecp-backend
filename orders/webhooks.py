import json
import logging
import hmac
import hashlib
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.conf import settings
from django.db import transaction
from django.contrib.auth.models import User
from events.models import Event, EventRegistration
from events.services.post_acceptance_forms import (
    is_online_event,
    trigger_post_acceptance_forms
)

logger = logging.getLogger('orders')

@csrf_exempt
def saleor_order_paid_webhook(request):
    """
    Handle Saleor 'order-paid' webhook.
    Creates EventRegistration and triggers post-acceptance forms for paid orders.

    Validates webhook signature, looks up user by email, checks event format,
    and triggers form assignments for confirmed attendees.
    """
    if request.method != 'POST':
        return HttpResponse(status=405)

    # Verify webhook signature
    if hasattr(settings, 'SALEOR_WEBHOOK_SECRET') and settings.SALEOR_WEBHOOK_SECRET:
        signature = request.headers.get('X-Saleor-Signature', '')
        payload_bytes = request.body
        hmac_check = hmac.new(
            settings.SALEOR_WEBHOOK_SECRET.encode(),
            payload_bytes,
            hashlib.sha256
        )
        if not hmac.compare_digest(hmac_check.hexdigest(), signature):
            logger.warning(f"Invalid Saleor webhook signature")
            return HttpResponse(status=401)

    try:
        payload = json.loads(request.body)
        order = payload.get("order")
        if not order:
            return HttpResponse("Missing order data", status=400)

        email = order.get("userEmail")
        if not email:
            return HttpResponse("Missing email", status=400)

        # Look up user by email
        user = User.objects.filter(email=email).first()
        if not user:
            logger.warning(f"No User found for email: {email}. Skipping registration.")
            return HttpResponse(status=200)

        lines = order.get("lines", [])
        registrations_created = 0

        for line in lines:
            variant = line.get("variant")
            if not variant:
                continue

            saleor_variant_id = variant.get("id")

            # Find the Event associated with this Saleor variant
            try:
                event = Event.objects.get(saleor_variant_id=saleor_variant_id)

                # Skip virtual events (they don't need post-acceptance forms)
                if is_online_event(event):
                    logger.info(f"Skipping virtual event {event.id} - no forms required")
                    continue

                # Create EventRegistration using transaction for atomicity
                with transaction.atomic():
                    registration, created = EventRegistration.objects.get_or_create(
                        event=event,
                        user=user,
                        defaults={
                            "status": "registered",
                            "attendee_status": "confirmed",
                            "registered_at": timezone.now(),
                        }
                    )

                    should_trigger_forms = False

                    if created:
                        logger.info(
                            f"Created registration for {user.email} to event '{event.title}' "
                            f"(event_id={event.id}) via Saleor webhook"
                        )
                        registrations_created += 1
                        should_trigger_forms = True
                    else:
                        # Update existing payment_pending registrations to confirmed
                        if registration.status == 'payment_pending':
                            registration.status = 'registered'
                            registration.attendee_status = 'confirmed'
                            registration.registered_at = timezone.now()
                            registration.save(update_fields=['status', 'attendee_status', 'registered_at'])
                            logger.info(
                                f"Updated existing registration for {user.email} to event {event.id} "
                                f"from payment_pending to confirmed via Saleor webhook"
                            )
                            should_trigger_forms = True
                        else:
                            logger.info(
                                f"Registration already exists for {user.email} to event {event.id} "
                                f"with status {registration.status}. Skipping form trigger."
                            )

                    if should_trigger_forms:
                        # Trigger post-acceptance forms (within atomic transaction)
                        def queue_forms():
                            try:
                                trigger_post_acceptance_forms(registration)
                            except Exception as e:
                                logger.error(
                                    f"Failed to trigger forms for registration {registration.id}: {e}",
                                    exc_info=True
                                )

                        # Use transaction.on_commit() pattern to ensure forms triggered after save
                        transaction.on_commit(queue_forms)

            except Event.DoesNotExist:
                logger.warning(f"No Event found for Saleor variant ID: {saleor_variant_id}")

        logger.info(f"Saleor order-paid webhook: {registrations_created} registration(s) created")
        return HttpResponse(status=200)

    except json.JSONDecodeError:
        logger.error("Invalid JSON in Saleor webhook payload")
        return HttpResponse("Invalid JSON", status=400)
    except Exception as e:
        logger.error(f"Error processing Saleor webhook: {e}", exc_info=True)
        return HttpResponse(status=500)
