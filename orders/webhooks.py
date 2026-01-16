import json
import logging
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from events.models import Event, EventRegistration

logger = logging.getLogger('orders')

@csrf_exempt
def saleor_order_paid_webhook(request):
    """
    Handle Saleor 'order-paid' webhook.
    """
    if request.method != 'POST':
        return HttpResponse(status=405)

    # TODO: Verify Saleor-Signature header if SALEOR_WEBHOOK_SECRET is set

    try:
        payload = json.loads(request.body)
        order = payload.get("order")
        if not order:
            return HttpResponse("Missing order data", status=400)

        email = order.get("userEmail")
        lines = order.get("lines", [])

        for line in lines:
            variant = line.get("variant")
            if not variant:
                continue
            
            saleor_variant_id = variant.get("id")
            
            # Find the Event associated with this Saleor variant
            try:
                event = Event.objects.get(saleor_variant_id=saleor_variant_id)
                
                # Create EventRegistration in ECP
                EventRegistration.objects.get_or_create(
                    event=event,
                    user_email=email,
                    defaults={
                        "registration_date": timezone.now(),
                        "status": "confirmed",
                        "payment_status": "paid",
                    }
                )
                logger.info(f"Created registration for {email} to event {event.id} via Saleor webhook.")
            except Event.DoesNotExist:
                logger.warning(f"No Event found for Saleor variant ID: {saleor_variant_id}")

        return HttpResponse(status=200)
    except Exception as e:
        logger.error(f"Error processing Saleor webhook: {e}")
        return HttpResponse(status=500)
