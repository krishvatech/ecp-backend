"""
Handles webhooks from Saleor and Stripe
"""
import json
import logging
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import hmac
import hashlib

logger = logging.getLogger('invoicing')

@csrf_exempt
@require_http_methods(["POST"])
def saleor_order_webhook(request):
    """Handle Saleor ORDER_CREATED, ORDER_CANCELLED, ORDER_FULLY_PAID events"""
    signature = request.headers.get('X-Saleor-Signature', '')
    secret = settings.SALEOR_WEBHOOK_SECRET

    # Verify signature
    body = request.body
    expected_sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        return JsonResponse({'error': 'Invalid signature'}, status=401)

    event_data = json.loads(body)
    event_type = event_data.get('event')

    if event_type == 'order_created':
        from invoicing.tasks import create_invoice_from_saleor_order
        create_invoice_from_saleor_order.delay(event_data['order']['id'])

    elif event_type == 'order_cancelled':
        # Handle order cancellation
        pass

    return JsonResponse({'ok': True})

@csrf_exempt
@require_http_methods(["POST"])
def stripe_payment_webhook(request, entity_code):
    """Handle Stripe payment webhooks per entity"""
    event_json = request.body
    sig_header = request.headers.get('Stripe-Signature')

    stripe_config = settings.STRIPE_CONFIG.get(entity_code)
    if not stripe_config:
        return JsonResponse({'error': 'Invalid entity'}, status=400)

    # Verify webhook signature
    import stripe
    try:
        event = stripe.Webhook.construct_event(
            event_json, sig_header, stripe_config['webhook_secret']
        )
    except ValueError:
        return JsonResponse({'error': 'Invalid payload'}, status=400)
    except stripe.error.SignatureVerificationError:
        return JsonResponse({'error': 'Invalid signature'}, status=400)

    if event['type'] == 'payment_intent.succeeded':
        from invoicing.tasks import record_payment_event
        record_payment_event.delay(
            entity_code,
            event['data']['object']['id'],
            'payment',
            event['data']['object']['amount'] / 100
        )

    elif event['type'] == 'charge.refunded':
        from invoicing.tasks import record_payment_event
        record_payment_event.delay(
            entity_code,
            event['data']['object']['id'],
            'refund',
            event['data']['object']['amount_refunded'] / 100
        )

    return JsonResponse({'ok': True})
