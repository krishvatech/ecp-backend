"""
Handles webhooks from Saleor and Stripe.
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


def _verify_saleor_signature(request) -> bool:
    secret = getattr(settings, 'SALEOR_WEBHOOK_SECRET', '')
    if not secret:
        return True
    signature = (
        request.headers.get('Saleor-Signature')
        or request.headers.get('X-Saleor-Signature')
        or request.headers.get('X-Saleor-HMAC-SHA256')
        or ''
    )
    expected_sig = hmac.new(secret.encode(), request.body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected_sig)


def _event_type(request, payload):
    return str(
        payload.get('event')
        or request.headers.get('Saleor-Event')
        or request.headers.get('X-Saleor-Event')
        or ''
    ).strip().lower().replace('-', '_')


@csrf_exempt
@require_http_methods(["POST"])
def saleor_order_webhook(request):
    """Handle Saleor paid-order events for invoice generation."""
    if not getattr(settings, "SALEOR_ENABLED", False):
        logger.info("Saleor integration disabled. Ignoring Saleor order webhook.")
        return JsonResponse({"status": "ignored", "reason": "Saleor integration disabled"}, status=200)

    if not _verify_saleor_signature(request):
        return JsonResponse({'error': 'Invalid signature'}, status=401)

    try:
        event_data = json.loads(request.body or b'{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    event_type = _event_type(request, event_data)
    order = event_data.get('order') or event_data.get('data', {}).get('order') or event_data
    order_id = order.get('id') if isinstance(order, dict) else None
    if not order_id:
        return JsonResponse({'error': 'Missing order id'}, status=400)

    paid_events = {'order_paid', 'order_fully_paid', 'orderpaid', 'orderfullypaid'}
    if event_type and event_type not in paid_events:
        return JsonResponse({'ok': True, 'ignored_event': event_type}, status=200)

    from invoicing.tasks import create_invoice_from_saleor_order
    create_invoice_from_saleor_order.delay(order_id)
    return JsonResponse({'ok': True, 'invoice_queued': True})


@csrf_exempt
@require_http_methods(["POST"])
def stripe_payment_webhook(request, entity_code):
    """Handle Stripe payment webhooks per entity. Kept for backwards compatibility."""
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
