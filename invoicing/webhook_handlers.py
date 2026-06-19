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


def _normalize_saleor_event_type(value):
    """Return a stable Saleor webhook event type.

    Saleor commonly sends the event type in the X-Saleor-Event header,
    while some test/custom payloads include it in the JSON body as event/type.
    """
    if isinstance(value, dict):
        value = value.get('type') or value.get('name') or value.get('event') or ''
    return str(value or '').strip().replace('-', '_').upper()


def _saleor_event_type_from_request(request, payload):
    return _normalize_saleor_event_type(
        request.headers.get('X-Saleor-Event')
        or request.headers.get('Saleor-Event')
        or request.headers.get('X-Saleor-Webhook-Event')
        or payload.get('event')
        or payload.get('type')
        or payload.get('name')
    )

@csrf_exempt
@require_http_methods(["POST"])
def saleor_order_webhook(request):
    """Handle Saleor order webhooks for offline/manual payment invoices."""
    if not getattr(settings, "SALEOR_ENABLED", False):
        logger.info("Saleor integration disabled. Ignoring Saleor order webhook.")
        return JsonResponse({"status": "ignored", "reason": "Saleor integration disabled"}, status=200)

    from orders.saleor_webhook_security import verify_saleor_webhook
    if not verify_saleor_webhook(request):
        return JsonResponse({'error': 'Invalid signature'}, status=401)

    body = request.body
    try:
        event_data = json.loads(body or b'{}')
    except json.JSONDecodeError:
        logger.warning("Invalid Saleor webhook JSON received")
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    event_type = _saleor_event_type_from_request(request, event_data)
    logger.info("Received Saleor webhook event_type=%s keys=%s", event_type, list(event_data.keys()) if isinstance(event_data, dict) else type(event_data).__name__)

    if not event_type:
        return JsonResponse({'status': 'ignored', 'reason': 'missing_event_type'}, status=200)

    if event_type in {'ADDRESS_CREATED', 'ADDRESS_UPDATED'}:
        from orders.saleor_address_sync import apply_saleor_address_webhook_payload
        address = apply_saleor_address_webhook_payload(event_data)
        return JsonResponse({'ok': True, 'address_synced': bool(address)})

    if event_type == 'ADDRESS_DELETED':
        from orders.models import BillingAddress
        address_data = event_data.get('address') or event_data.get('data') or {}
        saleor_address_id = address_data.get('id') or event_data.get('addressId') or ''
        if saleor_address_id:
            BillingAddress.objects.filter(saleor_address_id=saleor_address_id).update(
                saleor_address_id='',
                saleor_sync_status='not_synced',
                saleor_sync_error='Saleor address was deleted.',
                last_sync_source='saleor',
            )
        return JsonResponse({'ok': True})

    order = event_data.get('order') or {}
    saleor_order_id = order.get('id')

    if not saleor_order_id:
        return JsonResponse({'error': 'Missing order.id'}, status=400)

    if event_type in {'ORDER_CREATED', 'ORDER_CONFIRMED', 'ORDER_CREATED'.lower().upper()}:
        from invoicing.tasks import create_invoice_from_saleor_order
        create_invoice_from_saleor_order.delay(saleor_order_id)

    elif event_type in {'ORDER_PAID', 'ORDER_FULLY_PAID'}:
        from invoicing.tasks import record_saleor_order_payment
        transaction_reference = order.get('paymentReference') or order.get('number') or saleor_order_id
        record_saleor_order_payment.delay(saleor_order_id, transaction_reference, 'manual')

    elif event_type == 'ORDER_CANCELLED':
        # Starter behavior: invoice cancellation/credit-note logic can be added later.
        logger.info(f"Saleor order cancelled: {saleor_order_id}")

    return JsonResponse({'ok': True})
