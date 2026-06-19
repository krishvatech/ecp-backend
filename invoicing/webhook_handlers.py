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
    """Handle Saleor order webhooks for offline/manual payment invoices."""
    if not getattr(settings, "SALEOR_ENABLED", False):
        logger.info("Saleor integration disabled. Ignoring Saleor order webhook.")
        return JsonResponse({"status": "ignored", "reason": "Saleor integration disabled"}, status=200)

    signature = request.headers.get('X-Saleor-Signature', '')
    secret = getattr(settings, "SALEOR_WEBHOOK_SECRET", "")

    body = request.body
    if secret:
        expected_sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return JsonResponse({'error': 'Invalid signature'}, status=401)

    event_data = json.loads(body)
    event_type = str(event_data.get('event') or event_data.get('type') or '').upper()
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
