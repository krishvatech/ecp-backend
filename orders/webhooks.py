import json
import logging
import hmac
import hashlib
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.db import transaction
from .models import Order

logger = logging.getLogger('orders')


def _saleor_signature_is_valid(request) -> bool:
    """Validate legacy HMAC Saleor signatures when SALEOR_WEBHOOK_SECRET is configured."""
    secret = getattr(settings, 'SALEOR_WEBHOOK_SECRET', '')
    if not secret:
        # Newer Saleor installs may use JWS signatures. If no local secret is configured,
        # do not block the webhook; rely on HTTPS + secret target URL/custom auth header.
        return True
    signature = (
        request.headers.get('Saleor-Signature')
        or request.headers.get('X-Saleor-Signature')
        or request.headers.get('X-Saleor-HMAC-SHA256')
        or ''
    )
    expected = hmac.new(secret.encode(), request.body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _event_type(request, payload) -> str:
    raw = (
        payload.get('event')
        or request.headers.get('Saleor-Event')
        or request.headers.get('X-Saleor-Event')
        or ''
    )
    return str(raw).strip().lower().replace('-', '_')


@csrf_exempt
def saleor_order_paid_webhook(request):
    """
    Handle Saleor paid-order webhook.

    Confirms local EventRegistration rows and queues invoice generation. The task is
    idempotent, so duplicate Saleor webhook deliveries are safe.
    """
    if request.method != 'POST':
        return HttpResponse(status=405)

    if not getattr(settings, 'SALEOR_ENABLED', False):
        logger.info('Saleor disabled; ignoring order-paid webhook')
        return HttpResponse(status=200)

    if not _saleor_signature_is_valid(request):
        logger.warning('Invalid Saleor webhook signature')
        return HttpResponse(status=401)

    try:
        payload = json.loads(request.body or b'{}')
        order = payload.get('order') or payload.get('data', {}).get('order') or payload
        if not isinstance(order, dict) or not order.get('id'):
            return HttpResponse('Missing order data', status=400)

        event = _event_type(request, payload)
        paid_events = {'order_paid', 'order_fully_paid', 'orderfullypaid', 'orderpaid'}
        if event and event not in paid_events:
            logger.info('Ignoring Saleor event %s for order %s', event, order.get('id'))
            return HttpResponse(status=200)

        from .saleor_checkout import confirm_registrations_for_saleor_order, fetch_saleor_order
        from invoicing.tasks import create_invoice_from_saleor_order

        # Webhook subscription payloads differ by Saleor version/configuration. Fetch the
        # full order if lines/userEmail were not included in the subscription query.
        if not order.get('lines') or not order.get('userEmail'):
            order = fetch_saleor_order(order['id'])

        with transaction.atomic():
            local_order = Order.objects.select_for_update().filter(saleor_order_id=order['id']).first()
            if local_order:
                local_order.status = 'paid'
                if order.get('number'):
                    local_order.saleor_order_number = str(order.get('number'))
                local_order.save(update_fields=['status', 'saleor_order_number', 'updated_at'])

            registrations_confirmed = confirm_registrations_for_saleor_order(
                order,
                payment_reference=(local_order.payment_reference if local_order else order['id']),
            )

        create_invoice_from_saleor_order.delay(order['id'])
        logger.info(
            'Saleor paid webhook processed for order %s; confirmed %s registration(s)',
            order['id'], registrations_confirmed,
        )
        return HttpResponse(status=200)

    except json.JSONDecodeError:
        logger.error('Invalid JSON in Saleor webhook payload')
        return HttpResponse('Invalid JSON', status=400)
    except Exception as e:
        logger.error('Error processing Saleor paid webhook: %s', e, exc_info=True)
        return HttpResponse(status=500)
