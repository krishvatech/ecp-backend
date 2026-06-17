from celery import shared_task
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.core.files.storage import default_storage
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from invoicing.models import Invoice, PaymentEvent, LegalEntity, Customer, InvoiceLine, InvoiceSequence
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timedelta
from urllib.parse import urljoin
import logging

logger = logging.getLogger('invoicing')

def _decimal_money(value):
    return Decimal(str(value or "0.00")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _taxed_money_amount(data, bucket="gross"):
    return _decimal_money(((data or {}).get(bucket) or {}).get("amount"))


def _default_legal_entity():
    code = getattr(settings, "INVOICE_LEGAL_ENTITY_CODE", "CH") or "CH"
    defaults = {
        "name": getattr(settings, "INVOICE_LEGAL_ENTITY_NAME", "IMAA Switzerland GmbH"),
        "legal_form": getattr(settings, "INVOICE_LEGAL_ENTITY_FORM", "GmbH"),
        "address": getattr(settings, "INVOICE_LEGAL_ENTITY_ADDRESS", ""),
        "country": getattr(settings, "INVOICE_LEGAL_ENTITY_COUNTRY", "CH"),
        "vat_id": getattr(settings, "INVOICE_LEGAL_ENTITY_VAT_ID", ""),
        "bank_details": getattr(settings, "INVOICE_LEGAL_ENTITY_BANK_DETAILS", {}),
        "currency": getattr(settings, "INVOICE_CURRENCY", "USD"),
        "vat_exempt": getattr(settings, "INVOICE_VAT_EXEMPT", True),
    }
    entity, _ = LegalEntity.objects.get_or_create(code=code, defaults=defaults)
    return entity


def _next_invoice_number(legal_entity, issue_date):
    year = int(issue_date.year)
    with transaction.atomic():
        sequence, _ = InvoiceSequence.objects.select_for_update().get_or_create(
            legal_entity=legal_entity,
            series="INV",
            year=year,
            defaults={"last_number": 0},
        )
        sequence.last_number += 1
        sequence.save(update_fields=["last_number", "updated_at"])
        return f"IMAA-{legal_entity.code}-INV-{year}-{sequence.last_number:05d}"


def _invoice_public_url(invoice):
    """Return a full public/signed-ish URL for Saleor invoiceCreate."""
    base = (
        getattr(settings, "INVOICE_PUBLIC_BASE_URL", "")
        or getattr(settings, "BACKEND_PUBLIC_URL", "")
        or ""
    ).strip().rstrip("/")
    if base:
        return f"{base}/api/invoices/public/{invoice.public_download_token}/"

    if invoice.pdf_storage_reference:
        try:
            url = default_storage.url(invoice.pdf_storage_reference)
            if str(url).startswith(("http://", "https://")):
                return url
        except Exception:
            logger.warning("Could not build storage URL for invoice %s", invoice.number, exc_info=True)
    return ""


def _attach_invoice_to_saleor(invoice, saleor_order_id):
    public_url = _invoice_public_url(invoice)
    if not public_url:
        logger.warning(
            "Skipping Saleor invoiceCreate for %s because BACKEND_PUBLIC_URL/INVOICE_PUBLIC_BASE_URL is not configured.",
            invoice.number,
        )
        return None

    from events.saleor_sync import call_saleor_gql
    mutation = """
    mutation EcpInvoiceCreate($orderId: ID!, $input: InvoiceCreateInput!) {
      invoiceCreate(orderId: $orderId, input: $input) {
        invoice { id number url status }
        errors { field message code }
      }
    }
    """
    variables = {
        "orderId": saleor_order_id,
        "input": {
            "number": invoice.number,
            "url": public_url,
            "metadata": [
                {"key": "ecp_invoice_id", "value": str(invoice.id)},
                {"key": "ecp_invoice_number", "value": invoice.number},
            ],
            "privateMetadata": [
                {"key": "ecp_invoice_id", "value": str(invoice.id)},
                {"key": "ecp_saleor_order_id", "value": saleor_order_id},
            ],
        },
    }
    response = call_saleor_gql(mutation, variables)
    result = response.get("data", {}).get("invoiceCreate", {})
    errors = result.get("errors") or []
    if errors:
        message = "; ".join(f"{e.get('field') or 'general'}: {e.get('message') or e.get('code')}" for e in errors)
        raise RuntimeError(f"Saleor invoiceCreate failed for {invoice.number}: {message}")

    saleor_invoice = result.get("invoice")
    if saleor_invoice and saleor_invoice.get("id"):
        invoice.saleor_invoice_id = saleor_invoice["id"]
        invoice.save(update_fields=["saleor_invoice_id", "updated_at"])
        logger.info("Attached invoice %s to Saleor order %s", invoice.number, saleor_order_id)
    return saleor_invoice


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def create_invoice_from_saleor_order(self, saleor_order_id):
    """
    Create a local invoice from a paid Saleor order and attach the invoice URL back to Saleor.

    Safe to call multiple times; saleor_order_id is unique on Invoice.
    """
    if not getattr(settings, "SALEOR_ENABLED", False):
        logger.info("Saleor integration disabled. Skipping invoice for order %s.", saleor_order_id)
        return {"skipped": True, "reason": "Saleor integration disabled"}

    from orders.saleor_checkout import fetch_saleor_order
    from invoicing.pdf_generator import generate_invoice_pdf

    order = fetch_saleor_order(saleor_order_id)
    if not order.get("isPaid"):
        logger.info("Saleor order %s is not paid yet; invoice not generated.", saleor_order_id)
        return {"skipped": True, "reason": "order_not_paid"}

    existing = Invoice.objects.filter(saleor_order_id=saleor_order_id).first()
    if existing:
        if not existing.pdf_storage_reference:
            existing.pdf_storage_reference = generate_invoice_pdf(existing)
            existing.save(update_fields=["pdf_storage_reference", "updated_at"])
        if not existing.saleor_invoice_id:
            # If Saleor already has this invoice number from a previous retry, just store its id.
            for saleor_invoice in order.get("invoices") or []:
                if saleor_invoice.get("number") == existing.number:
                    existing.saleor_invoice_id = saleor_invoice.get("id", "")
                    existing.save(update_fields=["saleor_invoice_id", "updated_at"])
                    break
        if not existing.saleor_invoice_id:
            _attach_invoice_to_saleor(existing, saleor_order_id)
        logger.info("Invoice already exists for Saleor order %s: %s", saleor_order_id, existing.number)
        return {"invoice_id": existing.id, "number": existing.number, "existing": True}

    email = order.get("userEmail") or (order.get("user") or {}).get("email")
    if not email:
        logger.warning("Saleor order %s has no userEmail; invoice skipped", saleor_order_id)
        return {"skipped": True, "reason": "missing_email"}

    user = get_user_model().objects.filter(email__iexact=email).first()
    if not user:
        logger.warning("No local user found for Saleor order %s email=%s; invoice skipped", saleor_order_id, email)
        return {"skipped": True, "reason": "local_user_not_found", "email": email}

    issue_date = timezone.now().date()
    due_date = issue_date
    total = order.get("total") or {}
    total_net = _taxed_money_amount(total, "net")
    total_vat = _taxed_money_amount(total, "tax")
    total_gross = _taxed_money_amount(total, "gross")
    currency = ((total.get("gross") or {}).get("currency") or getattr(settings, "INVOICE_CURRENCY", "USD")).upper()

    legal_entity = _default_legal_entity()
    customer, _ = Customer.objects.get_or_create(
        user=user,
        defaults={
            "saleor_customer_id": str(((order.get("user") or {}).get("id") or "")),
            "preferred_language": "en",
        },
    )

    with transaction.atomic():
        # Re-check inside the transaction to protect against concurrent webhook retries.
        existing = Invoice.objects.select_for_update().filter(saleor_order_id=saleor_order_id).first()
        if existing:
            return {"invoice_id": existing.id, "number": existing.number, "existing": True}

        number = _next_invoice_number(legal_entity, issue_date)
        invoice = Invoice.objects.create(
            number=number,
            legal_entity=legal_entity,
            customer=customer,
            saleor_order_id=saleor_order_id,
            saleor_order_number=str(order.get("number") or ""),
            issue_date=issue_date,
            due_date=due_date,
            total_net=total_net,
            total_vat=total_vat,
            total_gross=total_gross,
            currency=currency,
            language="en",
        )

        for line in order.get("lines") or []:
            variant = line.get("variant") or {}
            product = variant.get("product") or {}
            description_parts = [line.get("productName") or product.get("name") or "Event"]
            if line.get("variantName"):
                description_parts.append(line["variantName"])
            description = " - ".join([p for p in description_parts if p])[:255]

            unit_price = _taxed_money_amount(line.get("unitPrice"), "net")
            net_amount = _taxed_money_amount(line.get("totalPrice"), "net")
            vat_amount = _taxed_money_amount(line.get("totalPrice"), "tax")
            tax_rate = _decimal_money(line.get("taxRate") or 0)

            InvoiceLine.objects.create(
                invoice=invoice,
                description=description,
                quantity=int(line.get("quantity") or 1),
                unit_price=unit_price,
                net_amount=net_amount,
                vat_rate=tax_rate,
                vat_amount=vat_amount,
                product_reference=variant.get("id") or product.get("id") or line.get("productSku") or "",
            )

        PaymentEvent.objects.create(
            invoice=invoice,
            event_type="payment",
            amount=total_gross,
            currency=currency,
            source=getattr(settings, "SALEOR_MANUAL_PAYMENT_SOURCE", "saleor_manual"),
            external_reference=saleor_order_id,
            notes=f"Saleor order {order.get('number') or saleor_order_id} marked paid manually/offline.",
        )

    invoice.pdf_storage_reference = generate_invoice_pdf(invoice)
    invoice.save(update_fields=["pdf_storage_reference", "updated_at"])
    _attach_invoice_to_saleor(invoice, saleor_order_id)
    send_invoice_email.delay(invoice.id)

    logger.info("Created invoice %s from Saleor order %s", invoice.number, saleor_order_id)
    return {"invoice_id": invoice.id, "number": invoice.number, "existing": False}

@shared_task
def record_payment_event(entity_code, external_ref, event_type, amount):
    """
    Record payment event and update invoice state

    Args:
        entity_code: Legal entity code (e.g., 'CH')
        external_ref: External payment reference (Stripe charge ID, etc.)
        event_type: 'payment', 'refund', or 'skonto_credit'
        amount: Payment amount in decimal
    """
    try:
        invoice = Invoice.objects.filter(
            legal_entity__code=entity_code,
            saleor_order_id=external_ref
        ).first()

        if not invoice:
            logger.error(f"Invoice not found for order {external_ref}")
            return

        # Create payment event
        event = PaymentEvent.objects.create(
            invoice=invoice,
            event_type=event_type,
            amount=Decimal(str(amount)),
            currency=invoice.currency,
            source='stripe',
            external_reference=external_ref,
        )

        logger.info(f"Recorded {event_type} for {invoice.number}: {amount}")

        # Trigger email if invoice is now fully paid
        if invoice.state == 'paid':
            send_payment_confirmation_email.delay(invoice.id)

    except Exception as e:
        logger.error(f"Error recording payment event: {str(e)}")
        raise

@shared_task
def generate_invoice_pdf_task(invoice_id):
    """
    Generate PDF for invoice and store to S3

    Args:
        invoice_id: Invoice primary key
    """
    try:
        invoice = Invoice.objects.get(id=invoice_id)
        from invoicing.pdf_generator import generate_invoice_pdf
        pdf_path = generate_invoice_pdf(invoice)
        invoice.pdf_storage_reference = pdf_path
        invoice.save()
        logger.info(f"Generated PDF for invoice {invoice.number}")
    except Invoice.DoesNotExist:
        logger.error(f"Invoice {invoice_id} not found")
    except Exception as e:
        logger.error(f"Error generating PDF for invoice {invoice_id}: {str(e)}")
        raise

@shared_task
def send_invoice_email(invoice_id):
    """
    Send invoice PDF to customer

    Args:
        invoice_id: Invoice primary key
    """
    try:
        invoice = Invoice.objects.get(id=invoice_id)

        # Retrieve PDF from storage
        if invoice.pdf_storage_reference:
            try:
                pdf_file = default_storage.open(invoice.pdf_storage_reference, 'rb')
                pdf_content = pdf_file.read()
                pdf_file.close()
            except Exception as e:
                logger.warning(f"PDF not found for {invoice.number}: {str(e)}")
                pdf_content = None
        else:
            logger.warning(f"No PDF reference for invoice {invoice.number}")
            pdf_content = None

        # Prepare email
        context = {
            'invoice': invoice,
            'portal_url': getattr(settings, 'FRONTEND_URL', 'https://example.com'),
            'skonto_config': getattr(settings, 'SKONTO_CONFIG', {}),
        }

        email = EmailMessage(
            subject=f'Your Invoice {invoice.number}',
            body=render_to_string('invoicing/invoice_email.html', context),
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'invoices@imaa.org'),
            to=[invoice.customer.user.email],
            reply_to=[settings.DEFAULT_REPLY_TO_EMAIL] if getattr(settings, "DEFAULT_REPLY_TO_EMAIL", "") else None,
        )
        email.content_subtype = 'html'

        # Attach PDF if available
        if pdf_content:
            email.attach(f'{invoice.number}.pdf', pdf_content, 'application/pdf')

        email.send()
        logger.info(f"Sent invoice email for {invoice.number}")

    except Invoice.DoesNotExist:
        logger.error(f"Invoice {invoice_id} not found")
    except Exception as e:
        logger.error(f"Error sending invoice email: {str(e)}")
        raise

@shared_task
def send_payment_confirmation_email(invoice_id):
    """
    Send payment confirmation email when invoice is paid

    Args:
        invoice_id: Invoice primary key
    """
    try:
        invoice = Invoice.objects.get(id=invoice_id)

        context = {
            'invoice': invoice,
            'portal_url': getattr(settings, 'FRONTEND_URL', 'https://example.com'),
        }

        email = EmailMessage(
            subject=f'Payment Received - Invoice {invoice.number}',
            body=render_to_string('invoicing/payment_confirmation_email.html', context),
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'invoices@imaa.org'),
            to=[invoice.customer.user.email],
            reply_to=[settings.DEFAULT_REPLY_TO_EMAIL] if getattr(settings, "DEFAULT_REPLY_TO_EMAIL", "") else None,
        )
        email.content_subtype = 'html'
        email.send()

        logger.info(f"Sent payment confirmation for {invoice.number}")

    except Invoice.DoesNotExist:
        logger.error(f"Invoice {invoice_id} not found")
    except Exception as e:
        logger.error(f"Error sending payment confirmation: {str(e)}")

@shared_task
def send_payment_reminders():
    """
    Send payment reminders for overdue invoices
    Runs daily via Celery Beat
    """
    try:
        from invoicing.models import Invoice
        overdue_count = 0

        invoices = Invoice.objects.all()
        for invoice in invoices:
            if invoice.state == 'overdue':
                send_payment_reminder_email.delay(invoice.id)
                overdue_count += 1

        logger.info(f"Sent {overdue_count} payment reminders")

    except Exception as e:
        logger.error(f"Error sending payment reminders: {str(e)}")

@shared_task
def send_payment_reminder_email(invoice_id):
    """
    Send a payment reminder email for an overdue invoice

    Args:
        invoice_id: Invoice primary key
    """
    try:
        invoice = Invoice.objects.get(id=invoice_id)

        context = {
            'invoice': invoice,
            'portal_url': getattr(settings, 'FRONTEND_URL', 'https://example.com'),
        }

        email = EmailMessage(
            subject=f'Payment Reminder - Invoice {invoice.number}',
            body=render_to_string('invoicing/payment_reminder_email.html', context),
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'invoices@imaa.org'),
            to=[invoice.customer.user.email],
            reply_to=[settings.DEFAULT_REPLY_TO_EMAIL] if getattr(settings, "DEFAULT_REPLY_TO_EMAIL", "") else None,
        )
        email.content_subtype = 'html'
        email.send()

        logger.info(f"Sent payment reminder for {invoice.number}")

    except Exception as e:
        logger.error(f"Error sending payment reminder email: {str(e)}")

@shared_task
def monthly_sanity_check():
    """
    Detect gaps in numbering, orphan transactions
    Runs monthly via Celery Beat
    """
    try:
        logger.info("Running monthly sanity check...")

        for le in LegalEntity.objects.all():
            # Check for numbering gaps
            year = datetime.now().year
            invoices = Invoice.objects.filter(
                legal_entity=le,
                issue_date__year=year
            ).order_by('number')

            if invoices.exists():
                numbers = []
                for inv in invoices:
                    try:
                        seq = int(inv.number.split('-')[-1])
                        numbers.append(seq)
                    except (ValueError, IndexError):
                        logger.warning(f"Invalid invoice number format: {inv.number}")

                # Check for gaps
                if numbers:
                    for i in range(min(numbers), max(numbers)):
                        if i not in numbers:
                            logger.warning(f"Gap in invoice numbering for {le.code}: {i} missing")

        logger.info("Monthly sanity check complete")

    except Exception as e:
        logger.error(f"Error in monthly sanity check: {str(e)}")
