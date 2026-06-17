from celery import shared_task
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.core.files.storage import default_storage
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from invoicing.models import Invoice, PaymentEvent, LegalEntity, Customer, InvoiceLine
from decimal import Decimal
from datetime import datetime, timedelta
import logging

logger = logging.getLogger('invoicing')

def _money_amount(node, default="0"):
    try:
        return Decimal(str((node or {}).get("amount", default)))
    except Exception:
        return Decimal(default)


def _metadata_to_dict(items):
    return {m.get("key"): m.get("value") for m in (items or []) if m.get("key")}


def _get_or_create_default_legal_entity():
    entity_code = getattr(settings, "DEFAULT_LEGAL_ENTITY_CODE", "CH")
    config = getattr(settings, "LEGAL_ENTITIES", {}).get(entity_code, {})
    legal_entity, _ = LegalEntity.objects.get_or_create(
        code=entity_code,
        defaults={
            "name": config.get("name", "IMAA Switzerland GmbH"),
            "legal_form": config.get("legal_form", "Swiss GmbH"),
            "address": config.get("address", ""),
            "country": config.get("country", entity_code),
            "currency": config.get("currency", "USD"),
            "vat_exempt": config.get("vat_exempt", True),
            "bank_details": config.get("bank_details", {}),
        },
    )
    return legal_entity


def _next_invoice_number(legal_entity):
    year = timezone.now().year
    counter_field = f"inv_counter_{year}"

    if hasattr(legal_entity, counter_field):
        current = getattr(legal_entity, counter_field) or 0
        next_value = current + 1
        setattr(legal_entity, counter_field, next_value)
        legal_entity.save(update_fields=[counter_field])
    else:
        next_value = Invoice.objects.filter(
            legal_entity=legal_entity,
            issue_date__year=year,
        ).count() + 1

    return f"IMAA-{legal_entity.code}-INV-{year}-{next_value:05d}"


def _resolve_user_from_saleor_order(order):
    User = get_user_model()
    private_metadata = _metadata_to_dict(order.get("privateMetadata"))
    user_id = private_metadata.get("ecp_user_id")
    if user_id:
        user = User.objects.filter(id=user_id).first()
        if user:
            return user

    email = (order.get("userEmail") or "").strip()
    if email:
        return User.objects.filter(email__iexact=email).first()
    return None


@shared_task
def create_invoice_from_saleor_order(saleor_order_id):
    """Create an issued invoice from a Saleor order.

    This is idempotent and safe for both manual checkout call and Saleor
    ORDER_CREATED webhook. It does not mark the invoice paid; payment is
    recorded only after manual/admin payment confirmation.
    """
    if not getattr(settings, "SALEOR_ENABLED", False):
        logger.info(f"Saleor integration disabled. Skipping create_invoice_from_saleor_order for order {saleor_order_id}.")
        return {"skipped": True, "reason": "Saleor integration disabled"}

    try:
        logger.info(f"Processing Saleor order for invoice: {saleor_order_id}")

        existing = Invoice.objects.filter(saleor_order_id=saleor_order_id).first()
        if existing:
            logger.info(f"Invoice already exists for Saleor order {saleor_order_id}: {existing.number}")
            return {"invoice_id": existing.id, "number": existing.number, "created": False}

        from orders.saleor_checkout import fetch_saleor_order
        saleor_order = fetch_saleor_order(saleor_order_id)
        user = _resolve_user_from_saleor_order(saleor_order)
        if not user:
            raise ValueError(f"Could not resolve ECP user for Saleor order {saleor_order_id}")

        totals = saleor_order.get("total") or {}
        gross = _money_amount((totals.get("gross") or {}))
        net = _money_amount((totals.get("net") or {}), default=str(gross))
        tax = _money_amount((totals.get("tax") or {}))
        currency = (totals.get("gross") or {}).get("currency") or getattr(settings, "DEFAULT_CURRENCY", "USD")

        issue_date = timezone.now().date()
        due_days = int(getattr(settings, "OFFLINE_PAYMENT_DUE_DAYS", 14))
        skonto_days = int(getattr(settings, "SKONTO_CONFIG", {}).get("days", 0) or 0)
        skonto_percentage = Decimal(str(getattr(settings, "SKONTO_CONFIG", {}).get("percentage", 0) or 0))

        with transaction.atomic():
            legal_entity = LegalEntity.objects.select_for_update().get(pk=_get_or_create_default_legal_entity().pk)
            customer, _ = Customer.objects.get_or_create(user=user)

            invoice = Invoice.objects.create(
                number=_next_invoice_number(legal_entity),
                legal_entity=legal_entity,
                customer=customer,
                saleor_order_id=saleor_order_id,
                issue_date=issue_date,
                due_date=issue_date + timedelta(days=due_days),
                skonto_deadline=issue_date + timedelta(days=skonto_days) if skonto_days else None,
                skonto_amount=(gross * skonto_percentage / Decimal("100.00")) if skonto_percentage else Decimal("0.00"),
                total_net=net,
                total_vat=tax,
                total_gross=gross,
                currency=currency,
                language="en",
            )

            for line in saleor_order.get("lines") or []:
                unit = line.get("unitPrice") or {}
                total = line.get("totalPrice") or {}
                unit_gross = _money_amount(unit.get("gross") or {})
                line_gross = _money_amount(total.get("gross") or {})
                line_net = _money_amount(total.get("net") or {}, default=str(line_gross))
                line_tax = _money_amount(total.get("tax") or {})
                variant = line.get("variant") or {}
                product = variant.get("product") or {}

                InvoiceLine.objects.create(
                    invoice=invoice,
                    description=line.get("productName") or product.get("name") or "Event ticket",
                    quantity=int(line.get("quantity") or 1),
                    unit_price=unit_gross,
                    net_amount=line_net,
                    vat_rate=Decimal("0.00"),
                    vat_amount=line_tax,
                    product_reference=product.get("id") or variant.get("id") or "",
                )

        generate_invoice_pdf_task.delay(invoice.id)
        send_invoice_email.delay(invoice.id)
        logger.info(f"Created invoice {invoice.number} for Saleor order {saleor_order_id}")
        return {"invoice_id": invoice.id, "number": invoice.number, "created": True}

    except Exception as e:
        logger.error(f"Error creating invoice from Saleor order: {str(e)}")
        raise


@shared_task
def record_saleor_order_payment(saleor_order_id, external_ref="", source="manual"):
    """Record manual payment against invoice linked to a Saleor order."""
    invoice = Invoice.objects.filter(saleor_order_id=saleor_order_id).first()
    if not invoice:
        logger.warning(f"Invoice not found for paid Saleor order {saleor_order_id}; creating invoice first.")
        create_invoice_from_saleor_order(saleor_order_id)
        invoice = Invoice.objects.filter(saleor_order_id=saleor_order_id).first()

    if not invoice:
        logger.error(f"Could not create/find invoice for Saleor order {saleor_order_id}")
        return

    ref = external_ref or saleor_order_id
    if PaymentEvent.objects.filter(invoice=invoice, event_type="payment", external_reference=ref).exists():
        return {"invoice_id": invoice.id, "already_recorded": True}

    PaymentEvent.objects.create(
        invoice=invoice,
        event_type="payment",
        amount=invoice.total_gross,
        currency=invoice.currency,
        source=source if source in {"manual", "wise"} else "manual",
        external_reference=ref,
        notes="Payment recorded from Saleor paid-order webhook.",
    )

    if invoice.state == "paid":
        send_payment_confirmation_email.delay(invoice.id)

    return {"invoice_id": invoice.id, "paid": invoice.state == "paid"}

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
