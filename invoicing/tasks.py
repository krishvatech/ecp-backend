from celery import shared_task
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.core.files.storage import default_storage
from django.conf import settings
from invoicing.models import Invoice, PaymentEvent, LegalEntity, Customer, InvoiceLine
from decimal import Decimal
from datetime import datetime, timedelta
import logging

logger = logging.getLogger('invoicing')

@shared_task
def create_invoice_from_saleor_order(saleor_order_id):
    """
    Create Invoice from Saleor ORDER_CREATED webhook

    Args:
        saleor_order_id: Order ID from Saleor (GraphQL ID)
    """
    try:
        logger.info(f"Processing Saleor order: {saleor_order_id}")

        # Check if invoice already exists (idempotency)
        if Invoice.objects.filter(saleor_order_id=saleor_order_id).exists():
            logger.warning(f"Invoice already exists for order {saleor_order_id}")
            return

        # TODO: Fetch order from Saleor API
        # This requires implementing Saleor GraphQL client
        # For now, log that this needs implementation
        logger.info(f"TODO: Fetch order details from Saleor for {saleor_order_id}")

        # Once order is fetched:
        # 1. Extract customer info from order
        # 2. Find or create Customer record
        # 3. Create Invoice record
        # 4. Create InvoiceLine for each order item
        # 5. Generate PDF
        # 6. Send email

    except Exception as e:
        logger.error(f"Error creating invoice from Saleor order: {str(e)}")
        raise

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
