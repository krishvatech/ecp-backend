"""
Management command to reconcile pending payments against invoices
Detects early payment discounts (skonto) and creates credit notes
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from invoicing.models import Invoice, PaymentEvent, CreditNote
from decimal import Decimal
import logging

logger = logging.getLogger('invoicing')


class Command(BaseCommand):
    help = 'Reconcile pending payments and apply skonto discounts'

    def add_arguments(self, parser):
        parser.add_argument(
            '--entity',
            type=str,
            default='CH',
            help='Legal entity code (default: CH)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes'
        )

    def handle(self, *args, **options):
        entity_code = options['entity']
        dry_run = options['dry_run']

        try:
            invoices = Invoice.objects.filter(
                legal_entity__code=entity_code
            ).exclude(state='paid')

            skonto_applied = 0
            for invoice in invoices:
                if self._check_skonto_eligible(invoice):
                    if not dry_run:
                        self._apply_skonto(invoice)
                    skonto_applied += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'Skonto eligible: {invoice.number}')
                    )

            self.stdout.write(
                self.style.SUCCESS(
                    f'Reconciliation complete: {skonto_applied} invoices eligible for skonto'
                )
            )

        except Exception as e:
            logger.error(f"Reconciliation error: {str(e)}")
            self.stdout.write(self.style.ERROR(f'Error: {str(e)}'))

    def _check_skonto_eligible(self, invoice):
        """Check if invoice qualifies for skonto discount"""
        if not invoice.skonto_deadline:
            return False

        events = invoice.payment_events.filter(event_type='payment')
        if not events.exists():
            return False

        # Check if paid on time
        latest_payment = events.order_by('-timestamp').first()
        if latest_payment.timestamp.date() > invoice.skonto_deadline:
            return False

        # Check if already applied
        if invoice.credit_notes.filter(reason='skonto').exists():
            return False

        return True

    def _apply_skonto(self, invoice):
        """Create credit note for skonto discount"""
        skonto_amount = (
            invoice.total_gross *
            Decimal(str(0.10))  # 10% discount
        )

        CreditNote.objects.create(
            number=self._generate_credit_note_number(invoice),
            original_invoice=invoice,
            reason='skonto',
            amount=skonto_amount,
        )

        logger.info(f"Applied skonto to {invoice.number}: {skonto_amount}")

    def _generate_credit_note_number(self, invoice):
        """Generate unique credit note number"""
        from datetime import datetime
        year = datetime.now().year
        count = CreditNote.objects.filter(
            original_invoice__legal_entity=invoice.legal_entity,
            issued_date__year=year,
        ).count() + 1
        return f"IMAA-{invoice.legal_entity.code}-CN-{year}-{count:05d}"
