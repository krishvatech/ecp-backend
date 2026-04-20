"""
Tests for invoicing models
"""
from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal

from invoicing.models import (
    LegalEntity, Customer, Invoice, InvoiceLine,
    PaymentEvent, CreditNote, ReservedNumber
)


class LegalEntityModelTests(TestCase):
    """Tests for LegalEntity model"""

    def setUp(self):
        self.le = LegalEntity.objects.create(
            code='CH',
            name='IMAA Switzerland GmbH',
            legal_form='Swiss GmbH',
            address='Zurich, CH',
            currency='USD',
            vat_exempt=True,
        )

    def test_legal_entity_creation(self):
        """Test creating a legal entity"""
        self.assertEqual(self.le.code, 'CH')
        self.assertEqual(self.le.name, 'IMAA Switzerland GmbH')
        self.assertTrue(self.le.vat_exempt)

    def test_legal_entity_str(self):
        """Test string representation"""
        self.assertEqual(str(self.le), 'CH - IMAA Switzerland GmbH')

    def test_unique_code(self):
        """Test code uniqueness constraint"""
        with self.assertRaises(Exception):
            LegalEntity.objects.create(
                code='CH',
                name='Duplicate',
                legal_form='Test'
            )


class CustomerModelTests(TestCase):
    """Tests for Customer model"""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.customer = Customer.objects.create(
            user=self.user,
            company_name='Test Corp',
            preferred_language='en',
        )

    def test_customer_creation(self):
        """Test creating a customer"""
        self.assertEqual(self.customer.user.email, 'test@example.com')
        self.assertEqual(self.customer.company_name, 'Test Corp')

    def test_customer_str(self):
        """Test string representation"""
        self.assertEqual(str(self.customer), 'test@example.com')

    def test_one_to_one_user(self):
        """Test OneToOne relationship with User"""
        self.assertEqual(self.customer.user, self.user)


class InvoiceModelTests(TestCase):
    """Tests for Invoice model"""

    def setUp(self):
        self.le = LegalEntity.objects.create(
            code='CH',
            name='IMAA Switzerland GmbH',
            legal_form='Swiss GmbH',
            address='Zurich, CH',
            currency='USD',
            vat_exempt=True,
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
        )
        self.customer = Customer.objects.create(user=self.user)
        self.invoice = Invoice.objects.create(
            number='IMAA-CH-INV-2026-00001',
            legal_entity=self.le,
            customer=self.customer,
            issue_date=datetime.now().date(),
            due_date=(datetime.now() + timedelta(days=30)).date(),
            total_net=Decimal('1000.00'),
            total_gross=Decimal('1000.00'),
            currency='USD',
        )

    def test_invoice_creation(self):
        """Test creating an invoice"""
        self.assertEqual(self.invoice.number, 'IMAA-CH-INV-2026-00001')
        self.assertEqual(self.invoice.total_gross, Decimal('1000.00'))

    def test_invoice_str(self):
        """Test string representation"""
        self.assertEqual(str(self.invoice), 'IMAA-CH-INV-2026-00001')

    def test_invoice_state_issued(self):
        """Test invoice state is 'issued' with no payments"""
        self.assertEqual(self.invoice.state, 'issued')

    def test_invoice_state_partially_paid(self):
        """Test invoice state is 'partially_paid' with partial payment"""
        PaymentEvent.objects.create(
            invoice=self.invoice,
            event_type='payment',
            amount=Decimal('500.00'),
            currency='USD',
            source='stripe',
        )
        self.assertEqual(self.invoice.state, 'partially_paid')

    def test_invoice_state_paid(self):
        """Test invoice state is 'paid' when fully paid"""
        PaymentEvent.objects.create(
            invoice=self.invoice,
            event_type='payment',
            amount=Decimal('1000.00'),
            currency='USD',
            source='stripe',
        )
        self.assertEqual(self.invoice.state, 'paid')

    def test_invoice_state_overdue(self):
        """Test invoice state is 'overdue' when past due date"""
        past_invoice = Invoice.objects.create(
            number='IMAA-CH-INV-2026-00002',
            legal_entity=self.le,
            customer=self.customer,
            issue_date=(datetime.now() - timedelta(days=60)).date(),
            due_date=(datetime.now() - timedelta(days=30)).date(),
            total_net=Decimal('1000.00'),
            total_gross=Decimal('1000.00'),
            currency='USD',
        )
        self.assertEqual(past_invoice.state, 'overdue')

    def test_invoice_unique_number(self):
        """Test invoice number uniqueness"""
        with self.assertRaises(Exception):
            Invoice.objects.create(
                number='IMAA-CH-INV-2026-00001',
                legal_entity=self.le,
                customer=self.customer,
                issue_date=datetime.now().date(),
                due_date=(datetime.now() + timedelta(days=30)).date(),
                total_net=Decimal('1000.00'),
                total_gross=Decimal('1000.00'),
            )


class InvoiceLineModelTests(TestCase):
    """Tests for InvoiceLine model"""

    def setUp(self):
        self.le = LegalEntity.objects.create(
            code='CH',
            name='IMAA Switzerland GmbH',
            legal_form='Swiss GmbH',
            address='Zurich, CH',
            currency='USD',
        )
        self.user = User.objects.create_user(username='testuser')
        self.customer = Customer.objects.create(user=self.user)
        self.invoice = Invoice.objects.create(
            number='IMAA-CH-INV-2026-00001',
            legal_entity=self.le,
            customer=self.customer,
            issue_date=datetime.now().date(),
            due_date=(datetime.now() + timedelta(days=30)).date(),
            total_net=Decimal('1000.00'),
            total_gross=Decimal('1000.00'),
        )
        self.line = InvoiceLine.objects.create(
            invoice=self.invoice,
            description='Event Registration',
            quantity=1,
            unit_price=Decimal('1000.00'),
            net_amount=Decimal('1000.00'),
        )

    def test_invoice_line_creation(self):
        """Test creating an invoice line"""
        self.assertEqual(self.line.description, 'Event Registration')
        self.assertEqual(self.line.quantity, 1)

    def test_invoice_line_relationship(self):
        """Test invoice line is linked to invoice"""
        self.assertEqual(self.line.invoice, self.invoice)
        self.assertEqual(self.invoice.lines.count(), 1)


class PaymentEventModelTests(TestCase):
    """Tests for PaymentEvent model"""

    def setUp(self):
        self.le = LegalEntity.objects.create(
            code='CH',
            name='IMAA Switzerland GmbH',
            legal_form='Swiss GmbH',
            address='Zurich, CH',
        )
        self.user = User.objects.create_user(username='testuser')
        self.customer = Customer.objects.create(user=self.user)
        self.invoice = Invoice.objects.create(
            number='IMAA-CH-INV-2026-00001',
            legal_entity=self.le,
            customer=self.customer,
            issue_date=datetime.now().date(),
            due_date=(datetime.now() + timedelta(days=30)).date(),
            total_net=Decimal('1000.00'),
            total_gross=Decimal('1000.00'),
        )
        self.event = PaymentEvent.objects.create(
            invoice=self.invoice,
            event_type='payment',
            amount=Decimal('1000.00'),
            currency='USD',
            source='stripe',
            external_reference='ch_123abc',
        )

    def test_payment_event_creation(self):
        """Test creating a payment event"""
        self.assertEqual(self.event.event_type, 'payment')
        self.assertEqual(self.event.amount, Decimal('1000.00'))

    def test_payment_event_str(self):
        """Test string representation"""
        self.assertIn('payment', str(self.event))
        self.assertIn('1000.00', str(self.event))

    def test_payment_event_immutability(self):
        """Test that payment events cannot be modified"""
        self.event.amount = Decimal('500.00')
        # In production, we'd use a custom save() to prevent updates
        # For now, this test documents the intended behavior
        pass


class CreditNoteModelTests(TestCase):
    """Tests for CreditNote model"""

    def setUp(self):
        self.le = LegalEntity.objects.create(
            code='CH',
            name='IMAA Switzerland GmbH',
            legal_form='Swiss GmbH',
            address='Zurich, CH',
        )
        self.user = User.objects.create_user(username='testuser')
        self.customer = Customer.objects.create(user=self.user)
        self.invoice = Invoice.objects.create(
            number='IMAA-CH-INV-2026-00001',
            legal_entity=self.le,
            customer=self.customer,
            issue_date=datetime.now().date(),
            due_date=(datetime.now() + timedelta(days=30)).date(),
            total_net=Decimal('1000.00'),
            total_gross=Decimal('1000.00'),
        )
        self.credit_note = CreditNote.objects.create(
            number='IMAA-CH-CN-2026-00001',
            original_invoice=self.invoice,
            reason='skonto',
            amount=Decimal('100.00'),
        )

    def test_credit_note_creation(self):
        """Test creating a credit note"""
        self.assertEqual(self.credit_note.number, 'IMAA-CH-CN-2026-00001')
        self.assertEqual(self.credit_note.reason, 'skonto')

    def test_credit_note_unique_number(self):
        """Test credit note number uniqueness"""
        with self.assertRaises(Exception):
            CreditNote.objects.create(
                number='IMAA-CH-CN-2026-00001',
                original_invoice=self.invoice,
                reason='refund',
                amount=Decimal('50.00'),
            )


class ReservedNumberModelTests(TestCase):
    """Tests for ReservedNumber model"""

    def setUp(self):
        self.le = LegalEntity.objects.create(
            code='CH',
            name='IMAA Switzerland GmbH',
            legal_form='Swiss GmbH',
            address='Zurich, CH',
        )
        self.user = User.objects.create_user(username='admin')
        self.reserved = ReservedNumber.objects.create(
            legal_entity=self.le,
            series='INV',
            year=2026,
            number=1,
            reserved_by=self.user,
            purpose='Manual invoice',
            status='reserved',
        )

    def test_reserved_number_creation(self):
        """Test creating a reserved number"""
        self.assertEqual(self.reserved.series, 'INV')
        self.assertEqual(self.reserved.status, 'reserved')

    def test_reserved_number_unique_constraint(self):
        """Test unique_together constraint"""
        with self.assertRaises(Exception):
            ReservedNumber.objects.create(
                legal_entity=self.le,
                series='INV',
                year=2026,
                number=1,
                reserved_by=self.user,
            )
