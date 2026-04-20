"""
Tests for invoicing API views
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.test import APIClient, APITestCase
from rest_framework import status
from datetime import datetime, timedelta
from decimal import Decimal

from invoicing.models import (
    LegalEntity, Customer, Invoice, InvoiceLine,
    PaymentEvent
)


class InvoiceViewSetTests(APITestCase):
    """Tests for Invoice API endpoints"""

    def setUp(self):
        self.client = APIClient()

        # Create legal entity
        self.le = LegalEntity.objects.create(
            code='CH',
            name='IMAA Switzerland GmbH',
            legal_form='Swiss GmbH',
            address='Zurich, CH',
            currency='USD',
        )

        # Create users
        self.user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='testpass123'
        )
        self.user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='testpass123'
        )

        # Create customers
        self.customer1 = Customer.objects.create(user=self.user1)
        self.customer2 = Customer.objects.create(user=self.user2)

        # Create invoices
        self.invoice1 = Invoice.objects.create(
            number='IMAA-CH-INV-2026-00001',
            legal_entity=self.le,
            customer=self.customer1,
            issue_date=datetime.now().date(),
            due_date=(datetime.now() + timedelta(days=30)).date(),
            total_net=Decimal('1000.00'),
            total_gross=Decimal('1000.00'),
        )

        self.invoice2 = Invoice.objects.create(
            number='IMAA-CH-INV-2026-00002',
            legal_entity=self.le,
            customer=self.customer2,
            issue_date=datetime.now().date(),
            due_date=(datetime.now() + timedelta(days=30)).date(),
            total_net=Decimal('2000.00'),
            total_gross=Decimal('2000.00'),
        )

    def test_list_invoices_unauthorized(self):
        """Test listing invoices without authentication"""
        response = self.client.get('/api/invoices/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_invoices_authorized(self):
        """Test listing invoices for authenticated user"""
        self.client.force_authenticate(user=self.user1)
        response = self.client.get('/api/invoices/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # User1 should only see their invoice
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['number'], 'IMAA-CH-INV-2026-00001')

    def test_list_invoices_only_own(self):
        """Test that users can only see their own invoices"""
        self.client.force_authenticate(user=self.user1)
        response = self.client.get('/api/invoices/')
        invoice_numbers = [inv['number'] for inv in response.data['results']]
        self.assertIn('IMAA-CH-INV-2026-00001', invoice_numbers)
        self.assertNotIn('IMAA-CH-INV-2026-00002', invoice_numbers)

    def test_retrieve_invoice(self):
        """Test retrieving a single invoice"""
        self.client.force_authenticate(user=self.user1)
        response = self.client.get(f'/api/invoices/{self.invoice1.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['number'], 'IMAA-CH-INV-2026-00001')

    def test_retrieve_invoice_forbidden(self):
        """Test that users cannot view other user's invoices"""
        self.client.force_authenticate(user=self.user1)
        response = self.client.get(f'/api/invoices/{self.invoice2.id}/')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_invoice_contains_lines(self):
        """Test that invoice serialization includes line items"""
        InvoiceLine.objects.create(
            invoice=self.invoice1,
            description='Test Line',
            quantity=1,
            unit_price=Decimal('1000.00'),
            net_amount=Decimal('1000.00'),
        )

        self.client.force_authenticate(user=self.user1)
        response = self.client.get(f'/api/invoices/{self.invoice1.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['lines']), 1)
        self.assertEqual(response.data['lines'][0]['description'], 'Test Line')

    def test_invoice_state_in_response(self):
        """Test that invoice state is included in response"""
        self.client.force_authenticate(user=self.user1)
        response = self.client.get(f'/api/invoices/{self.invoice1.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('state', response.data)
        self.assertEqual(response.data['state'], 'issued')

    def test_download_pdf_no_file(self):
        """Test downloading PDF when not yet generated"""
        self.client.force_authenticate(user=self.user1)
        response = self.client.get(f'/api/invoices/{self.invoice1.id}/download_pdf/')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_download_pdf_forbidden(self):
        """Test that users cannot download other user's PDFs"""
        self.client.force_authenticate(user=self.user1)
        response = self.client.get(f'/api/invoices/{self.invoice2.id}/download_pdf/')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_payment_events_in_response(self):
        """Test that payment events are included in invoice response"""
        PaymentEvent.objects.create(
            invoice=self.invoice1,
            event_type='payment',
            amount=Decimal('500.00'),
            currency='USD',
            source='stripe',
        )

        self.client.force_authenticate(user=self.user1)
        response = self.client.get(f'/api/invoices/{self.invoice1.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['payment_events']), 1)

    def test_invoice_state_updates_with_payment(self):
        """Test that invoice state reflects payment events"""
        self.client.force_authenticate(user=self.user1)

        # Initially issued
        response = self.client.get(f'/api/invoices/{self.invoice1.id}/')
        self.assertEqual(response.data['state'], 'issued')

        # Add payment
        PaymentEvent.objects.create(
            invoice=self.invoice1,
            event_type='payment',
            amount=Decimal('1000.00'),
            currency='USD',
            source='stripe',
        )

        # Now should be paid
        response = self.client.get(f'/api/invoices/{self.invoice1.id}/')
        self.assertEqual(response.data['state'], 'paid')
