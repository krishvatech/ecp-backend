"""
Tests for invoicing API views
"""
from django.test import TestCase, Client
from django.contrib.auth.models import Group, User
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



class AdminLegalEntitySettingsViewTests(APITestCase):
    """Tests for the Saleor Manager invoice-settings tab backend."""

    url = '/api/invoicing/admin/legal-entity/'

    def setUp(self):
        self.client = APIClient()
        self.legal_entity = LegalEntity.objects.create(
            code='CH',
            name='IMAA Switzerland GmbH',
            legal_form='Swiss GmbH',
            address='Zurich, CH',
            country='CH',
            vat_id='',
            currency='USD',
            vat_exempt=True,
            bank_details={
                'iban': 'OLD-IBAN',
                'legacy_reference': 'preserve-me',
            },
            inv_counter_2026=42,
        )
        self.regular_user = User.objects.create_user(
            username='regular-invoice-user',
            email='regular-invoice-user@example.com',
            password='testpass123',
        )
        self.platform_admin = User.objects.create_user(
            username='invoice-platform-admin',
            email='invoice-platform-admin@example.com',
            password='testpass123',
        )
        platform_admin_group, _ = Group.objects.get_or_create(name='platform_admin')
        self.platform_admin.groups.add(platform_admin_group)

    def test_settings_require_authentication(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_regular_user_cannot_read_settings(self):
        self.client.force_authenticate(user=self.regular_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_platform_admin_can_read_settings(self):
        self.client.force_authenticate(user=self.platform_admin)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['code'], 'CH')
        self.assertEqual(response.data['name'], 'IMAA Switzerland GmbH')
        self.assertNotIn('inv_counter_2026', response.data)

    def test_platform_admin_can_update_invoice_from_and_bank_details(self):
        self.client.force_authenticate(user=self.platform_admin)
        response = self.client.patch(
            self.url,
            {
                'name': 'IMAA Switzerland AG',
                'legal_form': 'Swiss AG',
                'address': 'Example Street 10\n8000 Zurich\nSwitzerland',
                'country': 'ch',
                'vat_id': 'CHE-123.456.789',
                'currency': 'usd',
                'vat_exempt': False,
                'bank_details': {
                    'account_name': 'IMAA Switzerland AG',
                    'bank_name': 'Example Bank',
                    'iban': '  CH00 0000 0000 0000 0000 0  ',
                    'swift': ' EXAMPLECH ',
                    'account_number': '',
                },
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.legal_entity.refresh_from_db()
        self.assertEqual(self.legal_entity.name, 'IMAA Switzerland AG')
        self.assertEqual(self.legal_entity.country, 'CH')
        self.assertEqual(self.legal_entity.currency, 'USD')
        self.assertEqual(self.legal_entity.inv_counter_2026, 42)
        self.assertEqual(self.legal_entity.bank_details['iban'], 'CH00 0000 0000 0000 0000 0')
        self.assertEqual(self.legal_entity.bank_details['swift'], 'EXAMPLECH')
        self.assertEqual(self.legal_entity.bank_details['legacy_reference'], 'preserve-me')

    def test_invalid_country_and_currency_are_rejected_without_partial_save(self):
        self.client.force_authenticate(user=self.platform_admin)
        response = self.client.patch(
            self.url,
            {
                'name': 'Should Not Save',
                'country': 'SWITZERLAND',
                'currency': 'DOLLARS',
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.legal_entity.refresh_from_db()
        self.assertEqual(self.legal_entity.name, 'IMAA Switzerland GmbH')
