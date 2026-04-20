from django.conf import settings
from django.db import models
from django.utils import timezone
from events.models import Event

class LegalEntity(models.Model):
    """Represents IMAA Switzerland GmbH"""
    code = models.CharField(max_length=2, unique=True)  # 'CH'
    name = models.CharField(max_length=255)
    legal_form = models.CharField(max_length=100)
    address = models.TextField()
    country = models.CharField(max_length=2, default='CH')
    vat_id = models.CharField(max_length=50, blank=True)
    bank_details = models.JSONField(default=dict)  # IBAN, SWIFT, etc.
    currency = models.CharField(max_length=3, default='USD')
    vat_exempt = models.BooleanField(default=True)  # CH is VAT exempt
    invoice_template_path = models.CharField(max_length=255, default='invoices/ch_template.html')

    # Invoice numbering state (per series per year)
    inv_counter_2026 = models.PositiveIntegerField(default=0)

    class Meta:
        verbose_name = "Legal Entity"
        verbose_name_plural = "Legal Entities"

    def __str__(self):
        return f"{self.code} - {self.name}"

class Customer(models.Model):
    """Customer who can have multiple invoices across entities"""
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    company_name = models.CharField(max_length=255, blank=True)
    vat_id = models.CharField(max_length=50, blank=True)
    billing_address = models.TextField(blank=True)
    preferred_language = models.CharField(max_length=5, choices=[('en', 'English'), ('de', 'German')], default='en')
    saleor_customer_id = models.CharField(max_length=255, blank=True)  # External reference
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email}"

class Invoice(models.Model):
    STATE_CHOICES = [
        ('draft', 'Draft'),
        ('issued', 'Issued'),
        ('partially_paid', 'Partially Paid'),
        ('paid', 'Paid'),
        ('overdue', 'Overdue'),
        ('cancelled', 'Cancelled'),
        ('refunded', 'Refunded'),
    ]

    number = models.CharField(max_length=50, unique=True, db_index=True)  # IMAA-CH-INV-2026-00042
    legal_entity = models.ForeignKey(LegalEntity, on_delete=models.PROTECT)
    customer = models.ForeignKey(Customer, on_delete=models.PROTECT)
    saleor_order_id = models.CharField(max_length=255, blank=True, db_index=True)  # For idempotency

    issue_date = models.DateField()
    due_date = models.DateField()
    skonto_deadline = models.DateField(null=True, blank=True)
    skonto_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    total_net = models.DecimalField(max_digits=12, decimal_places=2)
    total_vat = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    total_gross = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')

    language = models.CharField(max_length=5, choices=[('en', 'English')], default='en')  # Phase 2: German
    pdf_storage_reference = models.CharField(max_length=255, blank=True)  # S3 key or path

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-issue_date']
        indexes = [
            models.Index(fields=['legal_entity', 'issue_date']),
            models.Index(fields=['customer', 'issue_date']),
            models.Index(fields=['number']),
        ]

    def __str__(self):
        return self.number

    @property
    def state(self):
        """Derive state from PaymentEvents"""
        events = self.payment_events.all()
        total_paid = sum(float(e.amount) for e in events if e.event_type == 'payment')

        if total_paid >= float(self.total_gross):
            return 'paid'
        elif total_paid > 0:
            return 'partially_paid'
        elif timezone.now().date() > self.due_date:
            return 'overdue'
        return 'issued'

class InvoiceLine(models.Model):
    """Line items on an invoice"""
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name='lines')
    description = models.CharField(max_length=255)
    quantity = models.PositiveIntegerField(default=1)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    net_amount = models.DecimalField(max_digits=12, decimal_places=2)
    vat_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0)  # Percentage
    vat_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    product_reference = models.CharField(max_length=255, blank=True)  # Saleor product ID

    class Meta:
        ordering = ['id']

class PaymentEvent(models.Model):
    """Immutable payment record"""
    EVENT_TYPE_CHOICES = [
        ('payment', 'Payment'),
        ('refund', 'Refund'),
        ('skonto_credit', 'Skonto Credit'),
    ]

    invoice = models.ForeignKey(Invoice, on_delete=models.PROTECT, related_name='payment_events')
    event_type = models.CharField(max_length=20, choices=EVENT_TYPE_CHOICES)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3)

    source = models.CharField(max_length=50, choices=[
        ('stripe', 'Stripe'),
        ('wise', 'Wise Bank Transfer'),
        ('manual', 'Manual Entry'),
    ])
    external_reference = models.CharField(max_length=255, blank=True, db_index=True)  # Stripe charge ID, bank ref

    timestamp = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['timestamp']
        indexes = [
            models.Index(fields=['invoice', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.invoice.number} - {self.event_type} {self.amount}"

class CreditNote(models.Model):
    """Credit notes for refunds, voids, and Skonto adjustments"""
    REASON_CHOICES = [
        ('refund', 'Refund'),
        ('void', 'Void'),
        ('skonto', 'Skonto Adjustment'),
        ('correction', 'Correction'),
    ]

    number = models.CharField(max_length=50, unique=True, db_index=True)  # IMAA-CH-CN-2026-00003
    original_invoice = models.ForeignKey(Invoice, on_delete=models.PROTECT, related_name='credit_notes')
    reason = models.CharField(max_length=20, choices=REASON_CHOICES)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    vat_adjustment = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    pdf_storage_reference = models.CharField(max_length=255, blank=True)
    issued_date = models.DateField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-issued_date']

class ReservedNumber(models.Model):
    """Pre-allocated invoice numbers for manual workflows"""
    STATUS_CHOICES = [
        ('reserved', 'Reserved'),
        ('used', 'Used'),
        ('released', 'Released'),
    ]

    legal_entity = models.ForeignKey(LegalEntity, on_delete=models.CASCADE)
    series = models.CharField(max_length=3, choices=[('INV', 'Invoice'), ('CN', 'Credit Note')])
    year = models.IntegerField()
    number = models.PositiveIntegerField()

    reserved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    reserved_at = models.DateTimeField(auto_now_add=True)
    purpose = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='reserved')

    class Meta:
        unique_together = [('legal_entity', 'series', 'year', 'number')]
