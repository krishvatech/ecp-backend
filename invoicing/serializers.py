from rest_framework import serializers
from invoicing.models import Invoice, InvoiceLine, PaymentEvent, Customer, LegalEntity

class InvoiceLineSerializer(serializers.ModelSerializer):
    class Meta:
        model = InvoiceLine
        fields = ['id', 'description', 'quantity', 'unit_price', 'net_amount', 'vat_rate', 'vat_amount']
        read_only_fields = ['id']

class PaymentEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentEvent
        fields = ['id', 'event_type', 'amount', 'currency', 'source', 'external_reference', 'timestamp', 'notes']
        read_only_fields = ['id', 'timestamp']

class InvoiceSerializer(serializers.ModelSerializer):
    lines = InvoiceLineSerializer(many=True, read_only=True)
    payment_events = PaymentEventSerializer(many=True, read_only=True)
    state = serializers.CharField(read_only=True)

    class Meta:
        model = Invoice
        fields = [
            'id', 'number', 'customer', 'legal_entity', 'saleor_order_id',
            'issue_date', 'due_date', 'skonto_deadline',
            'total_net', 'total_vat', 'total_gross', 'currency',
            'state', 'language', 'pdf_storage_reference',
            'lines', 'payment_events', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'number', 'state', 'created_at', 'updated_at']

class CustomerInvoiceListSerializer(serializers.ModelSerializer):
    state = serializers.CharField(read_only=True)

    class Meta:
        model = Invoice
        fields = ['id', 'number', 'issue_date', 'due_date', 'total_gross', 'state', 'pdf_storage_reference']
        read_only_fields = fields
