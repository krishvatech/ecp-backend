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


class AdminLegalEntitySettingsSerializer(serializers.ModelSerializer):
    """Editable invoice issuer settings for the platform administration UI.

    Invoice numbering state and the legal-entity code remain read-only. Bank
    details are stored in the existing JSON field so this feature requires no
    database migration and does not affect existing invoice/order records.
    """

    ALLOWED_BANK_DETAIL_KEYS = (
        'account_name',
        'bank_name',
        'iban',
        'swift',
        'bic',
        'account_number',
    )

    bank_details = serializers.DictField(
        child=serializers.CharField(allow_blank=True, trim_whitespace=True),
        required=False,
    )

    class Meta:
        model = LegalEntity
        fields = [
            'id',
            'code',
            'name',
            'legal_form',
            'address',
            'country',
            'vat_id',
            'currency',
            'vat_exempt',
            'bank_details',
        ]
        read_only_fields = ['id', 'code']

    def validate_country(self, value):
        value = (value or '').strip().upper()
        if len(value) != 2 or not value.isalpha():
            raise serializers.ValidationError('Use a valid two-letter country code.')
        return value

    def validate_currency(self, value):
        value = (value or '').strip().upper()
        if len(value) != 3 or not value.isalpha():
            raise serializers.ValidationError('Use a valid three-letter currency code.')
        return value

    def validate_bank_details(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError('Bank details must be an object.')

        unknown_keys = sorted(set(value) - set(self.ALLOWED_BANK_DETAIL_KEYS))
        if unknown_keys:
            raise serializers.ValidationError(
                f"Unsupported bank detail field(s): {', '.join(unknown_keys)}."
            )

        return {
            key: str(raw_value or '').strip()
            for key, raw_value in value.items()
            if key in self.ALLOWED_BANK_DETAIL_KEYS
        }

    def update(self, instance, validated_data):
        # Merge only the supplied bank keys. This preserves any older/custom
        # keys that may already exist in production while allowing exposed
        # fields to be updated or explicitly cleared.
        bank_details = validated_data.pop('bank_details', None)
        if bank_details is not None:
            merged_bank_details = dict(instance.bank_details or {})
            merged_bank_details.update(bank_details)
            validated_data['bank_details'] = merged_bank_details

        return super().update(instance, validated_data)
