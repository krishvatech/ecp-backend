from django.contrib import admin
from invoicing.models import (
    LegalEntity, Customer, Invoice, InvoiceLine,
    PaymentEvent, CreditNote, ReservedNumber
)

@admin.register(LegalEntity)
class LegalEntityAdmin(admin.ModelAdmin):
    list_display = ('code', 'name', 'currency')
    readonly_fields = ('inv_counter_2026',)

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ('user', 'company_name', 'preferred_language')
    search_fields = ('user__email', 'company_name')
    readonly_fields = ('created_at',)

@admin.register(Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    list_display = ('number', 'customer', 'total_gross', 'state', 'issue_date')
    list_filter = ('issue_date', 'legal_entity')
    search_fields = ('number', 'customer__user__email')
    readonly_fields = ('number', 'state', 'created_at', 'updated_at')

    fieldsets = (
        ('Invoice Details', {
            'fields': ('number', 'legal_entity', 'customer', 'saleor_order_id')
        }),
        ('Dates', {
            'fields': ('issue_date', 'due_date', 'skonto_deadline')
        }),
        ('Amounts', {
            'fields': ('total_net', 'total_vat', 'total_gross', 'skonto_amount', 'currency')
        }),
        ('Status', {
            'fields': ('state', 'language', 'pdf_storage_reference')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

@admin.register(InvoiceLine)
class InvoiceLineAdmin(admin.ModelAdmin):
    list_display = ('invoice', 'description', 'quantity', 'unit_price', 'net_amount')
    list_filter = ('invoice',)
    search_fields = ('invoice__number', 'description')

@admin.register(PaymentEvent)
class PaymentEventAdmin(admin.ModelAdmin):
    list_display = ('invoice', 'event_type', 'amount', 'source', 'timestamp')
    list_filter = ('event_type', 'source', 'timestamp')
    search_fields = ('invoice__number', 'external_reference')
    readonly_fields = ('timestamp',)

@admin.register(CreditNote)
class CreditNoteAdmin(admin.ModelAdmin):
    list_display = ('number', 'original_invoice', 'reason', 'amount', 'issued_date')
    list_filter = ('reason', 'issued_date')
    search_fields = ('number', 'original_invoice__number')
    readonly_fields = ('issued_date', 'created_at')

@admin.register(ReservedNumber)
class ReservedNumberAdmin(admin.ModelAdmin):
    list_display = ('legal_entity', 'series', 'year', 'number', 'status')
    list_filter = ('status', 'series', 'year')
    readonly_fields = ('reserved_at',)
