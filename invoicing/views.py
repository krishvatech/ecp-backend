from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.http import FileResponse
from django.core.files.storage import default_storage
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_GET
from invoicing.models import Invoice, Customer
from invoicing.serializers import InvoiceSerializer, CustomerInvoiceListSerializer

class IsCustomerOrReadOnly(permissions.BasePermission):
    """Permission to check if user owns the invoice."""
    def has_object_permission(self, request, view, obj):
        return obj.customer.user == request.user

class InvoiceViewSet(viewsets.ReadOnlyModelViewSet):
    """Customer portal invoice endpoints"""
    serializer_class = InvoiceSerializer
    permission_classes = [permissions.IsAuthenticated, IsCustomerOrReadOnly]

    def get_queryset(self):
        """Return only invoices for authenticated user"""
        try:
            customer = Customer.objects.get(user=self.request.user)
            return Invoice.objects.filter(customer=customer).order_by('-issue_date')
        except Customer.DoesNotExist:
            return Invoice.objects.none()

    def get_serializer_class(self):
        if self.action == 'list':
            return CustomerInvoiceListSerializer
        return InvoiceSerializer

    @action(detail=True, methods=['get'])
    def download_pdf(self, request, pk=None):
        """Download invoice PDF"""
        try:
            invoice = self.get_object()

            if not invoice.pdf_storage_reference:
                return Response(
                    {'error': 'PDF not yet generated'},
                    status=status.HTTP_404_NOT_FOUND
                )

            pdf_file = default_storage.open(invoice.pdf_storage_reference, 'rb')
            response = FileResponse(pdf_file, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{invoice.number}.pdf"'
            return response

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@require_GET
def public_invoice_pdf(request, token):
    """
    Unguessable token-based invoice PDF endpoint for Saleor invoice URLs.

    This endpoint is intentionally not session-authenticated because Saleor stores a
    static invoice URL. Security comes from the per-invoice UUID token.
    """
    invoice = get_object_or_404(Invoice, public_download_token=token)
    if not invoice.pdf_storage_reference:
        from invoicing.pdf_generator import generate_invoice_pdf
        invoice.pdf_storage_reference = generate_invoice_pdf(invoice)
        invoice.save(update_fields=['pdf_storage_reference', 'updated_at'])

    pdf_file = default_storage.open(invoice.pdf_storage_reference, 'rb')
    response = FileResponse(pdf_file, content_type='application/pdf')
    response['Content-Disposition'] = f'inline; filename="{invoice.number}.pdf"'
    return response
