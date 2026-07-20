from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from django.http import FileResponse
from django.conf import settings
from django.core import signing
from django.core.files.storage import default_storage
from django.shortcuts import get_object_or_404
from django.utils.text import get_valid_filename
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import AllowAny
from invoicing.models import Invoice, Customer
from invoicing.serializers import (
    InvoiceSerializer,
    CustomerInvoiceListSerializer,
    AdminLegalEntitySettingsSerializer,
)
from invoicing.tasks import generate_invoice_pdf_task, _get_or_create_default_legal_entity
from invoicing.permissions import IsPlatformAdmin


class AdminLegalEntitySettingsView(APIView):
    """Read and update the default legal entity used on invoice PDFs.

    This endpoint intentionally updates only the existing ``LegalEntity`` row.
    It does not touch Saleor, invoice totals, customer billing addresses, invoice
    numbers, payment events, or already stored PDF files.
    """

    permission_classes = [permissions.IsAuthenticated, IsPlatformAdmin]

    def get_object(self):
        return _get_or_create_default_legal_entity()

    def get(self, request):
        legal_entity = self.get_object()
        serializer = AdminLegalEntitySettingsSerializer(legal_entity)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request):
        legal_entity = self.get_object()
        serializer = AdminLegalEntitySettingsSerializer(
            legal_entity,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)



def _user_can_access_invoice(user, invoice):
    """Allow invoice owner, staff/superusers, and event owners to access PDFs.

    Customer portal downloads use the invoice customer relationship. Event
    owners/admins download the same invoice from the Event Orders tab, so they
    must be authorized through the local ECP order that is linked to the
    Saleor order id stored on the invoice.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False

    customer_user_id = getattr(getattr(invoice, "customer", None), "user_id", None)
    if customer_user_id == getattr(user, "id", None):
        return True

    if getattr(user, "is_staff", False) or getattr(user, "is_superuser", False):
        return True

    saleor_order_id = getattr(invoice, "saleor_order_id", "") or ""
    if not saleor_order_id:
        return False

    try:
        from orders.models import Order
        return Order.objects.filter(
            saleor_order_id=saleor_order_id,
            items__event__created_by_id=getattr(user, "id", None),
        ).exists()
    except Exception:
        return False


def _get_invoice_for_download_or_generation(request, pk):
    invoice = get_object_or_404(
        Invoice.objects.select_related("customer__user", "legal_entity"),
        pk=pk,
    )
    if not _user_can_access_invoice(request.user, invoice):
        raise PermissionDenied("You do not have permission to access this invoice.")
    return invoice


PUBLIC_INVOICE_DOWNLOAD_SALT = "invoicing.public_download"


def _invoice_pdf_response(invoice):
    """Return a FileResponse for an invoice PDF or a clear API error."""
    if not invoice.pdf_storage_reference:
        return Response(
            {'error': 'PDF not yet generated'},
            status=status.HTTP_404_NOT_FOUND,
        )

    if not default_storage.exists(invoice.pdf_storage_reference):
        return Response(
            {'error': 'Invoice PDF file is missing. Please regenerate the PDF.'},
            status=status.HTTP_404_NOT_FOUND,
        )

    pdf_file = default_storage.open(invoice.pdf_storage_reference, 'rb')
    response = FileResponse(pdf_file, content_type='application/pdf')
    filename = get_valid_filename(f"{invoice.number}.pdf")
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@api_view(['GET'])
@permission_classes([AllowAny])
def public_invoice_pdf_download(request, token):
    """Download a paid invoice PDF through a signed email link.

    The normal /api/invoices/<id>/download_pdf/ endpoint requires the user to be
    authenticated. Email clients do not send the customer's JWT token, so the
    payment-confirmed email uses this signed, time-limited URL instead.
    """
    max_age_days = int(getattr(settings, 'INVOICE_PUBLIC_DOWNLOAD_MAX_AGE_DAYS', 30) or 30)
    max_age = max_age_days * 24 * 60 * 60 if max_age_days > 0 else None

    try:
        payload = signing.loads(token, salt=PUBLIC_INVOICE_DOWNLOAD_SALT, max_age=max_age)
    except signing.SignatureExpired:
        return Response({'error': 'Invoice download link has expired.'}, status=status.HTTP_410_GONE)
    except signing.BadSignature:
        return Response({'error': 'Invalid invoice download link.'}, status=status.HTTP_403_FORBIDDEN)

    invoice = get_object_or_404(
        Invoice.objects.select_related('customer__user', 'legal_entity'),
        pk=payload.get('invoice_id'),
    )
    if payload.get('number') != invoice.number:
        return Response({'error': 'Invalid invoice download link.'}, status=status.HTTP_403_FORBIDDEN)

    # This public link is only intended for finalized paid invoices.
    if invoice.state != 'paid':
        return Response({'error': 'Invoice is not paid yet.'}, status=status.HTTP_403_FORBIDDEN)

    return _invoice_pdf_response(invoice)


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


    @action(detail=True, methods=['post'])
    def generate_pdf(self, request, pk=None):
        """Generate/regenerate an invoice PDF.

        This endpoint is used by both the customer portal and the event-owner
        Orders & Invoices tab, so access is checked against the invoice owner,
        staff/superuser status, or the owner of an event attached to the local
        order linked to the invoice Saleor order id.
        """
        invoice = _get_invoice_for_download_or_generation(request, pk)
        generate_invoice_pdf_task(invoice.id)
        invoice.refresh_from_db()
        return Response({
            'id': invoice.id,
            'number': invoice.number,
            'state': invoice.state,
            'pdf_ready': bool(invoice.pdf_storage_reference),
            'download_url': f'/api/invoices/{invoice.id}/download_pdf/' if invoice.pdf_storage_reference else '',
        })

    @action(detail=True, methods=['get'])
    def download_pdf(self, request, pk=None):
        """Download an invoice PDF for an authorized user."""
        invoice = _get_invoice_for_download_or_generation(request, pk)

        return _invoice_pdf_response(invoice)
