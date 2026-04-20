"""
PDF generation for invoices using reportlab or WeasyPrint
"""
import logging
from io import BytesIO
from django.template.loader import render_to_string
from django.core.files.storage import default_storage
from django.conf import settings

logger = logging.getLogger('invoicing')

def generate_invoice_pdf(invoice):
    """
    Generate PDF for invoice and store to S3

    Args:
        invoice: Invoice instance

    Returns:
        PDF storage reference (S3 key or path)
    """
    try:
        # Render invoice template to HTML
        context = {
            'invoice': invoice,
            'legal_entity': invoice.legal_entity,
            'customer': invoice.customer,
            'lines': invoice.lines.all(),
            'payments': invoice.payment_events.all(),
        }

        html_content = render_to_string('invoicing/invoice_template.html', context)

        # Generate PDF from HTML
        # Using reportlab for simplicity; can be replaced with WeasyPrint
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            'InvoiceTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#333333'),
            spaceAfter=20,
        )
        story.append(Paragraph(f"Invoice {invoice.number}", title_style))
        story.append(Spacer(1, 0.3 * inch))

        # Invoice details
        details_data = [
            ['Invoice Number:', invoice.number],
            ['Issue Date:', str(invoice.issue_date)],
            ['Due Date:', str(invoice.due_date)],
            ['Customer:', invoice.customer.user.email],
        ]
        details_table = Table(details_data, colWidths=[2*inch, 4*inch])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(details_table)
        story.append(Spacer(1, 0.3 * inch))

        # Invoice lines
        lines_data = [['Description', 'Quantity', 'Unit Price', 'Amount']]
        for line in invoice.lines.all():
            lines_data.append([
                line.description,
                str(line.quantity),
                f"${line.unit_price}",
                f"${line.net_amount}",
            ])

        lines_table = Table(lines_data, colWidths=[3*inch, 1.5*inch, 1.5*inch, 1.5*inch])
        lines_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(lines_table)
        story.append(Spacer(1, 0.3 * inch))

        # Totals
        totals_data = [
            ['Subtotal:', f"${invoice.total_net}"],
            ['VAT:', f"${invoice.total_vat}"],
            ['Total:', f"${invoice.total_gross}"],
        ]
        totals_table = Table(totals_data, colWidths=[4*inch, 2*inch])
        totals_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'RIGHT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(totals_table)

        # Build PDF
        doc.build(story)
        buffer.seek(0)

        # Store to S3
        storage_key = f"invoices/{invoice.legal_entity.code}/{invoice.number}.pdf"
        default_storage.save(storage_key, buffer)

        logger.info(f"Generated PDF for invoice {invoice.number} at {storage_key}")
        return storage_key

    except Exception as e:
        logger.error(f"Error generating PDF for invoice {invoice.number}: {str(e)}")
        raise
