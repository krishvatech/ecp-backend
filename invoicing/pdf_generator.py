"""
Branded PDF generation for invoices.

The invoice PDF is generated with ReportLab so it works in local development,
Docker, and production without a browser dependency. Keep this module free of
request-specific logic: it accepts an Invoice instance and stores the generated
file through Django's configured storage backend.
"""
import logging
from decimal import Decimal, InvalidOperation
from io import BytesIO
from xml.sax.saxutils import escape

from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

logger = logging.getLogger("invoicing")

BRAND_TEAL = colors.HexColor("#18b8b0")
BRAND_NAVY = colors.HexColor("#071d49")
BRAND_MUTED = colors.HexColor("#667085")
BORDER = colors.HexColor("#d8dee9")
SOFT_BG = colors.HexColor("#f8fafc")
SUCCESS_BG = colors.HexColor("#dcfce7")
SUCCESS_TEXT = colors.HexColor("#166534")
WARNING_BG = colors.HexColor("#fef3c7")
WARNING_TEXT = colors.HexColor("#92400e")
DANGER_BG = colors.HexColor("#fee2e2")
DANGER_TEXT = colors.HexColor("#991b1b")


def _safe_text(value):
    """Return XML-safe text for ReportLab Paragraphs."""
    return escape(str(value or "").strip())


def _money(value, currency="USD"):
    """Format money consistently without relying on locale settings."""
    try:
        amount = Decimal(str(value or "0"))
    except (InvalidOperation, ValueError):
        amount = Decimal("0")
    return f"{str(currency or 'USD').upper()} {amount:,.2f}"


def _date(value):
    return value.strftime("%d %b %Y") if value else "—"


def _paragraph(text, style):
    return Paragraph(_safe_text(text).replace("\n", "<br/>"), style)


def _status_styles(invoice):
    state = (getattr(invoice, "state", "issued") or "issued").lower()
    if state == "paid":
        return "PAID", SUCCESS_BG, SUCCESS_TEXT
    if state in {"overdue", "cancelled", "refunded"}:
        return state.upper(), DANGER_BG, DANGER_TEXT
    if state == "partially_paid":
        return "PARTIALLY PAID", WARNING_BG, WARNING_TEXT
    return "ISSUED", WARNING_BG, WARNING_TEXT


def _customer_lines(customer):
    """Build billing block from invoice customer and saved checkout address."""
    user = getattr(customer, "user", None)
    lines = []

    company_name = getattr(customer, "company_name", "") or ""
    if company_name:
        lines.append(company_name)

    if user:
        full_name = ""
        get_full_name = getattr(user, "get_full_name", None)
        if callable(get_full_name):
            full_name = (get_full_name() or "").strip()
        if full_name and full_name not in lines:
            lines.append(full_name)
        elif not company_name:
            first = getattr(user, "first_name", "") or ""
            last = getattr(user, "last_name", "") or ""
            name = f"{first} {last}".strip()
            if name:
                lines.append(name)

    # Prefer the saved order billing address if available. It is what Saleor
    # received at checkout and therefore should match the invoice recipient.
    billing = None
    try:
        billing = getattr(user, "billing_address", None) if user else None
    except Exception:
        pass

    if billing:
        # Include billing address name first
        name = f"{_safe_text(billing.first_name)} {_safe_text(billing.last_name)}".strip()
        if name and name not in lines:
            lines.insert(0, name)

        company = _safe_text(getattr(billing, "company_name", "") or "")
        if company and company not in lines:
            lines.insert(0, company)

        # Add address fields
        for value in [
            _safe_text(billing.street_address_1),
            _safe_text(getattr(billing, "street_address_2", "")),
            f"{_safe_text(billing.postal_code)} {_safe_text(billing.city)}".strip(),
            " ".join(part for part in [
                _safe_text(getattr(billing, "country_area", "")),
                _safe_text(billing.country or "")
            ] if part).strip(),
        ]:
            if value:
                lines.append(value)
    elif getattr(customer, "billing_address", ""):
        # Fallback to customer's stored billing address
        lines.extend(str(customer.billing_address).splitlines())

    if user and getattr(user, "email", ""):
        lines.append(user.email)
    if getattr(customer, "vat_id", ""):
        lines.append(f"VAT: {customer.vat_id}")

    return lines or ["Customer"]


def _legal_entity_lines(legal_entity):
    lines = [legal_entity.name]
    if legal_entity.legal_form and legal_entity.legal_form not in legal_entity.name:
        lines.append(legal_entity.legal_form)
    if legal_entity.address:
        lines.extend(str(legal_entity.address).splitlines())
    if legal_entity.vat_id:
        lines.append(f"VAT: {legal_entity.vat_id}")
    return [line for line in lines if line]


def _bank_lines(legal_entity):
    bank = getattr(legal_entity, "bank_details", {}) or {}
    if not isinstance(bank, dict) or not bank:
        return []
    labels = {
        "account_name": "Account name",
        "bank_name": "Bank",
        "iban": "IBAN",
        "swift": "SWIFT/BIC",
        "bic": "BIC",
        "account_number": "Account no.",
    }
    lines = []
    for key in ["account_name", "bank_name", "iban", "swift", "bic", "account_number"]:
        value = bank.get(key)
        if value:
            lines.append(f"{labels[key]}: {value}")
    return lines


def _draw_footer(canvas, doc):
    canvas.saveState()
    width, _height = A4
    canvas.setStrokeColor(BORDER)
    canvas.line(doc.leftMargin, 18 * mm, width - doc.rightMargin, 18 * mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(BRAND_MUTED)
    canvas.drawString(doc.leftMargin, 10 * mm, "Thank you for your registration.")
    canvas.drawRightString(width - doc.rightMargin, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def generate_invoice_pdf(invoice):
    """
    Generate a clean, branded invoice PDF and return the storage reference.
    """
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=1.6 * cm,
            leftMargin=1.6 * cm,
            topMargin=1.4 * cm,
            bottomMargin=2.2 * cm,
            title=invoice.number,
            author=getattr(invoice.legal_entity, "name", "IMAA"),
        )

        base_styles = getSampleStyleSheet()
        styles = {
            "brand": ParagraphStyle(
                "Brand",
                parent=base_styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=18,
                leading=22,
                textColor=BRAND_NAVY,
            ),
            "subtitle": ParagraphStyle(
                "Subtitle",
                parent=base_styles["Normal"],
                fontSize=8.5,
                leading=11,
                textColor=BRAND_MUTED,
            ),
            "title": ParagraphStyle(
                "InvoiceTitle",
                parent=base_styles["Heading1"],
                alignment=TA_RIGHT,
                fontName="Helvetica-Bold",
                fontSize=24,
                leading=28,
                textColor=BRAND_NAVY,
                spaceAfter=4,
            ),
            "meta": ParagraphStyle(
                "Meta",
                parent=base_styles["Normal"],
                alignment=TA_RIGHT,
                fontSize=9,
                leading=12,
                textColor=BRAND_MUTED,
            ),
            "section": ParagraphStyle(
                "Section",
                parent=base_styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=9,
                leading=12,
                textColor=BRAND_NAVY,
                spaceAfter=6,
            ),
            "body": ParagraphStyle(
                "Body",
                parent=base_styles["Normal"],
                fontSize=9,
                leading=13,
                textColor=colors.HexColor("#1f2937"),
            ),
            "small": ParagraphStyle(
                "Small",
                parent=base_styles["Normal"],
                fontSize=8,
                leading=11,
                textColor=BRAND_MUTED,
            ),
            "table_header": ParagraphStyle(
                "TableHeader",
                parent=base_styles["Normal"],
                alignment=TA_CENTER,
                fontName="Helvetica-Bold",
                fontSize=8,
                leading=10,
                textColor=colors.white,
            ),
            "table_left": ParagraphStyle(
                "TableLeft",
                parent=base_styles["Normal"],
                alignment=TA_LEFT,
                fontSize=8.5,
                leading=11,
            ),
            "table_right": ParagraphStyle(
                "TableRight",
                parent=base_styles["Normal"],
                alignment=TA_RIGHT,
                fontSize=8.5,
                leading=11,
            ),
            "table_center": ParagraphStyle(
                "TableCenter",
                parent=base_styles["Normal"],
                alignment=TA_CENTER,
                fontSize=8.5,
                leading=11,
            ),
            "meta_label": ParagraphStyle(
                "MetaLabel",
                parent=base_styles["Normal"],
                fontName="Helvetica-Bold",
                fontSize=8.5,
                leading=11,
                textColor=BRAND_NAVY,
            ),
            "meta_value": ParagraphStyle(
                "MetaValue",
                parent=base_styles["Normal"],
                fontSize=8.5,
                leading=11,
                textColor=colors.HexColor("#1f2937"),
                # Break long unbroken strings (e.g. Saleor GraphQL IDs) so they
                # wrap inside the cell instead of overflowing into other columns.
                wordWrap="CJK",
            ),
        }

        story = []
        status_text, status_bg, status_text_color = _status_styles(invoice)

        # KeepTogether inside a Table cell can produce an invalid huge height
        # in ReportLab, causing LayoutError during regeneration. Use small
        # nested tables instead so ReportLab can measure the header correctly.
        left_header = Table(
            [
                [Paragraph("IMAA <font color='#18b8b0'>CONNECT</font>", styles["brand"])],
                [Paragraph("Events & Community Platform", styles["subtitle"])],
            ],
            colWidths=[8.8 * cm],
        )
        left_header.setStyle(TableStyle([
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ]))
        right_header = Table(
            [
                [Paragraph("INVOICE", styles["title"])],
                [Paragraph(f"{invoice.number}", styles["meta"])],
            ],
            colWidths=[8.2 * cm],
        )
        right_header.setStyle(TableStyle([
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ]))
        header = Table(
            [[left_header, right_header]],
            colWidths=[8.8 * cm, 8.2 * cm],
        )
        header.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(header)
        story.append(Spacer(1, 6 * mm))

        status_table = Table(
            [[
                Paragraph(f"Status: <b>{status_text}</b>", ParagraphStyle("Status", parent=styles["body"], textColor=status_text_color)),
                Paragraph(f"Issued: <b>{_date(invoice.issue_date)}</b>", styles["meta"]),
                Paragraph(f"Due: <b>{_date(invoice.due_date)}</b>", styles["meta"]),
            ]],
            colWidths=[5.65 * cm, 5.65 * cm, 5.65 * cm],
        )
        status_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), status_bg),
            ("BACKGROUND", (1, 0), (-1, 0), SOFT_BG),
            ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        story.append(status_table)
        story.append(Spacer(1, 8 * mm))

        from_lines = "\n".join(_legal_entity_lines(invoice.legal_entity))
        to_lines = "\n".join(_customer_lines(invoice.customer))
        address_table = Table(
            [
                [Paragraph("Invoice From", styles["section"]), Paragraph("Bill To", styles["section"])],
                [_paragraph(from_lines, styles["body"]), _paragraph(to_lines, styles["body"])],
            ],
            colWidths=[8.35 * cm, 8.35 * cm],
        )
        address_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), SOFT_BG),
            ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(address_table)
        story.append(Spacer(1, 8 * mm))

        # Prefer the human-readable Saleor order number; fall back to the GraphQL
        # ID only if no number is available. Either way the value is wrapped in a
        # Paragraph so long IDs wrap inside the cell instead of overflowing.
        order_ref = getattr(invoice, "saleor_order_number", "") or getattr(invoice, "saleor_order_id", "") or "—"
        if getattr(invoice, "saleor_order_number", ""):
            order_ref = f"#{invoice.saleor_order_number}"

        def _meta_label(text):
            return Paragraph(_safe_text(text), styles["meta_label"])

        def _meta_value(text):
            return Paragraph(_safe_text(text), styles["meta_value"])

        invoice_meta = Table(
            [
                [_meta_label("Invoice Number"), _meta_value(invoice.number),
                 _meta_label("Currency"), _meta_value(invoice.currency)],
                [_meta_label("Saleor Order"), _meta_value(order_ref),
                 _meta_label("Payment Terms"), _meta_value(f"Due by {_date(invoice.due_date)}")],
            ],
            colWidths=[3.0 * cm, 6.0 * cm, 3.2 * cm, 4.8 * cm],
        )
        invoice_meta.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), SOFT_BG),
            ("BACKGROUND", (2, 0), (2, -1), SOFT_BG),
            ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        story.append(invoice_meta)
        story.append(Spacer(1, 8 * mm))

        line_rows = [[
            Paragraph("Description", styles["table_header"]),
            Paragraph("Qty", styles["table_header"]),
            Paragraph("Unit Price", styles["table_header"]),
            Paragraph("VAT", styles["table_header"]),
            Paragraph("Amount", styles["table_header"]),
        ]]
        for line in invoice.lines.all():
            line_rows.append([
                Paragraph(_safe_text(line.description), styles["table_left"]),
                Paragraph(str(line.quantity), styles["table_center"]),
                Paragraph(_money(line.unit_price, invoice.currency), styles["table_right"]),
                Paragraph(_money(line.vat_amount, invoice.currency), styles["table_right"]),
                Paragraph(_money(line.net_amount + line.vat_amount, invoice.currency), styles["table_right"]),
            ])

        items_table = Table(line_rows, colWidths=[7.6 * cm, 1.4 * cm, 2.6 * cm, 2.0 * cm, 3.0 * cm], repeatRows=1)
        items_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_NAVY),
            ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SOFT_BG]),
        ]))
        story.append(items_table)
        story.append(Spacer(1, 6 * mm))

        totals_rows = [
            ["Subtotal", _money(invoice.total_net, invoice.currency)],
            ["VAT", _money(invoice.total_vat, invoice.currency)],
            ["Total", _money(invoice.total_gross, invoice.currency)],
        ]
        totals = Table(totals_rows, colWidths=[4.2 * cm, 3.4 * cm], hAlign="RIGHT")
        totals.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SOFT_BG),
            ("BACKGROUND", (0, -1), (-1, -1), BRAND_NAVY),
            ("TEXTCOLOR", (0, -1), (-1, -1), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        story.append(totals)
        story.append(Spacer(1, 8 * mm))

        payments = list(invoice.payment_events.all())
        if payments:
            payment_rows = [["Date", "Type", "Source", "Reference", "Amount"]]
            for payment in payments:
                payment_rows.append([
                    _date(payment.timestamp.date() if payment.timestamp else None),
                    payment.get_event_type_display(),
                    payment.get_source_display(),
                    payment.external_reference or "—",
                    _money(payment.amount, payment.currency or invoice.currency),
                ])
            payment_table = Table(payment_rows, colWidths=[2.6 * cm, 2.7 * cm, 3.0 * cm, 4.9 * cm, 3.0 * cm])
            payment_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), SOFT_BG),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
                ("ALIGN", (-1, 1), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(Paragraph("Payment History", styles["section"]))
            story.append(payment_table)
            story.append(Spacer(1, 6 * mm))

        bank_lines = _bank_lines(invoice.legal_entity)
        note_parts = []
        if invoice.state != "paid":
            note_parts.append(f"Please include invoice number {invoice.number} as payment reference.")
        else:
            note_parts.append("This invoice has been marked as paid. Thank you.")
        if bank_lines:
            note_parts.append("\n".join(bank_lines))

        if note_parts:
            story.append(Paragraph("Notes", styles["section"]))
            notes_text = _paragraph("\n".join(note_parts), styles["small"])
            notes_box = Table(
                [[notes_text]],
                colWidths=[16.7 * cm],
            )
            notes_box.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), SOFT_BG),
                ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]))
            story.append(notes_box)

        doc.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
        buffer.seek(0)

        storage_key = f"invoices/{invoice.legal_entity.code}/{invoice.number}.pdf"
        try:
            if default_storage.exists(storage_key):
                default_storage.delete(storage_key)
        except Exception:
            logger.debug("Could not delete previous invoice PDF before regeneration", exc_info=True)

        default_storage.save(storage_key, ContentFile(buffer.getvalue()))
        logger.info("Generated PDF for invoice %s at %s", invoice.number, storage_key)
        return storage_key

    except Exception as exc:
        logger.error("Error generating PDF for invoice %s: %s", invoice.number, exc)
        raise