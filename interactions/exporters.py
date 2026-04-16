"""
Q&A export helpers for the interactions app.

Provides:
- build_export_rows(event)   → list of normalized dicts (shared by CSV + PDF)
- generate_csv_response(rows, event)            → Django HttpResponse (attachment)
- generate_pdf_response(rows, event, exported_by) → Django HttpResponse (attachment)

Only host / staff are authorised to call these; callers must enforce permissions
before invoking anything here.

No threaded-reply model exists in this codebase; the replies_summary column is
always empty so callers get a stable, schema-consistent export without invented data.
"""

import csv
import io
from datetime import datetime, timezone as dt_timezone

from django.db.models import Count, Q
from django.http import HttpResponse
from django.utils import timezone


# ──────────────────────────────────────────────────────────────────────────────
# Data normalisation
# ──────────────────────────────────────────────────────────────────────────────

def _display_name_for_user(user) -> str:
    """Return best display name for a registered user object."""
    if user is None:
        return ""
    full = (getattr(user, "get_full_name", lambda: "")() or "").strip()
    if full:
        return full
    return (
        user.first_name
        or user.username
        or (user.email.split("@")[0] if user.email else f"User {user.pk}")
    )


def build_export_rows(event) -> list[dict]:
    """
    Fetch all questions for *event* and normalise each into a flat dict.

    Columns match the spec exactly. Anonymous questions show "Anonymous" in
    author_display_name; the real user/guest id is still included in actor_id
    so the host has internal traceability.

    Replies are always blank — no thread model exists in this codebase.
    """
    from .models import Question  # local import avoids circular at module load

    qs = (
        Question.objects
        .filter(event=event)
        .select_related(
            "user",
            "guest_asker",
            "answered_by",
            "pinned_by",
            "lounge_table",
            "anonymized_by",
        )
        .annotate(
            registered_upvotes=Count("upvote_links", distinct=True),
            guest_upvote_count=Count("guest_upvotes", distinct=True),
        )
        .order_by("created_at")
    )

    rows = []
    for q in qs:
        # ── author resolution ─────────────────────────────────────────────────
        if q.guest_asker:
            raw_author = q.guest_asker.get_display_name()
            author_type = "guest"
            actor_id = f"guest_{q.guest_asker_id}"
        elif q.user:
            raw_author = _display_name_for_user(q.user)
            author_type = "user"
            actor_id = str(q.user_id)
        else:
            raw_author = "Unknown"
            author_type = "unknown"
            actor_id = ""

        # honour anonymity — hide public label but keep internal id
        author_display_name = "Anonymous" if q.is_anonymous else raw_author

        # ── upvotes ───────────────────────────────────────────────────────────
        upvote_count = (q.registered_upvotes or 0) + (q.guest_upvote_count or 0)

        # ── answered_by name ─────────────────────────────────────────────────
        answered_by_name = _display_name_for_user(q.answered_by) if q.answered_by else ""

        # ── lounge table ─────────────────────────────────────────────────────
        lounge_table_id = str(q.lounge_table_id) if q.lounge_table_id else ""

        rows.append({
            "question_id":       str(q.pk),
            "event_id":          str(q.event_id),
            "lounge_table_id":   lounge_table_id,
            "content":           q.content,
            "author_display_name": author_display_name,
            "author_type":       author_type,
            "actor_id":          actor_id,
            "is_anonymous":      "true" if q.is_anonymous else "false",
            "upvote_count":      str(upvote_count),
            "moderation_status": q.moderation_status,
            "rejection_reason":  q.rejection_reason or "",
            "is_hidden":         "true" if q.is_hidden else "false",
            "is_answered":       "true" if q.is_answered else "false",
            "answered_at":       _fmt_dt(q.answered_at),
            "answered_by":       answered_by_name,
            "requires_followup": "true" if q.requires_followup else "false",
            "is_pinned":         "true" if q.is_pinned else "false",
            "pinned_at":         _fmt_dt(q.pinned_at),
            "created_at":        _fmt_dt(q.created_at),
            "updated_at":        _fmt_dt(q.updated_at),
            "replies_summary":   "",   # no thread model in this codebase
        })

    return rows


def _fmt_dt(value) -> str:
    """ISO-8601 string, empty string if None."""
    if value is None:
        return ""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


# ──────────────────────────────────────────────────────────────────────────────
# CSV export
# ──────────────────────────────────────────────────────────────────────────────

CSV_HEADERS = [
    "Question ID",
    "Event ID",
    "Lounge Table ID",
    "Question Text",
    "Author Display Name",
    "Author Type",
    "User ID / Guest ID",
    "Anonymous",
    "Upvote Count",
    "Moderation Status",
    "Rejection Reason",
    "Hidden",
    "Answered",
    "Answered At",
    "Answered By",
    "Requires Follow-up",
    "Pinned",
    "Pinned At",
    "Created At",
    "Updated At",
    "Thread / Replies Summary",
]

_ROW_KEYS = [
    "question_id",
    "event_id",
    "lounge_table_id",
    "content",
    "author_display_name",
    "author_type",
    "actor_id",
    "is_anonymous",
    "upvote_count",
    "moderation_status",
    "rejection_reason",
    "is_hidden",
    "is_answered",
    "answered_at",
    "answered_by",
    "requires_followup",
    "is_pinned",
    "pinned_at",
    "created_at",
    "updated_at",
    "replies_summary",
]


def generate_csv_response(rows: list[dict], event) -> HttpResponse:
    """Return a downloadable CSV HttpResponse."""
    slug = getattr(event, "slug", None) or str(event.pk)
    date_str = timezone.now().strftime("%Y-%m-%d")
    filename = f"{slug}_qna_export_{date_str}.csv"

    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'

    # BOM so Excel opens UTF-8 correctly
    response.write("\ufeff")

    writer = csv.writer(response, quoting=csv.QUOTE_ALL)
    writer.writerow(CSV_HEADERS)
    for row in rows:
        writer.writerow([row.get(k, "") for k in _ROW_KEYS])

    return response


# ──────────────────────────────────────────────────────────────────────────────
# PDF export  (reportlab)
# ──────────────────────────────────────────────────────────────────────────────

def generate_pdf_response(rows: list[dict], event, exported_by: str) -> HttpResponse:
    """Return a downloadable PDF HttpResponse using reportlab Platypus."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        HRFlowable,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    slug = getattr(event, "slug", None) or str(event.pk)
    date_str = timezone.now().strftime("%Y-%m-%d")
    filename = f"{slug}_qna_export_{date_str}.pdf"

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"Q&A Export – {getattr(event, 'title', event.pk)}",
    )

    styles = getSampleStyleSheet()
    style_normal = styles["Normal"]
    style_h1 = ParagraphStyle(
        "H1Export",
        parent=styles["Heading1"],
        fontSize=16,
        spaceAfter=4,
    )
    style_h2 = ParagraphStyle(
        "H2Export",
        parent=styles["Heading2"],
        fontSize=12,
        spaceBefore=12,
        spaceAfter=4,
    )
    style_meta = ParagraphStyle(
        "Meta",
        parent=style_normal,
        fontSize=9,
        textColor=colors.HexColor("#555555"),
        spaceAfter=2,
    )
    style_label = ParagraphStyle(
        "Label",
        parent=style_normal,
        fontSize=8,
        textColor=colors.HexColor("#888888"),
    )
    style_body = ParagraphStyle(
        "Body",
        parent=style_normal,
        fontSize=10,
        leading=14,
        spaceAfter=4,
    )
    style_answer_meta = ParagraphStyle(
        "AnswerMeta",
        parent=style_normal,
        fontSize=8,
        textColor=colors.HexColor("#444444"),
        leading=12,
    )

    export_ts = timezone.now().strftime("%Y-%m-%d %H:%M UTC")

    # ── summary counts ────────────────────────────────────────────────────────
    total      = len(rows)
    answered   = sum(1 for r in rows if r["is_answered"] == "true")
    unanswered = total - answered
    pending    = sum(1 for r in rows if r["moderation_status"] == "pending")
    rejected   = sum(1 for r in rows if r["moderation_status"] == "rejected")
    anonymous  = sum(1 for r in rows if r["is_anonymous"] == "true")
    followup   = sum(1 for r in rows if r["requires_followup"] == "true")
    pinned     = sum(1 for r in rows if r["is_pinned"] == "true")

    story = []

    # ── header ────────────────────────────────────────────────────────────────
    story.append(Paragraph(f"Q&amp;A Export Report", style_h1))
    story.append(Paragraph(
        f"Event: <b>{_esc(getattr(event, 'title', str(event.pk)))}</b> (ID: {event.pk})",
        style_meta,
    ))
    story.append(Paragraph(f"Exported at: {export_ts}", style_meta))
    story.append(Paragraph(f"Exported by: {_esc(exported_by)}", style_meta))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CCCCCC"), spaceAfter=6))

    # ── summary table ─────────────────────────────────────────────────────────
    story.append(Paragraph("Summary", style_h2))

    summary_data = [
        ["Metric", "Count"],
        ["Total Questions", str(total)],
        ["Answered", str(answered)],
        ["Unanswered", str(unanswered)],
        ["Pending Moderation", str(pending)],
        ["Rejected", str(rejected)],
        ["Anonymous", str(anonymous)],
        ["Requires Follow-up", str(followup)],
        ["Pinned", str(pinned)],
    ]
    summary_table = Table(summary_data, colWidths=[9 * cm, 3 * cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1976D2")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, 0), 9),
        ("FONTSIZE",   (0, 1), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F5F5F5"), colors.white]),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.5 * cm))

    # ── question listing ──────────────────────────────────────────────────────
    story.append(Paragraph("Questions", style_h2))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#DDDDDD"), spaceAfter=6))

    if not rows:
        story.append(Paragraph("No questions found for this event.", style_body))
    else:
        for i, row in enumerate(rows, start=1):
            # question number + moderation badge
            badges = []
            if row["is_pinned"] == "true":
                badges.append("PINNED")
            if row["is_hidden"] == "true":
                badges.append("HIDDEN")
            if row["moderation_status"] != "approved":
                badges.append(row["moderation_status"].upper())
            badge_str = ("  [" + " | ".join(badges) + "]") if badges else ""

            story.append(Paragraph(
                f"<b>#{i}</b>  ID: {row['question_id']}{_esc(badge_str)}",
                style_label,
            ))

            # question text
            story.append(Paragraph(_esc(row["content"]), style_body))

            # meta line 1: author + upvotes
            meta1_parts = [
                f"By: <b>{_esc(row['author_display_name'])}</b> ({row['author_type']})",
                f"Upvotes: {row['upvote_count']}",
                f"Asked: {row['created_at'][:16] if row['created_at'] else '—'}",
            ]
            if row["is_anonymous"] == "true":
                meta1_parts.append("[anonymous]")
            story.append(Paragraph("  ·  ".join(meta1_parts), style_answer_meta))

            # meta line 2: answer / follow-up
            if row["is_answered"] == "true":
                ans_info = f"Answered at {row['answered_at'][:16] if row['answered_at'] else '—'}"
                if row["answered_by"]:
                    ans_info += f" by {_esc(row['answered_by'])}"
                story.append(Paragraph(f"Answered: {ans_info}", style_answer_meta))

            if row["requires_followup"] == "true":
                story.append(Paragraph("Follow-up required", style_answer_meta))

            if row["rejection_reason"]:
                story.append(Paragraph(
                    f"Rejection reason: {_esc(row['rejection_reason'])}",
                    style_answer_meta,
                ))

            # separator
            story.append(HRFlowable(
                width="100%",
                thickness=0.3,
                color=colors.HexColor("#EEEEEE"),
                spaceAfter=4,
                spaceBefore=4,
            ))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def _esc(text: str) -> str:
    """Escape text for use inside a reportlab Paragraph (XML-safe)."""
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
