"""
Custom admin views for email template management.
Provides preview and test-send functionality for EmailTemplate snippets.
"""
import logging
from django.contrib.admin.views.decorators import staff_member_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.template import Template as DjangoTemplate, Context
from django.utils.timezone import now
from django.conf import settings
from django.core.mail import send_mail

logger = logging.getLogger(__name__)

# Sample context per template key — used for preview and test send
SAMPLE_CONTEXTS = {
    "welcome": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "email": "alex@example.com",
        "login_url": "https://example.com/login",
        "support_email": "support@example.com",
    },
    "password_changed": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "email": "alex@example.com",
        "changed_at": "17 Mar 2026, 10:30 AM UTC",
        "forgot_password_url": "https://example.com/forgot-password",
        "support_email": "support@example.com",
    },
    "speaker_credentials": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "last_name": "Smith",
        "username": "alex.smith",
        "email": "alex@example.com",
        "temporary_password": "TempP@ss123",
        "login_url": "https://example.com/login",
        "support_email": "support@example.com",
    },
    "admin_credentials": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "username": "alex.smith",
        "email": "alex@example.com",
        "temporary_password": "TempP@ss123",
        "login_url": "https://example.com/login",
        "support_email": "support@example.com",
    },
    "event_confirmation": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "last_name": "Smith",
        "role": "Speaker",
        "event_title": "M&A Innovation Summit 2026",
        "event_description": "A premier event for M&A professionals.",
        "event_start": now(),
        "event_end": now(),
        "event_timezone": "America/New_York",
        "event_url": "https://example.com/events/sample-event/",
        "profile_url": "https://example.com/profile/alex.smith",
        "login_url": "https://example.com/login",
        "support_email": "support@example.com",
    },
    "event_cancelled": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "event_title": "M&A Innovation Summit 2026",
        "event_start": now(),
        "event_end": now(),
        "event_timezone": "America/New_York",
        "cancellation_message": "Due to unforeseen circumstances we must cancel.",
        "has_recommended_event": True,
        "recommended_event_title": "M&A Leadership Forum",
        "recommended_event_url": "https://example.com/events/alternative/",
        "event_url": "https://example.com/events/sample-event/",
        "support_email": "support@example.com",
    },
    "event_invite": {
        "app_name": "IMAA Connect",
        "inviter_name": "Jordan Lee",
        "event_title": "M&A Innovation Summit 2026",
        "event_start": now(),
        "event_end": now(),
        "event_timezone": "America/New_York",
        "invite_url": "https://example.com/invites/abc123",
        "support_email": "support@example.com",
    },
    "group_invite": {
        "app_name": "IMAA Connect",
        "inviter_name": "Jordan Lee",
        "group_name": "M&A Professionals Network",
        "invite_url": "https://example.com/groups/invite/abc123",
        "support_email": "support@example.com",
    },
    "replay_no_show": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "event_title": "M&A Innovation Summit 2026",
        "event_start": now(),
        "event_end": now(),
        "event_timezone": "America/New_York",
        "event_url": "https://example.com/events/sample-event/",
        "replay_url": "https://example.com/account/recordings",
        "support_email": "support@example.com",
    },
    "replay_partial": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "event_title": "M&A Innovation Summit 2026",
        "event_start": now(),
        "event_end": now(),
        "event_timezone": "America/New_York",
        "event_url": "https://example.com/events/sample-event/",
        "replay_url": "https://example.com/account/recordings",
        "support_email": "support@example.com",
    },
    "kyc_approved": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "email": "alex@example.com",
        "verified_at": "17 Mar 2026, 10:00 AM UTC",
        "verified_name": "Alex Jordan Smith",
        "support_email": "support@example.com",
    },
    "kyc_failed": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "email": "alex@example.com",
        "reason_code": "name_mismatch",
        "reason_label": "Name mismatch - profile name didn't match your ID name",
        "profile_name": "Alex Smith",
        "id_name": "Alexander Smith",
        "support_email": "support@example.com",
    },
    "name_change_approved": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "new_name": "Alexander J. Smith",
        "requested_name": "Alexander Smith",
        "id_name": "Alexander J Smith",
        "admin_note": "Verified via passport.",
        "decided_at": "17 Mar 2026",
        "updated_at": "17 Mar 2026",
        "support_email": "support@example.com",
    },
    "name_change_manual_review": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "requested_name": "Alexander Smith",
        "id_name": "Alexander J Smith",
        "updated_at": "17 Mar 2026",
        "support_email": "support@example.com",
    },
    "name_change_verification_failed": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "support_email": "support@example.com",
    },
    "name_change_rejected": {
        "app_name": "IMAA Connect",
        "first_name": "Alex",
        "requested_name": "Alexander Smith",
        "admin_note": "Cannot verify.",
        "decided_at": "17 Mar 2026",
        "support_email": "support@example.com",
    },
    "admin_name_change_review": {
        "app_name": "IMAA Connect",
        "user_email": "alex@example.com",
        "request_id": 42,
        "requested_name": "Alexander Smith",
        "id_name": "Alexander J Smith",
        "reason": "User submitted name change request.",
        "admin_note": "",
        "received_at": "17 Mar 2026, 10:00 AM UTC",
        "admin_url": "https://example.com/admin",
    },
}


@staff_member_required
def email_template_preview(request, pk):
    """
    Render the email template HTML with sample context.
    Returns the rendered HTML as an iframe-ready response.
    Accessible via: GET /cms/email-templates/<pk>/preview/
    """
    from cms.models import EmailTemplate

    template = get_object_or_404(EmailTemplate, pk=pk)
    sample_ctx = SAMPLE_CONTEXTS.get(template.template_key, {})
    ctx = Context(sample_ctx)

    try:
        rendered_html = DjangoTemplate(template.html_body).render(ctx)
    except Exception as e:
        rendered_html = f"<pre>Template rendering error:\n{e}</pre>"

    return HttpResponse(rendered_html, content_type="text/html")


@staff_member_required
def email_template_test_send(request, pk):
    """
    Send a test email with the template to the logged-in admin's email address.
    Accessible via: POST /cms/email-templates/<pk>/test-send/
    """
    from cms.models import EmailTemplate

    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    template = get_object_or_404(EmailTemplate, pk=pk)
    admin_email = request.user.email

    if not admin_email:
        return JsonResponse(
            {"error": "Your account has no email address."}, status=400
        )

    sample_ctx = SAMPLE_CONTEXTS.get(template.template_key, {})
    ctx = Context(sample_ctx)

    try:
        subject = DjangoTemplate(template.subject).render(ctx)
        html_body = DjangoTemplate(template.html_body).render(ctx)
        text_body = DjangoTemplate(template.text_body).render(ctx)
    except Exception as e:
        return JsonResponse({"error": f"Render error: {e}"}, status=500)

    try:
        send_mail(
            subject=f"[TEST] {subject}",
            message=text_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[admin_email],
            html_message=html_body or None,
            fail_silently=False,
        )
        return JsonResponse({"success": True, "sent_to": admin_email})
    except Exception as e:
        logger.error(f"Test send failed for template {pk}: {e}")
        return JsonResponse({"error": str(e)}, status=500)
