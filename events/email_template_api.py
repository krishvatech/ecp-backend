from django.conf import settings
from django.template import Context, Template as DjangoTemplate
from rest_framework import serializers

from cms.api import (
    compile_mjml,
    get_file_defaults,
    render_template_parts,
    validate_required_placeholders,
    validate_template_syntax,
)
from cms.email_template_registry import get_template_metadata
from cms.models import EmailTemplate
from users.email_utils import format_event_time_for_email, send_platform_email

from .models import EventEmailTemplate


EVENT_EMAIL_TEMPLATE_KEYS = {key for key, _label in EventEmailTemplate.TEMPLATE_KEY_CHOICES}


def user_can_manage_event_email_templates(user, event):
    return bool(
        user
        and user.is_authenticated
        and (user.is_superuser or user.is_staff or event.created_by_id == user.id)
    )


def event_frontend_url(event):
    frontend_base = getattr(settings, "FRONTEND_URL", "").rstrip("/")
    slug_or_id = event.slug or event.id
    return f"{frontend_base}/events/{slug_or_id}/" if frontend_base else f"/events/{slug_or_id}/"


def event_location_text(event):
    parts = [getattr(event, "location", "") or ""]
    country = getattr(event, "location_country", "") or ""
    if country:
        parts.append(country)
    return ", ".join([part for part in parts if part])


def build_event_email_sample_context(event, template_key, user=None):
    metadata = get_template_metadata(template_key) or {}
    context = dict(metadata.get("sample_context", {}))
    time_info = format_event_time_for_email(event)
    frontend_base = getattr(settings, "FRONTEND_URL", "").rstrip("/")
    display_name = ""
    email = ""
    if user and user.is_authenticated:
        display_name = user.first_name or user.username or "Alex"
        email = user.email or "alex@example.com"

    context.update({
        "app_name": "IMAA Connect",
        "first_name": display_name or "Alex",
        "last_name": getattr(user, "last_name", "") if user and user.is_authenticated else "Morgan",
        "email": email or "alex@example.com",
        "recipient_name": display_name or "Alex",
        "guest_name": "Sam Rivera",
        "applicant_name": "Taylor Morgan",
        "event_title": event.title,
        "event_name": event.title,
        "event_description": getattr(event, "description", "") or "",
        "event_date": time_info.get("start_time_in_tz"),
        "event_start": time_info.get("start_time_in_tz"),
        "event_end": time_info.get("end_time_in_tz"),
        "event_start_str": time_info.get("event_start_str", ""),
        "event_end_str": time_info.get("event_end_str", ""),
        "event_date_str": time_info.get("event_date_str", ""),
        "event_date_range_str": time_info.get("event_date_range_str", ""),
        "event_timezone": getattr(event, "timezone", "") or "",
        "is_multi_day": getattr(event, "is_multi_day", False),
        "event_url": event_frontend_url(event),
        "event_location": event_location_text(event),
        "event_format": getattr(event, "format", "") or "",
        "support_email": getattr(settings, "SUPPORT_EMAIL", getattr(settings, "DEFAULT_FROM_EMAIL", "")),
        "login_url": f"{frontend_base}/login" if frontend_base else "/login",
        "profile_url": f"{frontend_base}/profile/{getattr(user, 'username', 'alex')}" if frontend_base else "/profile/alex",
        "invite_url": f"{event_frontend_url(event)}invite/sample/",
        "replay_url": f"{frontend_base}/account/recordings" if frontend_base else "/account/recordings",
        "companion_url": f"{frontend_base}/networking" if frontend_base else "/networking",
        "meeting_url": f"{frontend_base}/networking/meetings/sample" if frontend_base else "/networking/meetings/sample",
        "magic_link": f"{frontend_base}/auth/magic-link?token=sample" if frontend_base else "/auth/magic-link?token=sample",
        "signup_url": f"{frontend_base}/signup" if frontend_base else "/signup",
        "role": "Speaker",
        "inviter_name": "Jordan Lee",
        "group_name": "M&A Practitioners",
        "cancellation_message": getattr(event, "cancellation_message", "") or "This event has been cancelled.",
        "recommended_event_title": getattr(getattr(event, "recommended_event", None), "title", "") or "Recommended Event",
        "recommended_event_url": event_frontend_url(getattr(event, "recommended_event", event)),
        "custom_message": "Thank you for your interest. We are unable to approve this application at this time.",
        "expiration_date": time_info.get("end_time_in_tz"),
        "answering_user_name": "Dr. Morgan Chen",
        "question_text": "What should we prioritize after the event?",
        "answer_text": "Here is the follow-up answer from the speaker.",
        "requester_name": "Priya Shah",
        "requester_company": "Northstar Capital",
        "requester_job_title": "Director",
        "other_party_name": "Morgan Chen",
        "meeting_date": time_info.get("event_date_str", ""),
        "meeting_time": "11:30 AM",
        "duration_minutes": 30,
        "message": "I would like to connect after your session.",
        "reminder_minutes": 15,
        "table_number": "Table 4",
        "suggested_date": time_info.get("event_date_str", ""),
        "suggested_time": "2:00 PM",
        "suggestion_message": "Could we meet the next afternoon instead?",
        "location": "Networking Lounge",
    })
    return context


def get_event_email_template_payload(event, template_key):
    metadata = get_template_metadata(template_key)
    if template_key not in EVENT_EMAIL_TEMPLATE_KEYS or not metadata:
        return None

    event_template = EventEmailTemplate.objects.filter(event=event, template_key=template_key).select_related("updated_by").first()
    if event_template:
        return {
            "id": event_template.id,
            "event": event.id,
            "template_key": template_key,
            "label": metadata["label"],
            "category": metadata["category"],
            "subject": event_template.subject,
            "html_body": event_template.html_body,
            "text_body": event_template.text_body,
            "editor_json": event_template.editor_json,
            "mjml_body": event_template.mjml_body,
            "editor_type": event_template.editor_type,
            "is_active": event_template.is_active,
            "notes": event_template.notes,
            "updated_by": event_template.updated_by_id,
            "updated_by_name": event_template.updated_by.get_full_name() or event_template.updated_by.email if event_template.updated_by else None,
            "created_at": event_template.created_at,
            "updated_at": event_template.updated_at,
            "source": "event_specific",
            "status": "active" if event_template.is_active else "inactive",
            "merge_tags": metadata["merge_tags"],
            "required_placeholders": metadata["required_placeholders"],
        }

    global_template = EmailTemplate.objects.filter(template_key=template_key, is_active=True).select_related("updated_by").first()
    if global_template:
        return {
            "id": None,
            "event": event.id,
            "template_key": template_key,
            "label": metadata["label"],
            "category": metadata["category"],
            "subject": global_template.subject,
            "html_body": global_template.html_body,
            "text_body": global_template.text_body,
            "editor_json": global_template.editor_json,
            "mjml_body": global_template.mjml_body,
            "editor_type": global_template.editor_type,
            "is_active": True,
            "notes": global_template.notes,
            "updated_by": None,
            "updated_by_name": None,
            "created_at": global_template.created_at,
            "updated_at": global_template.last_updated,
            "source": "global_default",
            "status": "global_default",
            "merge_tags": metadata["merge_tags"],
            "required_placeholders": metadata["required_placeholders"],
        }

    defaults = get_file_defaults(template_key)
    return {
        "id": None,
        "event": event.id,
        "template_key": template_key,
        "label": metadata["label"],
        "category": metadata["category"],
        "subject": defaults["subject"],
        "html_body": defaults["html_body"],
        "text_body": defaults["text_body"],
        "editor_json": None,
        "mjml_body": "",
        "editor_type": "templatical",
        "is_active": True,
        "notes": "",
        "updated_by": None,
        "updated_by_name": None,
        "created_at": None,
        "updated_at": None,
        "source": "file_default",
        "status": "file_default",
        "merge_tags": metadata["merge_tags"],
        "required_placeholders": metadata["required_placeholders"],
    }


def validate_event_email_parts(template_key, subject, html_body, text_body, mjml_body=""):
    if not subject or not subject.strip():
        raise serializers.ValidationError({"subject": "Subject is required."})
    validate_template_syntax(subject, html_body, text_body)
    validate_required_placeholders(template_key, html_body, mjml_body, text_body)


def render_event_email_payload(event, template_key, payload, user=None, overrides=None):
    data = {**payload, **(overrides or {})}
    subject = data.get("subject", "")
    html_body = data.get("html_body", "")
    text_body = data.get("text_body", "")
    mjml_body = data.get("mjml_body", "")
    if mjml_body:
        html_body = compile_mjml(mjml_body)
    validate_event_email_parts(template_key, subject, html_body, text_body, mjml_body)
    context = build_event_email_sample_context(event, template_key, user=user)
    return render_template_parts(subject, html_body, text_body, context)


def save_event_email_template(event, template_key, data, user):
    current = get_event_email_template_payload(event, template_key)
    if not current:
        raise serializers.ValidationError({"template_key": "Template not found."})

    subject = data.get("subject", current["subject"])
    html_body = data.get("html_body", current["html_body"])
    text_body = data.get("text_body", current["text_body"])
    mjml_body = data.get("mjml_body", current["mjml_body"])
    if "mjml_body" in data and mjml_body:
        html_body = compile_mjml(mjml_body)

    validate_event_email_parts(template_key, subject, html_body, text_body, mjml_body)

    obj, _created = EventEmailTemplate.objects.get_or_create(
        event=event,
        template_key=template_key,
        defaults={
            "subject": subject,
            "html_body": html_body or "",
            "text_body": text_body or "",
        },
    )
    for field in ("subject", "html_body", "text_body", "editor_json", "mjml_body", "editor_type", "is_active", "notes"):
        if field in data:
            setattr(obj, field, data[field])
    obj.subject = subject
    obj.html_body = html_body or ""
    obj.text_body = text_body or ""
    obj.mjml_body = mjml_body or ""
    obj.updated_by = user
    obj.save()
    return obj


def send_event_email_test(event, template_key, test_email, user=None):
    payload = get_event_email_template_payload(event, template_key)
    if not payload:
        raise serializers.ValidationError({"template_key": "Template not found."})
    rendered = render_event_email_payload(event, template_key, payload, user=user)
    send_platform_email(
        subject=rendered["rendered_subject"],
        message=rendered["rendered_text"],
        recipient_list=[test_email],
        html_message=rendered["rendered_html"],
        fail_silently=False,
    )
    return rendered
