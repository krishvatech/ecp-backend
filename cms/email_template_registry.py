from datetime import timedelta
from pathlib import Path
import re

from django.conf import settings
from django.utils import timezone

from cms.models import REQUIRED_PLACEHOLDERS, TEMPLATE_KEY_CHOICES

TEMPLATE_VARIABLE_RE = re.compile(r"{{\s*([a-zA-Z_][\w]*(?:\.[\w]+)?)")


DEFAULT_SUBJECTS = {
    "welcome": "Welcome to {{ app_name }}",
    "password_changed": "Your {{ app_name }} password was changed",
    "speaker_credentials": "Your {{ app_name }} Speaker Account - Login Credentials",
    "admin_credentials": "Welcome to {{ app_name }} - Your Admin Credentials",
    "event_confirmation": "You're Confirmed as {{ role }} - {{ event_title }}",
    "event_cancelled": "Update: '{{ event_title }}' has been cancelled",
    "event_invite": "You're invited to '{{ event_title }}' on {{ app_name }}",
    "event_starting_soon": "Reminder: '{{ event_title }}' starts in 1 hour",
    "event_join_confirmation": "You've joined '{{ event_title }}'",
    "group_invite": "You're invited to join '{{ group_name }}' on {{ app_name }}",
    "replay_no_show": "You missed '{{ event_title }}' - the recording is now available",
    "replay_partial": "You left '{{ event_title }}' early - catch what you missed",
    "replay_expiring_soon": "Reminder: Replay for '{{ event_title }}' expires soon",
    "application_acknowledgement": "Application Received - {{ event_title }}",
    "application_approved": "Your application to '{{ event_title }}' has been approved!",
    "application_declined": "Your application to '{{ event_title }}' - status update",
    "user_registration_acknowledgement": "Registration Confirmed: {{ event_title }}",
    "guest_registration_acknowledgement": "Registration Confirmed: {{ event_title }}",
    "guest_otp": "Your verification code for {{ event_title }}",
    "guest_followup": "Join {{ app_name }} to unlock exclusive benefits",
    "kyc_approved": "Your identity verification is complete",
    "kyc_failed": "Action needed: identity verification failed",
    "name_change_approved": "Your name change request is approved",
    "name_change_manual_review": "Your name change request is under review",
    "name_change_verification_failed": "Your name change verification was unsuccessful",
    "name_change_rejected": "Your name change request was rejected",
    "admin_name_change_review": "New Identity Review Required: Name Change Request #{{ request_id }}",
    "post_event_qna_answer": "Your Q&A Question Has Been Answered - {{ event_title }}",
    "networking_meeting_request": "1:1 Meeting Request from {{ requester_name }} at {{ event_title }}",
    "networking_meeting_accepted": "Meeting Confirmed: {{ other_party_name }} at {{ event_title }}",
    "networking_meeting_declined": "Meeting Request Declined: {{ other_party_name }} at {{ event_title }}",
    "networking_meeting_suggested": "Alternative Time Suggested: {{ other_party_name }} at {{ event_title }}",
    "networking_meeting_cancelled": "Meeting Cancelled: {{ other_party_name }} at {{ event_title }}",
    "networking_meeting_reminder": "Reminder: Meeting with {{ other_party_name }} in {{ reminder_minutes }} minutes",
}

TEMPLATE_CATEGORIES = {
    "welcome": "Account",
    "password_changed": "Account",
    "speaker_credentials": "Account",
    "admin_credentials": "Account",
    "event_confirmation": "Events",
    "event_cancelled": "Events",
    "event_invite": "Events",
    "event_starting_soon": "Events",
    "event_join_confirmation": "Events",
    "group_invite": "Groups",
    "replay_no_show": "Replay",
    "replay_partial": "Replay",
    "replay_expiring_soon": "Replay",
    "application_acknowledgement": "Applications",
    "application_approved": "Applications",
    "application_declined": "Applications",
    "user_registration_acknowledgement": "Registrations",
    "guest_registration_acknowledgement": "Registrations",
    "guest_otp": "Guests",
    "guest_followup": "Guests",
    "kyc_approved": "Verification",
    "kyc_failed": "Verification",
    "name_change_approved": "Name Changes",
    "name_change_manual_review": "Name Changes",
    "name_change_verification_failed": "Name Changes",
    "name_change_rejected": "Name Changes",
    "admin_name_change_review": "Name Changes",
    "post_event_qna_answer": "Events",
    "networking_meeting_request": "Networking",
    "networking_meeting_accepted": "Networking",
    "networking_meeting_declined": "Networking",
    "networking_meeting_suggested": "Networking",
    "networking_meeting_cancelled": "Networking",
    "networking_meeting_reminder": "Networking",
}

MERGE_TAG_LABELS = {
    "app_name": "App Name",
    "first_name": "First Name",
    "changed_at": "Changed At",
    "temporary_password": "Temporary Password",
    "username": "Username",
    "email": "Email",
    "login_url": "Login URL",
    "forgot_password_url": "Forgot Password URL",
    "role": "Role",
    "event_title": "Event Title",
    "event_name": "Event Name",
    "event_description": "Event Description",
    "event_url": "Join Link",
    "event_date": "Event Date",
    "event_start": "Event Start",
    "event_end": "Event End",
    "event_start_str": "Event Start Time",
    "event_end_str": "Event End Time",
    "event_date_str": "Event Date",
    "event_date_range_str": "Event Date Range",
    "event_timezone": "Event Timezone",
    "event_location": "Event Location",
    "is_multi_day": "Is Multi-day Event",
    "support_email": "Support Email",
    "profile_url": "Profile URL",
    "cancellation_message": "Cancellation Message",
    "recommended_event_title": "Recommended Event Title",
    "recommended_event_url": "Recommended Event URL",
    "inviter_name": "Inviter Name",
    "invite_url": "Invite URL",
    "group_name": "Group Name",
    "replay_url": "Replay URL",
    "expiration_date": "Expiration Date",
    "applicant_name": "Applicant Name",
    "magic_link": "Magic Link",
    "custom_message": "Custom Message",
    "guest_name": "Guest Name",
    "otp_code": "OTP Code",
    "expiry_minutes": "Expiry Minutes",
    "signup_url": "Signup URL",
    "benefit": "Benefit",
    "new_name": "New Name",
    "requested_name": "Requested Name",
    "id_name": "ID Name",
    "profile_name": "Profile Name",
    "verified_name": "Verified Name",
    "verified_at": "Verified At",
    "updated_at": "Updated At",
    "reason_label": "Reason Label",
    "admin_note": "Admin Note",
    "decided_at": "Decided At",
    "user_email": "User Email",
    "request_id": "Request ID",
    "admin_url": "Admin URL",
    "reason": "Reason",
    "received_at": "Received At",
    "recipient_name": "Recipient Name",
    "answering_user_name": "Answering User Name",
    "answer_text": "Answer Text",
    "question_text": "Question Text",
    "requester_name": "Requester Name",
    "requester_company": "Requester Company",
    "requester_job_title": "Requester Job Title",
    "other_party_name": "Other Party Name",
    "companion_url": "Companion URL",
    "reminder_minutes": "Reminder Minutes",
    "meeting_time": "Meeting Time",
    "meeting_date": "Meeting Date",
    "meeting_url": "Meeting URL",
    "duration_minutes": "Duration Minutes",
    "message": "Message",
    "table_number": "Table Number",
    "suggested_date": "Suggested Date",
    "suggested_time": "Suggested Time",
    "suggestion_message": "Suggestion Message",
    "location": "Location",
}

COMMON_CONTEXT = {
    "app_name": "IMAA Connect",
    "first_name": "Alex",
    "support_email": getattr(settings, "SUPPORT_EMAIL", "support@example.com"),
}

EVENT_CONTEXT = {
    "event_title": "M&A Leadership Summit",
    "event_name": "M&A Leadership Summit",
    "event_url": "https://example.com/events/leadership-summit/",
    "event_date": timezone.now() + timedelta(days=7),
    "event_start": timezone.now() + timedelta(days=7),
    "event_end": timezone.now() + timedelta(days=7, hours=2),
    "event_start_str": "10:00 AM",
    "event_end_str": "12:00 PM",
    "event_date_str": "June 1, 2026",
    "event_date_range_str": "June 1, 2026",
    "event_timezone": "Asia/Kolkata",
    "event_location": "Online",
    "event_description": "A focused leadership session for M&A professionals.",
    "is_multi_day": False,
}

TEMPLATE_VARIABLES = {
    "welcome": ["app_name", "first_name", "support_email"],
    "password_changed": ["app_name", "first_name", "changed_at", "support_email"],
    "speaker_credentials": ["app_name", "first_name", "temporary_password", "login_url", "support_email"],
    "admin_credentials": ["app_name", "first_name", "temporary_password", "login_url", "support_email"],
    "event_confirmation": ["app_name", "first_name", "role", *EVENT_CONTEXT.keys(), "support_email"],
    "event_cancelled": ["app_name", "first_name", *EVENT_CONTEXT.keys(), "support_email"],
    "event_invite": ["app_name", "inviter_name", "event_title", "invite_url", "support_email"],
    "event_starting_soon": ["app_name", "first_name", *EVENT_CONTEXT.keys(), "support_email"],
    "event_join_confirmation": ["app_name", "first_name", *EVENT_CONTEXT.keys(), "support_email"],
    "group_invite": ["app_name", "inviter_name", "group_name", "invite_url", "support_email"],
    "replay_no_show": ["app_name", "first_name", "event_title", "replay_url", "support_email"],
    "replay_partial": ["app_name", "first_name", "event_title", "replay_url", "support_email"],
    "replay_expiring_soon": ["app_name", "first_name", "event_title", "event_url", "replay_url", "expiration_date", "support_email"],
    "application_acknowledgement": ["app_name", "applicant_name", *EVENT_CONTEXT.keys(), "support_email"],
    "application_approved": ["app_name", "applicant_name", *EVENT_CONTEXT.keys(), "support_email"],
    "application_declined": ["app_name", "applicant_name", *EVENT_CONTEXT.keys(), "support_email"],
    "user_registration_acknowledgement": ["app_name", "first_name", *EVENT_CONTEXT.keys(), "support_email"],
    "guest_registration_acknowledgement": ["app_name", "guest_name", *EVENT_CONTEXT.keys(), "support_email"],
    "guest_otp": ["app_name", "guest_name", "otp_code", "event_title", "support_email"],
    "guest_followup": ["app_name", "guest_name", "event_title", "signup_url", "support_email"],
    "kyc_approved": ["app_name", "first_name", "support_email"],
    "kyc_failed": ["app_name", "first_name", "support_email"],
    "name_change_approved": ["app_name", "first_name", "new_name", "support_email"],
    "name_change_manual_review": ["app_name", "first_name", "support_email"],
    "name_change_verification_failed": ["app_name", "first_name", "support_email"],
    "name_change_rejected": ["app_name", "first_name", "support_email"],
    "admin_name_change_review": ["app_name", "user_email", "request_id", "support_email"],
    "post_event_qna_answer": ["app_name", "recipient_name", "event_name", "event_title", "answer_text", "question_text", "support_email"],
    "networking_meeting_request": ["app_name", "first_name", "requester_name", "event_title", "companion_url", "meeting_time", "support_email"],
    "networking_meeting_accepted": ["app_name", "first_name", "other_party_name", "event_title", "companion_url", "meeting_time", "support_email"],
    "networking_meeting_declined": ["app_name", "first_name", "other_party_name", "event_title", "companion_url", "support_email"],
    "networking_meeting_suggested": ["app_name", "first_name", "other_party_name", "event_title", "companion_url", "meeting_time", "support_email"],
    "networking_meeting_cancelled": ["app_name", "first_name", "other_party_name", "event_title", "companion_url", "support_email"],
    "networking_meeting_reminder": ["app_name", "first_name", "other_party_name", "event_title", "reminder_minutes", "companion_url", "meeting_time", "support_email"],
}

SAMPLE_VALUES = {
    **COMMON_CONTEXT,
    **EVENT_CONTEXT,
    "changed_at": "May 25, 2026 at 10:30 AM",
    "temporary_password": "TempPass123!",
    "username": "alex@example.com",
    "email": "alex@example.com",
    "login_url": "https://example.com/login",
    "forgot_password_url": "https://example.com/forgot-password",
    "role": "Attendee",
    "profile_url": "https://example.com/profile",
    "cancellation_message": "This event has been cancelled due to a scheduling conflict.",
    "recommended_event_title": "M&A Strategy Roundtable",
    "recommended_event_url": "https://example.com/events/strategy-roundtable/",
    "inviter_name": "Jordan Lee",
    "invite_url": "https://example.com/invite/abc123",
    "group_name": "M&A Practitioners",
    "replay_url": "https://example.com/replays/leadership-summit/",
    "expiration_date": timezone.now() + timedelta(days=2),
    "applicant_name": "Taylor Morgan",
    "magic_link": "https://example.com/magic/join",
    "custom_message": "Thank you for your interest. We are unable to approve this application at this time.",
    "guest_name": "Sam Rivera",
    "otp_code": "123456",
    "expiry_minutes": 10,
    "signup_url": "https://example.com/signup",
    "benefit": "save your event history and access community networking",
    "new_name": "Alex Morgan",
    "requested_name": "Alex Morgan",
    "id_name": "Alexander Morgan",
    "profile_name": "Alex M.",
    "verified_name": "Alex Morgan",
    "verified_at": "May 25, 2026 at 10:30 AM",
    "updated_at": "May 25, 2026 at 10:30 AM",
    "reason_label": "Name mismatch",
    "admin_note": "Please upload a clearer document.",
    "decided_at": "May 25, 2026 at 10:30 AM",
    "user_email": "alex@example.com",
    "request_id": "NCR-1001",
    "admin_url": "https://example.com/admin/name-requests/NCR-1001",
    "reason": "The submitted ID name differs from the requested profile name.",
    "received_at": "May 25, 2026 at 10:30 AM",
    "recipient_name": "Alex",
    "answering_user_name": "Dr. Morgan Chen",
    "answer_text": "Here is the follow-up answer from the speaker.",
    "question_text": "What should we prioritize after the event?",
    "requester_name": "Priya Shah",
    "requester_company": "Northstar Capital",
    "requester_job_title": "Director",
    "other_party_name": "Morgan Chen",
    "companion_url": "https://example.com/networking",
    "reminder_minutes": 15,
    "meeting_time": "11:30 AM",
    "meeting_date": "June 1, 2026",
    "meeting_url": "https://example.com/networking/meetings/123",
    "duration_minutes": 30,
    "message": "I would like to connect after your session.",
    "table_number": "Table 4",
    "suggested_date": "June 2, 2026",
    "suggested_time": "2:00 PM",
    "suggestion_message": "Could we meet the next afternoon instead?",
    "location": "Networking Lounge",
}

def unique_in_order(values):
    seen = set()
    ordered = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def variables_from_template_files(template_key):
    variables = []
    template_dir = Path(settings.BASE_DIR) / "templates" / "emails"
    for extension in ("html", "txt"):
        path = template_dir / f"{template_key}.{extension}"
        if path.exists():
            variables.extend(match.split(".")[0] for match in TEMPLATE_VARIABLE_RE.findall(path.read_text(encoding="utf-8")))
    variables.extend(match.split(".")[0] for match in TEMPLATE_VARIABLE_RE.findall(DEFAULT_SUBJECTS.get(template_key, "")))
    return unique_in_order(variables)


def get_template_registry():
    registry = {}
    labels = dict(TEMPLATE_KEY_CHOICES)
    for key, label in TEMPLATE_KEY_CHOICES:
        variables = unique_in_order([*TEMPLATE_VARIABLES.get(key, []), *variables_from_template_files(key)])
        registry[key] = {
            "label": label,
            "category": TEMPLATE_CATEGORIES.get(key, "General"),
            "default_subject": DEFAULT_SUBJECTS.get(key, f"[{key}]"),
            "merge_tags": [
                {"label": MERGE_TAG_LABELS.get(var, var.replace("_", " ").title()), "tag": f"{{{{ {var} }}}}", "key": var}
                for var in variables
            ],
            "required_placeholders": REQUIRED_PLACEHOLDERS.get(key, []),
            "sample_context": {var: SAMPLE_VALUES.get(var, "") for var in variables},
        }
    return registry


EMAIL_TEMPLATE_REGISTRY = get_template_registry()


def get_template_metadata(template_key):
    return EMAIL_TEMPLATE_REGISTRY.get(template_key)
