# users/validators.py
from __future__ import annotations

import re
from django.core.exceptions import ValidationError
from django.conf import settings
from django.contrib.auth import get_user_model

# If you use the "email-validator" package (recommended):
from email_validator import validate_email as ev_validate_email, EmailNotValidError

User = get_user_model()

# Simple phone-like detector (8–15 digits, optional +)
PHONE_LIKE_RE = re.compile(r"^\+?\d{8,15}$")


def validate_email_smart(value: str) -> str:
    """
    Validate & normalize an email using the 'email-validator' library.

    - Handles syntax, IDN/unicode, and (optionally) DNS deliverability
    - Returns the normalized (lowercased) email string
    """
    v = (value or "").strip()
    check_deliverability = bool(getattr(settings, "STRICT_EMAIL_DNS", True))
    try:
        info = ev_validate_email(v, check_deliverability=check_deliverability)
        return info.email  # already normalized
    except EmailNotValidError as e:
        raise ValidationError(str(e))


def validate_email_strict(value: str, instance=None) -> str:
    """
    Extended email validator used by BOTH register and update flows.

    Wraps validate_email_smart and adds:
    - Reject phone-like strings (e.g., '9876543210')
    - Reject numeric-only local part (e.g., '123@gmail.com')
    - Enforce uniqueness case-insensitively (ignoring the current instance on update)
    """
    v = validate_email_smart(value).lower()

    # Block phone-like entries
    if PHONE_LIKE_RE.match(v):
        raise ValidationError("Please enter a valid email address, not a phone number.")

    # Block numeric-only local part
    if "@" in v:
        local = v.split("@", 1)[0]
        if local.isdigit():
            raise ValidationError("Email name cannot be only numbers.")

    # Uniqueness (ignore current instance on update)
    qs = User.objects.filter(email__iexact=v)
    if instance is not None:
        qs = qs.exclude(pk=getattr(instance, "pk", None))
    if qs.exists():
        raise ValidationError("A user with this email already exists.")

    return v
