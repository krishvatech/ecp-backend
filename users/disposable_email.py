"""Disposable email domain checks for new account signup.

Shared by the Django signup paths and the Cognito Pre Sign-up Lambda
(deploy/cognito_pre_signup/), so both enforce the same rules. The core of this
module only uses the standard library; Django settings are read lazily by the
``*_signup_*`` helpers at the bottom, which the Lambda does not call.

The blocklist is a local, versioned copy of
https://github.com/disposable-email-domains/disposable-email-domains (see
disposable_email_data/SOURCE.json). Nothing is fetched at request time.

These checks apply to NEW accounts only. Existing users keep logging in and
updating their profiles even when their domain is listed.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)

DISPOSABLE_EMAIL_CODE = "disposable_email_domain"
INVALID_EMAIL_CODE = "invalid_email"
ALLOWED_CODE = "allowed"

DISPOSABLE_EMAIL_MESSAGE = (
    "Temporary or disposable email addresses are not supported. "
    "Please use your regular email address."
)
INVALID_EMAIL_MESSAGE = "Enter a valid email address."

DATA_DIR = Path(__file__).resolve().with_name("disposable_email_data")
BLOCKLIST_PATH = DATA_DIR / "disposable_email_blocklist.conf"
ALLOWLIST_PATH = DATA_DIR / "allowlist.conf"

# A healthy upstream list has thousands of entries. Fewer than this means the
# file is truncated or the wrong file, which is logged as an error.
MIN_EXPECTED_BLOCKLIST_SIZE = 1000

_MAX_EMAIL_LENGTH = 254
_MAX_DOMAIN_LENGTH = 253
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True)
class EmailDomainCheck:
    """Result of checking one email address."""

    allowed: bool
    code: str
    domain: str = ""
    matched_domain: str = ""

    @property
    def is_disposable(self) -> bool:
        return self.code == DISPOSABLE_EMAIL_CODE

    @property
    def message(self) -> str:
        if self.code == DISPOSABLE_EMAIL_CODE:
            return DISPOSABLE_EMAIL_MESSAGE
        if self.code == INVALID_EMAIL_CODE:
            return INVALID_EMAIL_MESSAGE
        return ""


@dataclass(frozen=True)
class DomainLists:
    blocked: frozenset
    allowed: frozenset = frozenset()


def normalize_domain(value) -> str:
    """
    Return ``value`` as a lowercase ASCII (IDNA) domain, or "" when it is not a
    usable domain. Internationalized domains are converted to punycode, which is
    how the blocklist stores them.
    """
    if not isinstance(value, str):
        return ""
    domain = value.strip().rstrip(".").lower()
    if not domain or len(domain) > _MAX_DOMAIN_LENGTH:
        return ""
    if not domain.isascii():
        try:
            domain = domain.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return ""
    labels = domain.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(label) for label in labels):
        return ""
    return domain


def extract_email_domain(email) -> str:
    """Return the normalized domain of ``email``, or "" when it is malformed."""
    if not isinstance(email, str):
        return ""
    value = email.strip()
    if not value or len(value) > _MAX_EMAIL_LENGTH:
        return ""
    local, sep, domain = value.rpartition("@")
    if not sep or not local or any(ch.isspace() for ch in value):
        return ""
    return normalize_domain(domain)


def _candidate_domains(domain: str) -> list[str]:
    """``a.b.example.com`` -> [a.b.example.com, b.example.com, example.com]."""
    labels = [label for label in domain.split(".") if label]
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def _lenient_email_domain(email) -> str:
    """
    Best-effort domain of an address that failed strict parsing, e.g.
    ``"a b"@mailinator.com`` or ``a@x_y.mailinator.com``. Used only to look for
    a blocklist match, so an address Cognito accepts but we consider malformed
    cannot slip past the check.
    """
    if not isinstance(email, str):
        return ""
    _, sep, domain = email.strip().rpartition("@")
    domain = domain.strip().rstrip(".").lower()
    if not sep or not domain:
        return ""
    if not domain.isascii():
        try:
            domain = domain.encode("idna").decode("ascii").lower()
        except UnicodeError:
            pass
    return domain


def parse_domain_lines(lines: Iterable[str], *, source: str = "") -> frozenset:
    """
    Parse one domain per line. Blank lines and ``#`` comments are ignored;
    malformed entries are skipped (and counted in a warning) instead of failing.
    """
    domains = set()
    skipped = 0
    for raw in lines:
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        domain = normalize_domain(entry)
        if domain:
            domains.add(domain)
        else:
            skipped += 1
    if skipped:
        logger.warning("Skipped %s malformed domain entries in %s", skipped, source or "domain list")
    return frozenset(domains)


def parse_domain_csv(value) -> frozenset:
    """Parse a comma/whitespace separated domain list (settings or env vars)."""
    if not value:
        return frozenset()
    if isinstance(value, str):
        value = re.split(r"[\s,]+", value)
    return parse_domain_lines((str(item) for item in value), source="configured allowlist")


def load_domain_file(path) -> frozenset:
    path = Path(path)
    with path.open(encoding="utf-8") as handle:
        return parse_domain_lines(handle, source=path.name)


def load_domain_lists(blocklist_path=BLOCKLIST_PATH, allowlist_path=ALLOWLIST_PATH) -> DomainLists:
    """
    Load the bundled lists. If the blocklist cannot be read, the error is logged
    and an empty blocklist is returned, so a packaging fault never blocks every
    signup; the logged error is what alerts us.
    """
    try:
        blocked = load_domain_file(blocklist_path)
    except (OSError, UnicodeError):
        logger.exception("Disposable email blocklist could not be loaded from %s", blocklist_path)
        blocked = frozenset()
    if len(blocked) < MIN_EXPECTED_BLOCKLIST_SIZE:
        logger.error(
            "Disposable email blocklist has only %s entries (expected at least %s)",
            len(blocked),
            MIN_EXPECTED_BLOCKLIST_SIZE,
        )

    try:
        allowed = load_domain_file(allowlist_path)
    except FileNotFoundError:
        allowed = frozenset()
    except (OSError, UnicodeError):
        logger.exception("Disposable email allowlist could not be loaded from %s", allowlist_path)
        allowed = frozenset()

    return DomainLists(blocked=blocked, allowed=allowed)


def match_disposable_domain(domain: str, lists: DomainLists, extra_allowed: frozenset = frozenset()) -> str:
    """
    Return the blocklist entry that ``domain`` falls under, or "" when the domain
    is not listed or is allowlisted. ``domain`` must already be normalized.
    """
    candidates = _candidate_domains(domain)
    if any(c in lists.allowed or c in extra_allowed for c in candidates):
        return ""
    return next((c for c in candidates if c in lists.blocked), "")


def check_email(email, lists: DomainLists, extra_allowed: frozenset = frozenset()) -> EmailDomainCheck:
    """Classify ``email`` as allowed, disposable or invalid. Never raises."""
    domain = extract_email_domain(email)
    if not domain:
        lenient = _lenient_email_domain(email)
        matched = match_disposable_domain(lenient, lists, extra_allowed) if lenient else ""
        if matched:
            return EmailDomainCheck(allowed=False, code=DISPOSABLE_EMAIL_CODE, domain=lenient, matched_domain=matched)
        return EmailDomainCheck(allowed=False, code=INVALID_EMAIL_CODE)
    matched = match_disposable_domain(domain, lists, extra_allowed)
    if matched:
        return EmailDomainCheck(allowed=False, code=DISPOSABLE_EMAIL_CODE, domain=domain, matched_domain=matched)
    return EmailDomainCheck(allowed=True, code=ALLOWED_CODE, domain=domain)


@lru_cache(maxsize=1)
def get_bundled_domain_lists() -> DomainLists:
    return load_domain_lists()


# ---------------------------------------------------------------------------
# Django signup helpers
# ---------------------------------------------------------------------------
# Settings (env-backed in ecp_backend/settings/base.py):
#   DISPOSABLE_EMAIL_VALIDATION_ENABLED  (default True)  Django master switch;
#       does NOT affect the Cognito Pre Sign-up Lambda
#   DISPOSABLE_EMAIL_ALLOWLIST           (default "")    extra allowed domains
#   DISPOSABLE_EMAIL_BLOCK_COGNITO_JIT   (default True)  also refuse to create a
#       local user for a brand-new Cognito identity with a disposable domain


def signup_check_enabled() -> bool:
    from django.conf import settings

    return bool(getattr(settings, "DISPOSABLE_EMAIL_VALIDATION_ENABLED", True))


def check_signup_email(email) -> EmailDomainCheck:
    """
    Check an email for a NEW account. When the feature is switched off, only
    the syntax check still applies.
    """
    if not signup_check_enabled():
        domain = extract_email_domain(email)
        if not domain:
            return EmailDomainCheck(allowed=False, code=INVALID_EMAIL_CODE)
        return EmailDomainCheck(allowed=True, code=ALLOWED_CODE, domain=domain)

    from django.conf import settings

    extra_allowed = parse_domain_csv(getattr(settings, "DISPOSABLE_EMAIL_ALLOWLIST", ()))
    return check_email(email, get_bundled_domain_lists(), extra_allowed)


def is_disposable_signup_email(email) -> bool:
    """True only when ``email`` is well formed and its domain is disposable."""
    return check_signup_email(email).is_disposable


def check_new_participant_email(email) -> EmailDomainCheck:
    """
    Check an email that admits someone without a full signup (guest join,
    event applications). It uses the same rules as signup, so a malformed
    address or a disposable domain is refused. An email that already belongs
    to a registered user is always allowed, matching the signup rule that
    existing accounts keep working.
    """
    result = check_signup_email(email)
    if result.is_disposable:
        from django.contrib.auth import get_user_model

        if get_user_model().objects.filter(email__iexact=str(email).strip()).exists():
            return EmailDomainCheck(allowed=True, code=ALLOWED_CODE, domain=result.domain)
    return result


def validate_signup_email_domain(email) -> None:
    """Raise a Django ValidationError when ``email`` uses a disposable domain."""
    if is_disposable_signup_email(email):
        from django.core.exceptions import ValidationError

        raise ValidationError(DISPOSABLE_EMAIL_MESSAGE, code=DISPOSABLE_EMAIL_CODE)


def blocks_new_cognito_account(email) -> bool:
    """Whether a local user must not be created for a new Cognito identity."""
    from django.conf import settings

    if not getattr(settings, "DISPOSABLE_EMAIL_BLOCK_COGNITO_JIT", True):
        return False
    return is_disposable_signup_email(email)
