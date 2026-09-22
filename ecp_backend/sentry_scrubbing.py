"""
Sentry event sanitization.

`before_send` / `before_send_transaction` keep the original header filtering
and additionally redact credentials anywhere in the (already serialized) event:
request bodies, cookies, query strings, stack-frame variables, breadcrumbs,
exception messages and extra data.

Three layers, all applied to every event:

1. Key-based: values under credential-like keys (refresh_token, id_token,
   Authorization, the secure-session cookie name, ...) at any depth.
2. Pattern-based: `Bearer <token>`, `refresh_token=...` / `"refresh_token": "..."`
   and `<secure-session cookie>=...` inside any string.
3. Value-based: code handling raw credentials registers them per request via
   `protect_current_request()`. Any string containing a 16-character chunk of a
   registered value is replaced, so even truncated reprs (Sentry trims long
   frame variables) cannot carry a usable fragment of 31+ characters.

This module must stay importable from settings: no Django imports at load time.
"""

import re

REDACTED = "[REDACTED]"
FILTERED = "[Filtered]"

# Existing behavior from settings: these request headers become "[Filtered]".
FILTERED_HEADERS = {"authorization", "cookie", "x-csrftoken", "x-csrf-token"}

_SENSITIVE_KEYS = frozenset({
    "refresh_token", "refreshtoken", "rotated_refresh_token", "stored_refresh",
    "encrypted_refresh_token",
    "id_token", "idtoken", "access_token", "accesstoken", "cognito_access_token",
    "authorization", "http_authorization",
    "cookie", "http_cookie", "set_cookie",
    "secret_hash", "client_secret", "clientsecret",
    "handle",
})
_DEFAULT_SESSION_COOKIE = "__Host-ecp_secure_session"
_CHUNK = 16
_HINT_KEY = "_ecp_sensitive_values"

_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9\-._~+/=]{8,}")
_TOKEN_FIELD_RE = re.compile(
    r"(?i)(\\?[\"']?(?:refresh_token|id_token|access_token|cognito_access_token)\\?[\"']?\s*[:=]\s*\\?[\"']?)"
    r"[^\"'\\&\s,;}]+"
)


def _normalize_key(key):
    return str(key).strip().lower().replace("-", "_")


def _session_cookie_names():
    names = {_DEFAULT_SESSION_COOKIE}
    try:
        from django.conf import settings

        names.add(getattr(settings, "SECURE_AUTH_COOKIE_NAME", _DEFAULT_SESSION_COOKIE))
    except Exception:
        pass
    return {n for n in names if n}


class SensitiveValues:
    """Raw credentials seen while handling one request (never sent anywhere)."""

    def __init__(self):
        self._chunks = set()

    def add(self, value):
        if not isinstance(value, str):
            return
        value = value.strip()
        if len(value) < 8:
            return
        if len(value) <= _CHUNK:
            self._chunks.add(value)
            return
        for start in range(0, len(value) - _CHUNK + 1, _CHUNK):
            self._chunks.add(value[start:start + _CHUNK])

    def found_in(self, text):
        return any(chunk in text for chunk in self._chunks)

    def __repr__(self):
        return f"<SensitiveValues chunks={len(self._chunks)}>"


def protect_current_request():
    """
    Return a per-request SensitiveValues registry and, when Sentry is active,
    attach it to the current isolation scope so every event captured for this
    request is scrubbed of those values. The values are only placed in the
    event `hint`, which Sentry never transmits.
    """
    sensitive = SensitiveValues()
    try:
        import sentry_sdk
    except ImportError:
        return sensitive
    if not sentry_sdk.get_client().is_active():
        return sensitive

    def _attach(event, hint):
        if hint is not None:
            hint[_HINT_KEY] = sensitive
        return event

    sentry_sdk.get_isolation_scope().add_event_processor(_attach)
    return sensitive


def _scrub_string(text, sensitive, cookie_re):
    if sensitive is not None and sensitive.found_in(text):
        return REDACTED
    text = _BEARER_RE.sub(r"\1 " + REDACTED, text)
    text = _TOKEN_FIELD_RE.sub(r"\1" + REDACTED, text)
    text = cookie_re.sub(r"\1=" + REDACTED, text)
    return text


def _scrub(obj, sensitive, sensitive_keys, cookie_re, depth=0):
    if depth > 64:
        return obj
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            value = obj[key]
            if _normalize_key(key) in sensitive_keys:
                if value not in (None, "", FILTERED, REDACTED, [], {}):
                    obj[key] = REDACTED
            else:
                obj[key] = _scrub(value, sensitive, sensitive_keys, cookie_re, depth + 1)
        return obj
    if isinstance(obj, list):
        return [_scrub(item, sensitive, sensitive_keys, cookie_re, depth + 1) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_scrub(item, sensitive, sensitive_keys, cookie_re, depth + 1) for item in obj)
    if isinstance(obj, str):
        return _scrub_string(obj, sensitive, cookie_re)
    return obj


def sanitize_event(event, sensitive=None):
    """Redact credentials in a Sentry event in place and return it."""
    if not isinstance(event, dict):
        return event
    cookie_names = _session_cookie_names()
    sensitive_keys = _SENSITIVE_KEYS | {_normalize_key(n) for n in cookie_names}
    cookie_re = re.compile(
        "(" + "|".join(re.escape(n) for n in sorted(cookie_names)) + r")=[^;\s\"']*"
    )
    return _scrub(event, sensitive, sensitive_keys, cookie_re)


def _filter_headers(event):
    request = event.get("request") or {}
    headers = request.get("headers") or {}
    # Never send auth/session secrets to Sentry.
    for key in list(headers.keys()):
        if key.lower() in FILTERED_HEADERS:
            headers[key] = FILTERED


def before_send(event, hint):
    _filter_headers(event)
    return sanitize_event(event, (hint or {}).get(_HINT_KEY))


def before_send_transaction(event, hint):
    # The Django integration attaches request data (including bodies) to
    # transactions too, and transactions bypass before_send.
    _filter_headers(event)
    return sanitize_event(event, (hint or {}).get(_HINT_KEY))
