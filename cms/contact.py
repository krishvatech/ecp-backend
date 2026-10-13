"""Contact Us enquiries: validated, spam-checked and e-mailed. Nothing is stored.

``POST /api/cms/public/contact/`` (anonymous). Delivery uses the project's e-mail settings: from
``DEFAULT_FROM_EMAIL`` to ``CONTACT_FORM_RECIPIENTS`` (setting or environment variable, comma
separated), reply-to the visitor. Without recipients the form is reported as unavailable
(``enabled: false`` in the page API, 503 here), so it never pretends to accept a message it cannot
deliver.

Spam and abuse protection (no third-party service):
* honeypot field ``website`` must stay empty;
* ``form_token``: signed when the page is rendered; a submission needs one that is at least
  ``MIN_FILL_SECONDS`` and at most ``MAX_TOKEN_AGE`` old;
* per-IP rate limit (``ContactRateThrottle``);
* the same e-mail address and message within ``DUPLICATE_WINDOW`` seconds is accepted once.
Field values are length-limited, stripped of control characters and only ever sent as plain text.
"""

import hashlib
import logging
import os
import re
import time

from django.conf import settings
from django.core import signing
from django.core.cache import cache
from django.core.mail import EmailMessage
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView

from cms.contact_page_content import contact_form_rules

logger = logging.getLogger(__name__)

TOKEN_SALT = "cms.contact.form"
MIN_FILL_SECONDS = 3
MAX_TOKEN_AGE = 6 * 60 * 60
DUPLICATE_WINDOW = 10 * 60
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_PHONE = re.compile(r"^[0-9+()./\s-]{0,40}$")


def contact_recipients():
    value = getattr(settings, "CONTACT_FORM_RECIPIENTS", None)
    if value is None:
        value = os.getenv("CONTACT_FORM_RECIPIENTS", "")
    if isinstance(value, str):
        value = value.split(",")
    return [address.strip() for address in value if address and address.strip()]


def new_form_token(now=None):
    """Signed issue time of the form (checked for tampering, age and minimum fill time)."""
    return signing.dumps({"issued": now if now is not None else time.time()}, salt=TOKEN_SALT)


def contact_form_config():
    """What the page needs to render the form (part of the public ContactPage API response)."""
    rules = contact_form_rules()
    return {"enabled": bool(contact_recipients()), "countries": rules["countries"],
            "max_lengths": rules["max_lengths"], "token": new_form_token()}


def _clean(value):
    return _CONTROL.sub("", value or "").strip()


class ContactRateThrottle(AnonRateThrottle):
    """Per-IP limit for enquiries: CONTACT_FORM_RATE (default 5 per hour)."""

    scope = "contact"
    default_rate = "5/hour"

    def get_rate(self):  # no class-level `rate`, so DRF asks here (and settings overrides apply)
        return getattr(settings, "CONTACT_FORM_RATE", None) or self.default_rate


class ContactSubmissionSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)
    email = serializers.EmailField(max_length=254)
    phone = serializers.CharField(max_length=40, required=False, allow_blank=True, default="")
    country = serializers.CharField(max_length=100)
    message = serializers.CharField(max_length=2000)
    consent = serializers.BooleanField()
    website = serializers.CharField(required=False, allow_blank=True, default="")  # honeypot
    form_token = serializers.CharField(max_length=200)

    def validate(self, data):
        for name in ("first_name", "last_name", "phone", "country", "message"):
            data[name] = _clean(data.get(name, ""))
        errors = {}
        for name in ("first_name", "last_name", "message"):
            if not data[name]:
                errors[name] = "This field is required."
        if data["phone"] and not _PHONE.match(data["phone"]):
            errors["phone"] = "Use digits, spaces and + ( ) - only."
        if data["country"] not in contact_form_rules()["countries"]:
            errors["country"] = "Select your country."
        if data["consent"] is not True:
            errors["consent"] = "Please agree so that we can respond to your enquiry."
        if errors:
            raise serializers.ValidationError(errors)
        return data


class ContactSubmissionView(APIView):
    authentication_classes = []
    permission_classes = []
    throttle_classes = [ContactRateThrottle]

    def post(self, request):
        recipients = contact_recipients()
        if not recipients:
            return Response({"code": "contact_unavailable", "detail": "The contact form is not available."},
                            status=status.HTTP_503_SERVICE_UNAVAILABLE)
        serializer = ContactSubmissionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        if data["website"]:  # a bot filled the hidden field: answer as if it worked, send nothing
            logger.info("contact form: honeypot submission ignored")
            return Response({"status": "sent"})
        try:
            issued = float(signing.loads(data["form_token"], salt=TOKEN_SALT, max_age=MAX_TOKEN_AGE)["issued"])
        except signing.SignatureExpired:
            return Response({"code": "form_expired", "detail": "This form has expired. Reload the page and try again."},
                            status=status.HTTP_400_BAD_REQUEST)
        except (signing.BadSignature, KeyError, TypeError, ValueError):
            return Response({"code": "form_invalid", "detail": "Reload the page and try again."}, status=status.HTTP_400_BAD_REQUEST)
        age = time.time() - issued
        if age > MAX_TOKEN_AGE:
            return Response({"code": "form_expired", "detail": "This form has expired. Reload the page and try again."},
                            status=status.HTTP_400_BAD_REQUEST)
        if age < MIN_FILL_SECONDS:
            return Response({"code": "too_fast", "detail": "Please take a moment and send the form again."},
                            status=status.HTTP_400_BAD_REQUEST)

        fingerprint = hashlib.sha256(f"{data['email'].lower()}|{data['message']}".encode()).hexdigest()
        duplicate_key = f"cms:contact:dup:{fingerprint}"
        if not cache.add(duplicate_key, 1, DUPLICATE_WINDOW):
            return Response({"status": "sent", "duplicate": True})

        name = f"{data['first_name']} {data['last_name']}".replace("\r", " ").replace("\n", " ")
        body = "\n".join([
            "New enquiry from the IMAA website contact form (/contact-us).",
            "",
            f"Name: {name}",
            f"E-mail: {data['email']}",
            f"Phone: {data['phone'] or '-'}",
            f"Country: {data['country']}",
            "Consent to be contacted: yes",
            "",
            "Message:",
            data["message"],
        ])
        message = EmailMessage(subject=f"Website enquiry from {name}"[:200], body=body,
                               from_email=settings.DEFAULT_FROM_EMAIL, to=recipients, reply_to=[data["email"]])
        try:
            message.send(fail_silently=False)
        except Exception:
            cache.delete(duplicate_key)
            logger.exception("contact form: e-mail delivery failed")
            return Response({"code": "delivery_failed", "detail": "Your message could not be sent. Please e-mail us instead."},
                            status=status.HTTP_502_BAD_GATEWAY)
        return Response({"status": "sent"})
