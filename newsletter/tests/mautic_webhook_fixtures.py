"""Mautic 7.1.3 webhook payloads, trimmed from real local deliveries.

Captured 2026-10-15 from a local Mautic 7.1.3 (Webhook-Signature header,
one event per request in immediate queue mode). Values are synthetic; the
nesting, key names and value types are Mautic's own, including the fields the
receiver must not store (content, IP address, user agent, contact fields).
"""

import base64
import hashlib
import hmac
import json


def sign(body: bytes, secret: str) -> str:
    """Mautic's signature: base64(HMAC-SHA256(raw JSON body, secret))."""
    return base64.b64encode(hmac.new(secret.encode(), body, hashlib.sha256).digest()).decode()


def encode(payload: dict) -> bytes:
    # Mautic sends compact JSON with escaped slashes; the receiver signs and
    # parses the bytes as received, so any valid JSON encoding is equivalent.
    return json.dumps(payload).encode("utf-8")


def _lead(contact_id, email):
    return {
        "id": int(contact_id),
        "points": 0,
        "color": None,
        "fields": {
            "core": {"email": {"id": "6", "alias": "email", "type": "email", "value": email}},
        },
    }


def _email_ref(email_id):
    return {"id": int(email_id), "name": f"B15 capture {email_id}", "subject": f"B15 capture {email_id}"}


def email_on_send(*, email_id=100, contact_id=4288, email="b15@example.test",
                  id_hash="6ad06ee1871c6027239578", timestamp="2026-10-15T06:12:49+00:00"):
    return {"mautic.email_on_send": [{
        "email": {**_email_ref(email_id), "isPublished": True, "emailType": "template",
                  "customHtml": "<html><body><p>B15 local capture</p></body></html>"},
        "contact": {"id": str(contact_id), "firstname": "B15", "lastname": None,
                    "email": email, "ecp_newsletter_opt_in": None},
        "contentHash": "0a1b2c3d4e5f",
        "idHash": id_hash,
        "subject": f"B15 capture {email_id}",
        "source": ["api", 0],
        "headers": {"List-Unsubscribe": "<https://mautic.example.test/email/unsubscribe/x>"},
        "content": "<html><body><p>B15 local capture</p></body></html>",
        "tokens": {"{unsubscribe_url}": "https://mautic.example.test/email/unsubscribe/x"},
        "timestamp": timestamp,
    }]}


def email_on_open(*, email_id=100, contact_id=4288, email="b15@example.test", stat_id=110,
                  open_count=1, timestamp="2026-10-15T06:14:40+00:00"):
    return {"mautic.email_on_open": [{
        "stat": {
            "id": stat_id,
            "emailAddress": email,
            "ipAddress": {"ipAddress": "203.0.113.7"},
            "dateSent": "2026-10-15T06:12:49+00:00",
            "isRead": True,
            "isFailed": False,
            "dateRead": timestamp,
            "retryCount": 0,
            "source": "api",
            "openCount": open_count,
            "lastOpened": timestamp,
            "sourceId": 0,
            "trackingHash": "6ad06ee1871c6027239578",
            "viewedInBrowser": False,
            "lead": _lead(contact_id, email),
            "email": _email_ref(email_id),
        },
        "timestamp": timestamp,
    }]}


def page_on_hit(*, email_id=100, contact_id=4288, email="b15@example.test", hit_id=1,
                url="https://example.test/b15-link?x=1", timestamp="2026-10-15T06:14:41+00:00"):
    return {"mautic.page_on_hit": [{
        "hit": {
            "id": hit_id,
            "dateHit": timestamp,
            "page": None,
            "redirect": {"id": 3, "url": url},
            "email": _email_ref(email_id),
            "lead": _lead(contact_id, email),
            "ipAddress": {"ipAddress": "203.0.113.7"},
            "country": "", "region": "", "city": "", "isp": "", "organization": "",
            "code": 200,
            "referer": None,
            "url": url,
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "trackingId": "00yrkdw2hczvs66l0bgqraf",
            "source": "email",
            "sourceId": int(email_id),
            "query": {"ct": {"email": str(email_id), "lead": str(contact_id)}, "page_url": url},
        },
        "timestamp": timestamp,
    }]}


def channel_subscription_changed(*, contact_id=4288, email="b15@example.test", old_status="contactable",
                                 new_status="unsubscribed", timestamp="2026-10-15T06:13:10+00:00",
                                 channel="email"):
    dnc = [] if new_status == "contactable" else [
        {"id": 455, "reason": {"unsubscribed": 1, "bounced": 2, "manual": 3}.get(new_status, 3),
         "comments": "B15 capture", "channel": channel, "channelId": None},
    ]
    event = {
        "contact": {
            "isPublished": True,
            "id": int(contact_id),
            "points": 0,
            "fields": {
                "core": {"email": {"alias": "email", "type": "email", "value": email}},
                "personal": {}, "social": {}, "professional": {},
            },
            "ipAddresses": [],
            "doNotContact": dnc,
        },
        "channel": channel,
        "old_status": old_status,
        "new_status": new_status,
    }
    if timestamp is not None:
        event["timestamp"] = timestamp
    return {"mautic.lead_channel_subscription_changed": [event]}
