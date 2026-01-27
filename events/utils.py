import os
import requests
import logging

logger = logging.getLogger(__name__)

DYTE_API_BASE = os.getenv("DYTE_API_BASE", "https://api.dyte.io/v2")
DYTE_AUTH_HEADER = os.getenv("DYTE_AUTH_HEADER", "")
DYTE_PRESET_HOST = os.getenv("DYTE_PRESET_NAME_HOST", os.getenv("DYTE_PRESET_NAME", "group_call_host"))
DYTE_PRESET_PARTICIPANT = os.getenv("DYTE_PRESET_NAME_MEMBER", "group_call_participant")

def _dyte_headers():
    """HTTP headers for Dyte REST API."""
    if not DYTE_AUTH_HEADER:
        raise RuntimeError("DYTE_AUTH_HEADER is not configured")
    return {
        "Authorization": DYTE_AUTH_HEADER,
        "Content-Type": "application/json",
    }

def create_dyte_meeting(title):
    """Utility to create a Dyte meeting and return the meeting ID."""
    payload = {
        "title": title,
        "record_on_start": False,
    }
    try:
        resp = requests.post(f"{DYTE_API_BASE}/meetings", headers=_dyte_headers(), json=payload, timeout=10)
        resp.raise_for_status()
        return resp.json().get("data", {}).get("id")
    except Exception as e:
        logger.error(f"Failed to create Dyte meeting: {e}")
        return None
