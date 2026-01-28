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
        if not resp.ok:
            print(f"DYTE ERROR: Create Meeting {resp.status_code} - {resp.text}")
        resp.raise_for_status()
        return resp.json().get("data", {}).get("id")
    except Exception as e:
        logger.error(f"Failed to create Dyte meeting: {e}")
        print(f"DYTE EXCEPTION (Create Meeting): {e}")
        return None

def add_dyte_participant(meeting_id, user_id, name, preset_name):
    """
    Add a participant to a Dyte meeting.
    Returns: (auth_token, error_message)
    """
    url = f"{DYTE_API_BASE}/meetings/{meeting_id}/participants"
    payload = {
        "name": name,
        "preset_name": preset_name,
        "custom_participant_id": str(user_id),
    }
    try:
        resp = requests.post(url, headers=_dyte_headers(), json=payload, timeout=10)
        if resp.status_code == 201:
            data = resp.json().get("data", {})
            return data.get("token"), None
        else:
            logger.error(f"Dyte add participant failed: {resp.status_code} - {resp.text}")
            print(f"DYTE ERROR: Add Participant {resp.status_code} - {resp.text}")
            return None, f"Dyte API Error: {resp.status_code}"
    except Exception as e:
        logger.error(f"Dyte add participant exception: {e}")
        print(f"DYTE EXCEPTION: {e}")
        return None, str(e)


# ============================================================
# =================== WebSocket Helpers ======================
# ============================================================
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

def send_speed_networking_message(event_id, msg_type, data):
    """
    Broadcast a message to all users in the event.
    """
    channel_layer = get_channel_layer()
    group_name = f"event_{event_id}"
    
    # We send a message with 'type' matching the consumer method we want to trigger
    # The consumer method then calls send_json to the client.
    # To map 'speed_networking.session_started' to a method name, Channels replaces '.' with '_'
    # So we need a handler called 'speed_networking_session_started' in the consumer.
    
    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            "type": msg_type, 
            "data": data
        }
    )

def send_speed_networking_user_message(user_id, msg_type, data):
    """
    Send a message to a specific user (across all their active connections).
    """
    channel_layer = get_channel_layer()
    group_name = f"user_{user_id}"
    
    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            "type": msg_type, 
            "data": data
        }
    )
