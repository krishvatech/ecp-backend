#!/usr/bin/env python
import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ecp_backend.settings.dev')
django.setup()

from events.models import Event
from events.views import RecordingWebhookView
from rest_framework.test import APIRequestFactory

# Get event 643
event = Event.objects.get(id=643)
print(f"\n{'='*60}")
print(f"Event: {event.title}")
print(f"Meeting ID: {event.rtk_meeting_id}")
print(f"\nBEFORE webhook:")
print(f"  replay_publishing_mode: {event.replay_publishing_mode}")
print(f"  replay_visible_to_participants: {event.replay_visible_to_participants}")
print(f"  recording_url: {event.recording_url}")

# Simulate webhook
factory = APIRequestFactory()
payload = {
    "event": "recording.statusUpdate",  # ✅ REQUIRED!
    "meeting": {"id": event.rtk_meeting_id},
    "recording": {
        "recordingId": "test-123",
        "status": "UPLOADED",
        "output_file_name": "test-recording.mp4",
        "download_url": "https://example.com/recording.mp4",
        "asset_links": {"download": "https://example.com/recording.mp4"}
    }
}

view = RecordingWebhookView.as_view()
request = factory.post('/webhook/rtk-recording/', json.dumps(payload), content_type='application/json')
response = view(request)

print(f"\nWebhook response: {response.status_code}")
if hasattr(response, 'data'):
    print(f"Response data: {response.data}")

# Check after webhook
event.refresh_from_db()
print(f"\nAFTER webhook:")
print(f"  replay_publishing_mode: {event.replay_publishing_mode}")
print(f"  replay_visible_to_participants: {event.replay_visible_to_participants}")
print(f"  recording_url: {event.recording_url}")
print(f"{'='*60}\n")
