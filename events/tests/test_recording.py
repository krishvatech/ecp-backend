import pytest
from events.models import Event
from django.conf import settings

@pytest.mark.django_db
def test_recording_webhook_triggers_task(client, organization, auth_client):
    """
    POST to recording webhook should update Event.recording_url (with Celery eager mode).
    """
    # ensure Celery tasks run immediately during tests
    assert settings.CELERY_TASK_ALWAYS_EAGER

    # create an event
    payload = {"organization_id": organization.id, "title": "With Recording", "description": "Test"}
    res = auth_client.post("/api/events/", payload, content_type="application/json")
    event_id = res.json()["id"]

    # call webhook
    rec_url = "http://example.com/recordings/test.mp4"
    resp = client.post("/api/events/recording-webhook/", {"event_id": event_id, "recording_url": rec_url}, content_type="application/json")
    assert resp.status_code == 202

    # check that event.recording_url was set
    updated = Event.objects.get(pk=event_id)
    assert updated.recording_url == rec_url
