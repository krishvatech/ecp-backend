"""
URL configuration for the realtime app.

These routes are included under the ``/api/`` prefix in the project
level ``urls.py``.  They expose endpoints for generating tokens to
join or broadcast in live event streams.
"""
from django.urls import path

from realtime.views import EventStreamTokenView


urlpatterns = [
    # POST /api/events/<event_id>/token/ → generate short‑lived token
    path("events/<int:event_id>/token/", EventStreamTokenView.as_view(), name="event_stream_token"),
]
