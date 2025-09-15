"""
URL configuration for the realtime app.

These routes are included under the ``/api/`` prefix in the project
level ``urls.py``.  They expose endpoints for generating tokens to
join or broadcast in live event streams.
"""
from django.urls import path

from realtime.views import EventStreamTokenView


urlpatterns = [
    # resolves to /api/events/<pk>/token/ because project urls.py includes realtime under "api/"
    path("events/<int:pk>/token/", EventStreamTokenView.as_view(), name="event-token"),
]