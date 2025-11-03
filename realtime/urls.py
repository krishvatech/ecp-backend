from django.urls import path
from .views import EventRtcTokenView, AgoraDiagnosticView

urlpatterns = [
    path("rtc/events/<int:event_id>/token/", EventRtcTokenView.as_view(), name="rtc-token"),
    path("agora/diag/", AgoraDiagnosticView.as_view(), name="agora-diag"),
]
