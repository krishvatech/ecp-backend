from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import QuestionViewSet
from .export_view import QnAExportView

router = DefaultRouter()
router.register(r'questions', QuestionViewSet, basename='question')

urlpatterns = [
    # Export endpoint — standalone view, listed before router include so it
    # takes priority over any router-generated pattern for this path.
    path('questions/export/', QnAExportView.as_view(), name='qna-export'),
    path('', include(router.urls)),
]
