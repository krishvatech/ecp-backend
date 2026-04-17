from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    QuestionViewSet,
    QnAReplyViewSet,
    QnAQuestionGroupViewSet,
    QnAQuestionGroupSuggestionViewSet
)
from .export_view import QnAExportView

router = DefaultRouter()
router.register(r'questions', QuestionViewSet, basename='question')
router.register(r'replies', QnAReplyViewSet, basename='qna-reply')
router.register(r'qna-groups/ai-suggestions', QnAQuestionGroupSuggestionViewSet, basename='qna-group-suggestion')
router.register(r'qna-groups', QnAQuestionGroupViewSet, basename='qna-group')

urlpatterns = [
    # Export endpoint — standalone view, listed before router include so it
    # takes priority over any router-generated pattern for this path.
    path('questions/export/', QnAExportView.as_view(), name='qna-export'),
    path('', include(router.urls)),
]
