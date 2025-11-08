from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CommentViewSet, ReactionViewSet, ShareViewSet, EngagementMetricsView

router = DefaultRouter()
router.register(r'comments', CommentViewSet, basename='comment')
router.register(r'reactions', ReactionViewSet, basename='reaction')
router.register(r'shares', ShareViewSet, basename='share')

urlpatterns = [
    path('metrics/', EngagementMetricsView.as_view(), name='engagements-metrics'),
    path('', include(router.urls)),
]
