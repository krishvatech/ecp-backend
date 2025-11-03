# activity_feed/urls.py
from rest_framework.routers import DefaultRouter
from .views import FeedItemViewSet

router = DefaultRouter()
router.register(r'feed', FeedItemViewSet, basename='activity-feed')

urlpatterns = router.urls
