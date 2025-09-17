"""
URL patterns for the activity_feed app.

This router registers a read‑only viewset for feed items.  Included
under the ``/api/activity/`` prefix in the project’s root URL config.
"""
from rest_framework.routers import DefaultRouter
from .views import FeedItemViewSet

router = DefaultRouter()
router.register(r"feed", FeedItemViewSet, basename="feed")
urlpatterns = router.urls
