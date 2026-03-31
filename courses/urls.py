from rest_framework.routers import DefaultRouter
from .views import MoodleCourseViewSet

router = DefaultRouter()
router.register(r"courses", MoodleCourseViewSet, basename="courses")

urlpatterns = router.urls
