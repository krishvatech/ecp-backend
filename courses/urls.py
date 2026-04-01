from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import MoodleCourseViewSet, image_proxy

router = DefaultRouter()
router.register(r"courses", MoodleCourseViewSet, basename="courses")

# Place the image proxy before router urls so it doesn't get captured as a course {pk}.
urlpatterns = [
    path("courses/image-proxy/", image_proxy, name="course-image-proxy"),
] + router.urls
