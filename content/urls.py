"""
URL patterns for the content app.

This module defines a DRF router for the ResourceViewSet.  The router
generates standard RESTful routes such as ``/resources/`` and
``/resources/<id>/``.  Included under the ``/api/content/`` prefix.
"""
from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import ResourceViewSet, download_resource  # Add download_resource import

router = DefaultRouter()
router.register(r'resources', ResourceViewSet, basename='resource')

urlpatterns = router.urls + [
    path('resources/<int:pk>/download/', download_resource, name='resource-download'),
]