"""
ViewSets for the content app.

The ``ResourceViewSet`` exposes full CRUD endpoints for resources while
enforcing basic community‑scoped permissions.  Listing operations
support filtering via django‑filters for the resource type, parent
community/event, publication status and tags.  Unauthenticated users
are blocked at the DRF layer, and non‑staff users may only see
published resources belonging to community they belong to.
"""
import requests
from django.db.models import Q
from django.http import HttpResponse
from rest_framework import permissions, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from django_filters.rest_framework import DjangoFilterBackend, FilterSet, CharFilter
from .models import Resource
from django.utils import timezone
from .tasks import publish_resource_task
from .serializers import ResourceSerializer


class ResourceFilter(FilterSet):
    """Filter set for Resource queries."""
    tag = CharFilter(method="filter_tag")

    class Meta:
        model = Resource
        fields = ["type", "community", "event", "is_published"]

    def filter_tag(self, queryset, name, value):
        if value:
            return queryset.filter(tags__contains=[value])
        return queryset


class ResourceViewSet(viewsets.ModelViewSet):
    """
    CRUD operations for Resource objects.  On creation the ``uploaded_by`` field
    is automatically assigned.  Non‑staff users can only view published resources
    within their community, and only members/owners can create or modify them.
    """
    serializer_class = ResourceSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_class = ResourceFilter

    def get_queryset(self):
        user = self.request.user
        qs = Resource.objects.all().select_related("community", "event", "uploaded_by")
        if not (user.is_staff or user.is_superuser):
            qs = qs.filter(is_published=True)
            org_ids = list(user.community.values_list("id", flat=True))
            org_ids += list(getattr(user, "owned_community", []).values_list("id", flat=True))
            qs = qs.filter(Q(community_id__in=org_ids))
        return qs.order_by("-created_at")

    def perform_create(self, serializer):
        user = self.request.user
        org_id = serializer.validated_data["community_id"]
        if not (
            user.is_staff
            or user.is_superuser
            or user.community.filter(id=org_id).exists()
            or user.owned_community.filter(id=org_id).exists()
        ):
            raise PermissionDenied("You must be a member of the community to upload resources.")
        event_id = serializer.validated_data.get("event_id")
        if event_id is not None:
            from events.models import Event
            try:
                event = Event.objects.get(pk=event_id)
            except Event.DoesNotExist:
                raise PermissionDenied("Invalid event ID.")
            if event.community_id != org_id:
                raise PermissionDenied("Event does not belong to the specified community.")
        serializer.save()

    def perform_update(self, serializer):
        user = self.request.user
        instance = self.get_object()
        if not (
            user.is_staff
            or user.is_superuser
            or instance.uploaded_by_id == user.id
            or instance.community.owner_id == user.id
        ):
            raise PermissionDenied("You do not have permission to modify this resource.")
        super().perform_update(serializer)

    def perform_destroy(self, instance):
        user = self.request.user
        if not (
            user.is_staff
            or user.is_superuser
            or instance.uploaded_by_id == user.id
            or instance.community.owner_id == user.id
        ):
            raise PermissionDenied("You do not have permission to delete this resource.")
        instance.delete()
        
    def _maybe_schedule(self, instance: Resource):
        """Schedule a publish job if this is a draft with a future time."""
        if not instance.is_published and instance.publish_at:
            # if already in the past, publish immediately
            if instance.publish_at <= timezone.now():
                publish_resource_task.delay(instance.id)
            else:
                publish_resource_task.apply_async(args=[instance.id], eta=instance.publish_at)

    def perform_create(self, serializer):
        # ... your existing org/event permission checks stay the same ...
        super().perform_create(serializer)
        instance = serializer.save()
        self._maybe_schedule(instance)

    def perform_update(self, serializer):
        instance = self.get_object()
        super().perform_update(serializer)
        self._maybe_schedule(self.get_object())


# Download endpoint - OUTSIDE the class
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_resource(request, pk):
    """
    Proxy download endpoint that forces file download with proper headers
    """
    try:
        # Get the resource
        resource = Resource.objects.get(pk=pk, is_published=True)
        
        # Only files can be downloaded this way
        if resource.type != 'file':
            return HttpResponse("Only file resources can be downloaded", status=400)
        
        # Get the file URL
        file_url = resource.file.url
        
        # Fetch the file from S3
        response = requests.get(file_url, stream=True)
        
        if response.status_code != 200:
            return HttpResponse("Failed to fetch file", status=500)
        
        # Determine content type
        content_type = response.headers.get('content-type', 'application/octet-stream')
        
        # Create response with proper download headers
        file_response = HttpResponse(
            response.content,
            content_type=content_type
        )
        
        # Force download with Content-Disposition header
        filename = f"{resource.title}.pdf"
        file_response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return file_response
        
    except Resource.DoesNotExist:
        return HttpResponse("Resource not found", status=404)
    except Exception as e:
        return HttpResponse(f"Error: {str(e)}", status=500)
