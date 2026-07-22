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
from rest_framework.filters import SearchFilter, OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend, FilterSet, CharFilter
from .models import Resource
from django.utils import timezone
from .tasks import publish_resource_task
from .serializers import ResourceSerializer
from events.models import EventRegistration 

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
def _free_accessible_event_ids(user):
    if not user or not user.is_authenticated:
        return set()
    return set(
        EventRegistration.objects.filter(
            user=user,
            status="registered",
            attendee_status="confirmed",
            is_banned=False,
        )
        .filter(
            Q(event__is_free=True) | Q(event__price=0)
        )
        .values_list("event_id", flat=True)
    )


def _paid_accessible_event_ids(user):
    if not user or not user.is_authenticated:
        return set()

    from orders.models import Order
    paid_order_event_ids = Order.objects.filter(
        user=user,
        status="paid",
        paid_at__isnull=False
    ).values_list("items__event_id", flat=True)

    return set(
        EventRegistration.objects.filter(
            user=user,
            status="registered",
            attendee_status="confirmed",
            is_banned=False,
            event_id__in=paid_order_event_ids
        )
        .exclude(
            Q(event__is_free=True) | Q(event__price=0)
        )
        .values_list("event_id", flat=True)
    )


def _accessible_event_ids(user):
    if not user or not user.is_authenticated:
        return set()
    return _free_accessible_event_ids(user).union(_paid_accessible_event_ids(user))


def has_resource_access(user, resource):
    """
    Determine if a user has access to a specific resource.
    Follows all rules for:
    - superuser/staff bypass
    - community resource membership check
    - free event access
    - paid event access
    - soft-deleted/unpublished/archived status
    - uploader or community owner bypass
    """
    if resource.is_deleted:
        return False

    if resource.event_id and resource.event.status == "archived":
        return False

    if not user or not user.is_authenticated:
        return False

    if user.is_superuser or user.is_staff:
        return True

    if resource.uploaded_by_id == user.id or resource.community.owner_id == user.id:
        return True

    if not resource.is_published:
        return False

    if resource.uploaded_by_id:
        try:
            profile_status = getattr(resource.uploaded_by.profile, "profile_status", None)
            if profile_status in ("suspended", "fake", "deceased"):
                return False
        except Exception:
            pass

    if resource.event_id is None:
        # Community-level resource: check if user belongs to the community
        org_ids = set(user.community.values_list("id", flat=True))
        org_ids.update(user.owned_community.values_list("id", flat=True))
        return resource.community_id in org_ids
    else:
        # Event-level resource: check if user has access to this event
        event = resource.event
        is_free = getattr(event, "is_free", False) or getattr(event, "price", None) == 0

        try:
            registration = EventRegistration.objects.get(
                user=user,
                event_id=resource.event_id,
                status="registered",
                attendee_status="confirmed",
                is_banned=False
            )
        except EventRegistration.DoesNotExist:
            return False

        if is_free:
            return True
        else:
            from orders.models import Order
            return Order.objects.filter(
                user=user,
                status="paid",
                paid_at__isnull=False,
                items__event_id=resource.event_id
            ).exists()


class ResourceViewSet(viewsets.ModelViewSet):
    """
    CRUD operations for Resource objects.  On creation the ``uploaded_by`` field
    is automatically assigned.  Non‑staff users can only view published resources
    within their community, and only members/owners can create or modify them.
    """
    serializer_class = ResourceSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ResourceFilter
    search_fields = ['title', 'description', 'tags']
    ordering_fields = ['created_at', 'title']
    ordering = ['-created_at']

    def get_queryset(self):
        user = self.request.user
        qs = (
            Resource.objects
            .select_related("community", "event", "uploaded_by")
            .filter(Q(event__isnull=True) | ~Q(event__status="archived"))
        )

        # Superusers and staff can see all resources
        if user.is_superuser or user.is_staff:
            return qs.order_by("-created_at")

        # Get accessible event IDs using helper logic
        accessible_eids = _accessible_event_ids(user)

        # Community membership org IDs
        org_ids = list(user.community.values_list("id", flat=True))
        org_ids += list(getattr(user, "owned_community", []).values_list("id", flat=True))

        # Show:
        #  - resources uploaded by the user or owned by the community owner
        #  - published community-level resources for communities the user belongs to
        #  - published event-level resources for events the user has access to
        qs = qs.filter(
            Q(uploaded_by=user) |
            Q(community__owner=user) |
            (
                Q(is_published=True) & (
                    Q(event__isnull=True, community_id__in=org_ids) |
                    Q(event_id__in=accessible_eids)
                )
            )
        )

        # Exclude resources from suspended/fake/deceased users
        BLOCKED = ("suspended", "fake", "deceased")
        qs = qs.exclude(uploaded_by__profile__profile_status__in=BLOCKED)

        return qs.order_by("-created_at")



    def perform_create(self, serializer):
        user = self.request.user
        event = serializer.validated_data.get("event")    # <— object or None

        # If event is provided, derive community from it
        if event:
            if not event.community:
                raise PermissionDenied("The selected event does not have a community.")
            org = event.community
        else:
            # Fallback: use explicitly provided community (for backwards compat)
            org = serializer.validated_data.get("community")
            if not org:
                raise PermissionDenied("Either event_id or community_id must be provided.")

        org_id = org.id

        # Permission check: user must be superuser/staff OR member of the community
        if not (
            user.is_staff
            or user.is_superuser
            or user.community.filter(id=org_id).exists()
            or user.owned_community.filter(id=org_id).exists()
        ):
            raise PermissionDenied("You must be a member of the community to upload resources.")

        # Save with derived community and event
        serializer.save(community=org, event=event, uploaded_by=user)

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
        payload = self.request.data
        reason = payload.get("reason", "") if hasattr(payload, "get") else ""
        instance.soft_delete(user=user, reason=reason)
        
    def _maybe_schedule(self, instance: Resource):
        """Schedule a publish job if this is a draft with a future time."""
        if not instance.is_published and instance.publish_at:
            # if already in the past, publish immediately
            if instance.publish_at <= timezone.now():
                publish_resource_task.delay(instance.id)
            else:
                publish_resource_task.apply_async(args=[instance.id], eta=instance.publish_at)

    # def perform_create(self, serializer):
    #     # ... your existing org/event permission checks stay the same ...
    #     super().perform_create(serializer)
    #     instance = serializer.save()
    #     self._maybe_schedule(instance)

    # def perform_update(self, serializer):
    #     instance = self.get_object()
    #     super().perform_update(serializer)
    #     self._maybe_schedule(self.get_object())


# Download endpoint - OUTSIDE the class
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_resource(request, pk):
    """
    Proxy download endpoint that forces file download with proper headers
    """
    try:
        # Get the resource
        resource = Resource.objects.select_related("event", "community").get(
            pk=pk,
        )
        if not has_resource_access(request.user, resource):
            raise Resource.DoesNotExist
        
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
