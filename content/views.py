"""
ViewSets for the content app.

The ``ResourceViewSet`` exposes full CRUD endpoints for resources while
enforcing basic organization‑scoped permissions.  Listing operations
support filtering via django‑filters for the resource type, parent
organization/event, publication status and tags.  Unauthenticated users
are blocked at the DRF layer, and non‑staff users may only see
published resources belonging to organizations they belong to.
"""
from django.db.models import Q
from rest_framework import permissions, viewsets
from rest_framework.exceptions import PermissionDenied
from django_filters.rest_framework import DjangoFilterBackend, FilterSet, CharFilter
from .models import Resource
from .serializers import ResourceSerializer

class ResourceFilter(FilterSet):
    """Filter set for Resource queries."""
    tag = CharFilter(method="filter_tag")

    class Meta:
        model = Resource
        fields = ["type", "organization", "event", "is_published"]

    def filter_tag(self, queryset, name, value):
        if value:
            return queryset.filter(tags__contains=[value])
        return queryset

class ResourceViewSet(viewsets.ModelViewSet):
    """
    CRUD operations for Resource objects.  On creation the ``uploaded_by`` field
    is automatically assigned.  Non‑staff users can only view published resources
    within their organizations, and only members/owners can create or modify them.
    """
    serializer_class = ResourceSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_class = ResourceFilter

    def get_queryset(self):
        user = self.request.user
        qs = Resource.objects.all().select_related("organization", "event", "uploaded_by")
        if not (user.is_staff or user.is_superuser):
            qs = qs.filter(is_published=True)
            org_ids = list(user.organizations.values_list("id", flat=True))
            org_ids += list(getattr(user, "owned_organizations", []).values_list("id", flat=True))
            qs = qs.filter(Q(organization_id__in=org_ids))
        return qs.order_by("-created_at")

    def perform_create(self, serializer):
        user = self.request.user
        org_id = serializer.validated_data["organization_id"]
        if not (
            user.is_staff
            or user.is_superuser
            or user.organizations.filter(id=org_id).exists()
            or user.owned_organizations.filter(id=org_id).exists()
        ):
            raise PermissionDenied("You must be a member of the organization to upload resources.")
        event_id = serializer.validated_data.get("event_id")
        if event_id is not None:
            from events.models import Event
            try:
                event = Event.objects.get(pk=event_id)
            except Event.DoesNotExist:
                raise PermissionDenied("Invalid event ID.")
            if event.organization_id != org_id:
                raise PermissionDenied("Event does not belong to the specified organization.")
        serializer.save()

    def perform_update(self, serializer):
        user = self.request.user
        instance = self.get_object()
        if not (
            user.is_staff
            or user.is_superuser
            or instance.uploaded_by_id == user.id
            or instance.organization.owner_id == user.id
        ):
            raise PermissionDenied("You do not have permission to modify this resource.")
        super().perform_update(serializer)

    def perform_destroy(self, instance):
        user = self.request.user
        if not (
            user.is_staff
            or user.is_superuser
            or instance.uploaded_by_id == user.id
            or instance.organization.owner_id == user.id
        ):
            raise PermissionDenied("You do not have permission to delete this resource.")
        instance.delete()
