"""
ViewSets for the activity_feed app.

Exposes a read‑only endpoint for listing feed items.  Feed items may
be filtered by organization, event and verb via query parameters.  By
default only feed entries belonging to organizations the user is a
member of are returned, unless the user is staff or superuser.
"""
from django.db.models import Q
from rest_framework import permissions, viewsets
from django_filters.rest_framework import DjangoFilterBackend
from .models import FeedItem
from .serializers import FeedItemSerializer

class FeedItemViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read‑only viewset for activity feed items.
    Only authenticated users may access the feed.  Entries can be
    filtered by organization, event and verb.  Non‑staff users will only
    see items associated with organizations they belong to.
    """
    serializer_class = FeedItemSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["organization", "event", "verb"]

    def get_queryset(self):
        user = self.request.user
        qs = FeedItem.objects.all().select_related(
            "organization", "event", "actor", "target_content_type"
        )
        if not (user.is_staff or user.is_superuser):
            org_ids = list(user.organizations.values_list("id", flat=True))
            org_ids += list(getattr(user, "owned_organizations", []).values_list("id", flat=True))
            qs = qs.filter(Q(organization_id__in=org_ids) | Q(event__organization_id__in=org_ids))
        return qs.order_by("-created_at")
