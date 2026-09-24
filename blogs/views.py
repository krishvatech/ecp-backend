"""
Blog API views.

Two surfaces, kept apart on purpose:

* ``BlogPostViewSet`` (``/api/blogs/``): read-only, any authenticated user,
  published posts only. Drafts return 404 exactly like missing slugs.
* ``BlogPostAdminViewSet`` and the category/tag viewsets
  (``/api/blogs/admin/...``): Django superusers only. Every superuser can
  manage every post, regardless of ``created_by``.
"""
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.models import Q
from drf_spectacular.utils import OpenApiParameter, extend_schema, extend_schema_view
from rest_framework import mixins, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.filters import SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import BlogCategory, BlogPost, BlogTag
from .permissions import IsSuperuser
from .serializers import (
    BlogAdminSerializer,
    BlogCategorySerializer,
    BlogDetailSerializer,
    BlogListSerializer,
    BlogPublishSerializer,
    BlogTagSerializer,
)

_TERM_FILTER_PARAMS = [
    OpenApiParameter("category", str, description="Category slug or id"),
    OpenApiParameter("tag", str, description="Tag slug or id"),
]


def _filter_by_term(queryset, relation, value):
    value = (value or "").strip()
    if not value:
        return queryset
    match = Q(**{f"{relation}__slug__iexact": value})
    if value.isdigit():
        match |= Q(**{f"{relation}__id": int(value)})
    return queryset.filter(match).distinct()


class BlogPostQuerysetMixin:
    filter_backends = [SearchFilter]
    search_fields = ["title", "excerpt"]

    def base_queryset(self):
        return BlogPost.objects.select_related(
            "author__profile",
        ).prefetch_related("categories", "tags")

    def apply_term_filters(self, queryset):
        params = self.request.query_params
        queryset = _filter_by_term(queryset, "categories", params.get("category"))
        return _filter_by_term(queryset, "tags", params.get("tag"))


@extend_schema_view(list=extend_schema(parameters=_TERM_FILTER_PARAMS))
class BlogPostViewSet(BlogPostQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    """Published blogs for Explore Blogs. Newest published first."""

    permission_classes = [IsAuthenticated]
    lookup_field = "slug"
    lookup_value_regex = r"[-a-zA-Z0-9_]+"

    def get_queryset(self):
        queryset = self.base_queryset().filter(status=BlogPost.STATUS_PUBLISHED)
        if self.action == "list":
            queryset = self.apply_term_filters(queryset)
        return queryset.order_by("-published_at", "-id")

    def get_serializer_class(self):
        return BlogDetailSerializer if self.action == "retrieve" else BlogListSerializer


@extend_schema_view(
    list=extend_schema(
        parameters=_TERM_FILTER_PARAMS
        + [OpenApiParameter("status", str, enum=["draft", "published"])]
    )
)
class BlogPostAdminViewSet(
    BlogPostQuerysetMixin,
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Superuser management of all blogs (drafts included). No DELETE."""

    permission_classes = [IsAuthenticated, IsSuperuser]
    serializer_class = BlogAdminSerializer
    http_method_names = ["get", "post", "patch", "head", "options"]
    lookup_value_regex = r"\d+"

    def get_queryset(self):
        queryset = self.base_queryset().select_related(
            "created_by__profile", "updated_by__profile"
        )
        if self.action == "list":
            status_param = (self.request.query_params.get("status") or "").strip()
            if status_param:
                if status_param not in dict(BlogPost.STATUS_CHOICES):
                    raise ValidationError({"status": "Must be 'draft' or 'published'."})
                queryset = queryset.filter(status=status_param)
            queryset = self.apply_term_filters(queryset)
        return queryset.order_by("-updated_at", "-id")

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user, updated_by=self.request.user)

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    def _transition(self, method_name):
        post = self.get_object()
        try:
            getattr(post, method_name)(user=self.request.user)
        except DjangoValidationError as exc:
            raise ValidationError(exc.message_dict)
        post = self.get_queryset().get(pk=post.pk)
        return Response(self.get_serializer(post).data)

    @extend_schema(request=BlogPublishSerializer, responses=BlogAdminSerializer)
    @action(detail=True, methods=["post"])
    def publish(self, request, pk=None):
        return self._transition("publish")

    @extend_schema(request=BlogPublishSerializer, responses=BlogAdminSerializer)
    @action(detail=True, methods=["post"])
    def unpublish(self, request, pk=None):
        return self._transition("unpublish")


class BlogTermAdminViewSet(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Superuser management of a flat taxonomy. No DELETE, to protect posts."""

    permission_classes = [IsAuthenticated, IsSuperuser]
    http_method_names = ["get", "post", "patch", "head", "options"]
    lookup_value_regex = r"\d+"
    filter_backends = [SearchFilter]
    search_fields = ["name", "slug"]


class BlogCategoryAdminViewSet(BlogTermAdminViewSet):
    queryset = BlogCategory.objects.order_by("name", "id")
    serializer_class = BlogCategorySerializer


class BlogTagAdminViewSet(BlogTermAdminViewSet):
    queryset = BlogTag.objects.order_by("name", "id")
    serializer_class = BlogTagSerializer
