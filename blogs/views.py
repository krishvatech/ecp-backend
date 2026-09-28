"""
Blog API views.

Two surfaces, kept apart on purpose:

* ``BlogPostViewSet`` (``/api/blogs/``): read-only, any authenticated user,
  published posts only. Drafts return 404 exactly like missing slugs.
  ``<slug>/?content_mode=chunked`` + ``<slug>/content/?chunk=N`` let the
  reader lazy-load a long article in chunks (see blogs.content_chunks).
* ``BlogPostAdminViewSet`` and the category/tag viewsets
  (``/api/blogs/admin/...``): Django superusers only. Every superuser can
  manage every post, regardless of ``created_by``.
"""
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.models import Q
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.filters import SearchFilter
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .content_chunks import content_chunks
from .models import BlogCategory, BlogImportRun, BlogPost, BlogTag
from .permissions import IsSuperuser
from .serializers import (
    BlogAdminSerializer,
    BlogCategorySerializer,
    BlogDetailSerializer,
    BlogImportRunSerializer,
    BlogImportStartSerializer,
    BlogListSerializer,
    BlogPublishSerializer,
    BlogTagSerializer,
)

_TERM_FILTER_PARAMS = [
    OpenApiParameter("category", str, description="Category slug or id"),
    OpenApiParameter("tag", str, description="Tag slug or id"),
]


class BlogPagination(PageNumberPagination):
    """Blog post lists: the site default size, but clients may ask for a
    different page size (the card grids use 9), capped."""

    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 50


# Reader order: newest published first, id as a deterministic tie-break.
READER_ORDERING = ("-published_at", "-id")
CONTENT_MODE_CHUNKED = "chunked"

_PAGE_PARAMS = [OpenApiParameter("page_size", int, description="Posts per page (max 50, default 20)")]


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


@extend_schema_view(list=extend_schema(parameters=_TERM_FILTER_PARAMS + _PAGE_PARAMS))
class BlogPostViewSet(BlogPostQuerysetMixin, viewsets.ReadOnlyModelViewSet):
    """Published blogs for Explore Blogs. Newest published first."""

    permission_classes = [IsAuthenticated]
    pagination_class = BlogPagination
    lookup_field = "slug"
    lookup_value_regex = r"[-a-zA-Z0-9_]+"

    def get_queryset(self):
        queryset = self.base_queryset().filter(status=BlogPost.STATUS_PUBLISHED)
        if self.action == "list":
            queryset = self.apply_term_filters(queryset)
        return queryset.order_by(*READER_ORDERING)

    def get_serializer_class(self):
        return BlogListSerializer if self.action == "list" else BlogDetailSerializer

    @extend_schema(
        parameters=[OpenApiParameter(
            "content_mode", str, enum=[CONTENT_MODE_CHUNKED],
            description="`chunked`: content_html holds only the first chunk; "
                        "fetch the rest from content/?chunk=N.",
        )],
    )
    def retrieve(self, request, *args, **kwargs):
        post = self.get_object()  # published only: drafts and unknown slugs are 404
        data = self.get_serializer(post).data
        if request.query_params.get("content_mode") == CONTENT_MODE_CHUNKED:
            chunks = content_chunks(post.content_html)
            data["content_html"] = chunks[0]
            data["content_chunk"] = 1
            data["content_chunks"] = len(chunks)
            data["content_has_more"] = len(chunks) > 1
        return Response(data)

    @extend_schema(
        parameters=[OpenApiParameter("chunk", int, required=True, description="1-based chunk number")],
        responses={
            200: OpenApiResponse(description="{chunk, content_html, has_more, chunks}"),
            400: OpenApiResponse(description="chunk is missing or not a positive integer."),
            404: OpenApiResponse(description="Unknown/unpublished slug or chunk out of range."),
        },
    )
    @action(detail=True, methods=["get"])
    def content(self, request, slug=None):
        """One chunk of a published article's HTML (lazy loading)."""
        post = self.get_object()  # published only
        raw = request.query_params.get("chunk", "")
        if not raw.isdigit() or int(raw) < 1:
            raise ValidationError({"chunk": "Must be a positive integer."})
        number = int(raw)
        chunks = content_chunks(post.content_html)
        if number > len(chunks):
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response({
            "chunk": number,
            "content_html": chunks[number - 1],
            "has_more": number < len(chunks),
            "chunks": len(chunks),
        })


@extend_schema_view(
    list=extend_schema(
        parameters=_TERM_FILTER_PARAMS
        + [OpenApiParameter("status", str, enum=["draft", "published"])]
        + _PAGE_PARAMS
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
    pagination_class = BlogPagination
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


def _enqueue_wordpress_import(run):
    from .tasks import run_wordpress_blog_import

    return run_wordpress_blog_import.delay(str(run.pk)).id


class BlogWordPressImportViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Superuser-only WordPress Blog import: start (async), status, history."""

    permission_classes = [IsAuthenticated, IsSuperuser]
    serializer_class = BlogImportRunSerializer
    lookup_value_regex = r"[0-9a-fA-F-]{36}"
    pagination_class = None
    enqueue = staticmethod(_enqueue_wordpress_import)

    def get_queryset(self):
        queryset = BlogImportRun.objects.select_related("requested_by__profile").order_by("-created_at")
        if self.action == "list":
            try:
                limit = max(1, min(int(self.request.query_params.get("limit", 10)), 50))
            except ValueError:
                limit = 10
            return queryset[:limit]
        return queryset

    @extend_schema(
        request=BlogImportStartSerializer,
        responses={
            202: BlogImportRunSerializer,
            409: OpenApiResponse(description="An import is already running; body contains `active_run`."),
            503: OpenApiResponse(description="Import not configured or could not be queued."),
        },
    )
    def create(self, request, *args, **kwargs):
        from .wordpress.sync import ImportAlreadyRunning, ImportNotConfigured, start_wordpress_import

        try:
            run = start_wordpress_import(request.user, enqueue=self.enqueue)
        except ImportAlreadyRunning as exc:
            return Response(
                {
                    "detail": "An import is already running.",
                    "active_run": BlogImportRunSerializer(exc.run, context={"request": request}).data if exc.run else None,
                },
                status=status.HTTP_409_CONFLICT,
            )
        except ImportNotConfigured as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        run.refresh_from_db()
        data = BlogImportRunSerializer(run, context={"request": request}).data
        data["message"] = "WordPress Blog import queued."
        return Response(data, status=status.HTTP_202_ACCEPTED)

    @extend_schema(responses={200: BlogImportRunSerializer, 404: OpenApiResponse(description="No imports yet.")})
    @action(detail=False, methods=["get"])
    def latest(self, request):
        run = self.get_queryset().first()
        if run is None:
            return Response({"detail": "No WordPress imports yet."}, status=status.HTTP_404_NOT_FOUND)
        return Response(self.get_serializer(run).data)
