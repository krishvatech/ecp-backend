"""Anonymous, read-only article sections of the public website: In The News and M&A Publications.

The articles are BlogPost rows imported from the WordPress categories ``news`` and
``publications``. They are public website content, not member Blogs:

* ``GET /api/blogs/public/<section>/`` (newest first, paginated) and
  ``GET /api/blogs/public/<section>/<slug>/`` serve only published posts of that section's
  category that are not members-only, to anonymous visitors;
* the member Blogs (``BlogPostViewSet``) leave these categories out (``PUBLIC_SECTION_CATEGORY_SLUGS``).

The list accepts ``?tag=<tag slug>`` and ``?year=<YYYY>`` (publication year) and adds ``filters`` to the
paginated response: the section's years and its tags used by at least ``MIN_TAG_POSTS`` posts, each with
a count (always for the whole section, so the options do not disappear while a filter is active). The
detail's ``content_html`` passes the Blog importer's allowlist sanitiser (nh3) again, because the public
website renders it on the server.
"""

from django.conf import settings
from django.db.models import Count
from django.db.models.functions import ExtractYear
from django.http import Http404
from rest_framework import viewsets
from rest_framework.pagination import PageNumberPagination
from rest_framework.throttling import ScopedRateThrottle

from blogs.models import BlogPost
from blogs.serializers import BlogDetailSerializer, BlogListSerializer
from blogs.wordpress.normalizer import sanitize_html

# Public section (URL segment) -> WordPress/ECP category slug.
PUBLIC_SECTIONS = {"in-the-news": "news", "publications": "publications"}


def public_section_category_slugs():
    """Categories that belong to the public website sections, not to the member Blogs."""
    configured = getattr(settings, "PUBLIC_SECTION_CATEGORY_SLUGS", None)
    return tuple(configured) if configured is not None else tuple(PUBLIC_SECTIONS.values())


MIN_TAG_POSTS = 3
MAX_FILTER_TAGS = 30


class PublicSectionDetailSerializer(BlogDetailSerializer):
    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["content_html"] = sanitize_html(data.get("content_html") or "")
        return data


class PublicSectionPagination(PageNumberPagination):
    page_size = 9
    page_size_query_param = "page_size"
    max_page_size = 24


class PublicSectionPostViewSet(viewsets.ReadOnlyModelViewSet):
    authentication_classes = []
    permission_classes = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "cms_public"
    pagination_class = PublicSectionPagination
    lookup_field = "slug"

    def section_posts(self):
        category = PUBLIC_SECTIONS.get(self.kwargs.get("section"))
        if category is None:
            raise Http404("Unknown section.")
        return BlogPost.objects.filter(status=BlogPost.STATUS_PUBLISHED, wp_membership_restricted=False, categories__slug=category)

    def get_queryset(self):
        queryset = self.section_posts()
        if self.action == "list":
            tag = self.request.query_params.get("tag", "").strip()
            if tag:
                queryset = queryset.filter(tags__slug=tag)
            year = self.request.query_params.get("year", "").strip()
            if year:
                if not (year.isdigit() and len(year) == 4):
                    raise Http404("Unknown year.")
                queryset = queryset.filter(published_at__year=int(year))
        return (queryset.select_related("author").prefetch_related("categories", "tags")
                .order_by("-published_at", "-id").distinct())

    def get_serializer_class(self):
        return PublicSectionDetailSerializer if self.action == "retrieve" else BlogListSerializer

    def filter_options(self):
        ids = self.section_posts().values("id")
        years = (BlogPost.objects.filter(id__in=ids, published_at__isnull=False)
                 .annotate(year=ExtractYear("published_at")).values("year").annotate(count=Count("id")).order_by("-year"))
        tags = (BlogPost.tags.through.objects.filter(blogpost_id__in=ids)
                .values("blogtag__slug", "blogtag__name").annotate(count=Count("blogpost_id", distinct=True))
                .filter(count__gte=MIN_TAG_POSTS).order_by("-count", "blogtag__name")[:MAX_FILTER_TAGS])
        return {
            "years": [{"year": row["year"], "count": row["count"]} for row in years],
            "tags": [{"slug": row["blogtag__slug"], "name": row["blogtag__name"], "count": row["count"]} for row in tags],
        }

    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        response.data["filters"] = self.filter_options()
        return response
