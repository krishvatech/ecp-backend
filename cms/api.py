from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from wagtail.models import Page
from wagtail.rich_text import RichText


def image_url(request, image, spec="fill-2000x900"):
    if not image:
        return ""
    try:
        url = image.get_rendition(spec).url
    except Exception:
        try:
            url = image.file.url
        except Exception:
            return ""
    if not url:
        return ""
    if url.startswith("http://") or url.startswith("https://"):
        return url
    if request:
        return request.build_absolute_uri(url)
    return url


class CmsPageBySlugView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request, slug):
        page = Page.objects.live().public().filter(slug=slug).first()
        if not page:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)

        specific = page.specific

        data = {
            "id": page.id,
            "title": page.title,
            "slug": page.slug,
            "type": specific.__class__.__name__,
        }

        # HomePage
        if hasattr(specific, "intro"):
            data["intro_html"] = str(RichText(specific.intro or ""))

        # StandardPage
        if hasattr(specific, "body"):
            data["body_html"] = str(RichText(specific.body or ""))

        # AboutPage (New)
        if hasattr(specific, "hero_title"):
            data["hero_title"] = specific.hero_title or ""
            data["hero_subtitle"] = specific.hero_subtitle or ""
            data["hero_image_url"] = image_url(request, getattr(specific, "hero_background_image", None))
            if hasattr(specific, "cta_primary_label"):
                data["cta_buttons"] = [
                    {
                        "key": "primary",
                        "label": specific.cta_primary_label or "",
                        "url": specific.cta_primary_url or "",
                    },
                    {
                        "key": "secondary",
                        "label": specific.cta_secondary_label or "",
                        "url": specific.cta_secondary_url or "",
                    },
                    {
                        "key": "tertiary",
                        "label": specific.cta_tertiary_label or "",
                        "url": specific.cta_tertiary_url or "",
                    },
                ]
            if hasattr(specific, "hero_cta_label"):
                data["hero_cta_label"] = specific.hero_cta_label or ""
                data["hero_cta_url"] = specific.hero_cta_url or ""
            if hasattr(specific, "search_placeholder"):
                data["search_placeholder"] = specific.search_placeholder or ""
            if hasattr(specific, "featured_events_title"):
                data["featured_events_title"] = specific.featured_events_title or ""
            if hasattr(specific, "featured_events"):
                featured_out = []
                for block in specific.featured_events:
                    if block.block_type == "featured_event":
                        v = block.value
                        img = v.get("image")
                        featured_out.append({
                            "title": v.get("title", ""),
                            "desc": v.get("desc", ""),
                            "image_url": image_url(request, img, spec="fill-1200x700"),
                            "link_url": v.get("link_url", ""),
                        })
                data["featured_events"] = featured_out
            if hasattr(specific, "community_title"):
                data["community_title"] = specific.community_title or ""
            if hasattr(specific, "community_cards"):
                community_out = []
                for block in specific.community_cards:
                    if block.block_type == "community_card":
                        v = block.value
                        img = v.get("image")
                        community_out.append({
                            "title": v.get("title", ""),
                            "desc": v.get("desc", ""),
                            "image_url": image_url(request, img, spec="fill-1200x700"),
                            "link_url": v.get("link_url", ""),
                        })
                data["community_cards"] = community_out
            if hasattr(specific, "newsletter_title"):
                data["newsletter_title"] = specific.newsletter_title or ""
            if hasattr(specific, "newsletter_subtitle"):
                data["newsletter_subtitle"] = specific.newsletter_subtitle or ""
            if hasattr(specific, "newsletter_email_placeholder"):
                data["newsletter_email_placeholder"] = specific.newsletter_email_placeholder or ""
            if hasattr(specific, "newsletter_button_label"):
                data["newsletter_button_label"] = specific.newsletter_button_label or ""

        if hasattr(specific, "intro_html"):
            data["intro_html"] = str(RichText(specific.intro_html or ""))

        if hasattr(specific, "features_title"):
            data["features_title"] = specific.features_title or ""

        if hasattr(specific, "features"):
            out = []
            for block in specific.features:
                if block.block_type == "feature":
                    v = block.value
                    img = v.get("image")
                    out.append({
                        "title": v.get("title", ""),
                        "desc": v.get("desc", ""),
                        "image_url": image_url(request, img, spec="fill-1200x700"),
                    })
            data["features"] = out

        if hasattr(specific, "mission_title"):
            data["mission_title"] = specific.mission_title or ""

        if hasattr(specific, "mission_html"):
            data["mission_html"] = str(RichText(specific.mission_html or ""))

        return Response(data, status=status.HTTP_200_OK)
