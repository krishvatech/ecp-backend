from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from wagtail.models import Page
from wagtail.rich_text import RichText


def image_url(image, spec="fill-2000x900"):
    if not image:
        return ""
    try:
        return image.get_rendition(spec).url
    except Exception:
        try:
            return image.file.url
        except Exception:
            return ""


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
            data["hero_image_url"] = image_url(getattr(specific, "hero_background_image", None))
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
                        "image_url": image_url(img, spec="fill-1200x700"),
                    })
            data["features"] = out

        if hasattr(specific, "mission_title"):
            data["mission_title"] = specific.mission_title or ""

        if hasattr(specific, "mission_html"):
            data["mission_html"] = str(RichText(specific.mission_html or ""))

        return Response(data, status=status.HTTP_200_OK)
