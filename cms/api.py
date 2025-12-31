from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from wagtail.models import Page
from wagtail.rich_text import RichText

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

        if hasattr(specific, "intro"):
            data["intro_html"] = str(RichText(specific.intro or ""))

        if hasattr(specific, "body"):
            data["body_html"] = str(RichText(specific.body or ""))

        return Response(data, status=status.HTTP_200_OK)
