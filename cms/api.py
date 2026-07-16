import shutil
import subprocess
import tempfile
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.template import Context, Template as DjangoTemplate, TemplateSyntaxError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, serializers
from rest_framework.permissions import IsAuthenticated

from wagtail.models import Page
from wagtail.rich_text import RichText

from cms.email_template_registry import get_template_metadata
from cms.models import EmailTemplate, TEMPLATE_KEY_CHOICES
from cms.serializers import (
    EmailTemplatePreviewSerializer,
    EmailTemplateSendTestSerializer,
    EmailTemplateSerializer,
)
from users.email_utils import send_platform_email


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


def is_cms_page_deleted(page):
    """Return True when a Wagtail CMS page has been archived/soft-deleted."""
    specific = page.specific
    return bool(getattr(specific, "cms_is_deleted", False))


class CmsPageBySlugView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request, slug):
        page = Page.objects.live().public().filter(slug=slug).first()
        if not page:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)

        specific = page.specific
        if getattr(specific, "cms_is_deleted", False):
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)

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

        if hasattr(specific, "left_column"):
            data["left_column"] = [
                block.value for block in specific.left_column if block.block_type == "section"
            ]
        if hasattr(specific, "right_column"):
            data["right_column"] = [
                block.value for block in specific.right_column if block.block_type == "section"
            ]

        return Response(data, status=status.HTTP_200_OK)


class ProfileLayoutView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        # Find the first ProfileLayoutPage (it's a singleton)
        from .models import ProfileLayoutPage
        page = ProfileLayoutPage.objects.live().public().filter(cms_is_deleted=False).first()
        if not page:
            return Response({"detail": "Profile Layout not configured"}, status=status.HTTP_404_NOT_FOUND)

        specific = page
        data = {
            "id": page.id,
            "title": page.title,
            "slug": page.slug,
            "left_column": [
                block.value for block in specific.left_column if block.block_type == "section"
            ],
            "right_column": [
                block.value for block in specific.right_column if block.block_type == "section"
            ],
        }
        return Response(data, status=status.HTTP_200_OK)


VALID_TEMPLATE_KEYS = {key for key, _label in TEMPLATE_KEY_CHOICES}


def is_admin_user(user):
    return bool(user and user.is_authenticated and (user.is_staff or user.is_superuser))


def is_platform_admin(user):
    return bool(user and user.is_authenticated and user.is_superuser)


def read_email_template_file(template_key, extension):
    path = Path(settings.BASE_DIR) / "templates" / "emails" / f"{template_key}.{extension}"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def get_file_defaults(template_key):
    metadata = get_template_metadata(template_key)
    return {
        "subject": metadata["default_subject"] if metadata else f"[{template_key}]",
        "html_body": read_email_template_file(template_key, "html"),
        "text_body": read_email_template_file(template_key, "txt"),
    }


def compile_mjml(mjml_body):
    if not mjml_body:
        return ""

    compiler_errors = []

    def _coerce_compiled_result_to_html(result):
        if result is None:
            return ""
        if isinstance(result, str):
            return result
        if isinstance(result, (bytes, bytearray)):
            return bytes(result).decode("utf-8", errors="replace")
        if isinstance(result, dict):
            errors = result.get("errors")
            if errors:
                raise RuntimeError(errors)
            return result.get("html") or result.get("content") or ""
        if isinstance(result, tuple):
            return _coerce_compiled_result_to_html(result[0])

        for attr in ("html", "content"):
            if hasattr(result, attr):
                value = getattr(result, attr)
                if callable(value):
                    value = value()
                if isinstance(value, str):
                    return value
                if isinstance(value, (bytes, bytearray)):
                    return bytes(value).decode("utf-8", errors="replace")

        if hasattr(result, "errors"):
            errors = getattr(result, "errors")
            if callable(errors):
                errors = errors()
            if errors:
                raise RuntimeError(errors)

        # Avoid returning an opaque object repr like "<builtins.Output object at ...>".
        raise RuntimeError(f"Unsupported MJML compiler output type: {type(result)}")

    try:
        import mrml
    except ImportError as exc:
        compiler_errors.append(str(exc))
        try:
            import mrml_python as mrml
        except ImportError as mrml_python_exc:
            compiler_errors.append(str(mrml_python_exc))
            mrml = None

    if mrml is not None:
        try:
            if hasattr(mrml, "to_html"):
                result = mrml.to_html(mjml_body)
            elif hasattr(mrml, "mjml_to_html"):
                result = mrml.mjml_to_html(mjml_body)
            else:
                raise RuntimeError("No supported MJML compile function found.")

            return _coerce_compiled_result_to_html(result)
        except serializers.ValidationError:
            raise
        except Exception as exc:
            raise serializers.ValidationError({"mjml_body": f"MJML compilation failed: {exc}"}) from exc

    mjml_cli = shutil.which("mjml")
    if mjml_cli:
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".mjml", delete=True) as tmp:
                tmp.write(mjml_body)
                tmp.flush()
                result = subprocess.run(
                    [mjml_cli, tmp.name, "-s"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
        except subprocess.TimeoutExpired as exc:
            raise serializers.ValidationError({"mjml_body": "MJML compilation timed out."}) from exc

        if result.returncode == 0 and result.stdout:
            return result.stdout

        error = result.stderr.strip() or result.stdout.strip() or "Unknown MJML CLI error."
        raise serializers.ValidationError({"mjml_body": f"MJML compilation failed: {error}"})

    raise serializers.ValidationError({
        "mjml_body": (
            "MJML compiler is not installed. Install the Python package `mrml` (recommended), "
            "or make the Node MJML CLI available on PATH (e.g. `npm install -g mjml`). "
            "If you're using the provided Docker image, rebuild it so the bundled MJML CLI is installed."
        )
    })


def validate_template_syntax(subject, html_body, text_body):
    errors = {}
    for field, value in (("subject", subject), ("html_body", html_body), ("text_body", text_body)):
        if value is None:
            continue
        try:
            DjangoTemplate(value)
        except TemplateSyntaxError as exc:
            errors[field] = f"Invalid Django template syntax: {exc}"
    if errors:
        raise serializers.ValidationError(errors)


def validate_required_placeholders(template_key, html_body, mjml_body="", text_body=""):
    metadata = get_template_metadata(template_key) or {}
    required = metadata.get("required_placeholders", [])
    searchable = f"{mjml_body or ''}\n{html_body or ''}\n{text_body or ''}"
    missing = [placeholder for placeholder in required if placeholder not in searchable]
    if missing:
        raise serializers.ValidationError({
            "html_body": f"Missing required placeholders: {', '.join(missing)}"
        })


def render_template_parts(subject, html_body, text_body, context):
    validate_template_syntax(subject, html_body, text_body)
    ctx = Context(context)
    return {
        "rendered_subject": DjangoTemplate(subject).render(ctx),
        "rendered_html": DjangoTemplate(html_body or "").render(ctx),
        "rendered_text": DjangoTemplate(text_body or "").render(ctx),
    }


def get_email_template_payload(template_key):
    metadata = get_template_metadata(template_key)
    if not metadata:
        return None

    obj = EmailTemplate.objects.filter(template_key=template_key).select_related("updated_by").first()
    if obj:
        source = "db"
        template_status = "active" if obj.is_active else "inactive"
        payload = {
            "template_key": template_key,
            "label": metadata["label"],
            "category": metadata["category"],
            "subject": obj.subject,
            "html_body": obj.html_body,
            "text_body": obj.text_body,
            "editor_json": obj.editor_json,
            "mjml_body": obj.mjml_body,
            "editor_type": obj.editor_type,
            "is_active": obj.is_active,
            "notes": obj.notes,
            "last_updated": obj.last_updated,
            "created_at": obj.created_at,
            "updated_by_name": obj.updated_by.get_full_name() or obj.updated_by.email if obj.updated_by else None,
            "source": source,
            "status": template_status,
        }
    else:
        defaults = get_file_defaults(template_key)
        payload = {
            "template_key": template_key,
            "label": metadata["label"],
            "category": metadata["category"],
            "subject": defaults["subject"],
            "html_body": defaults["html_body"],
            "text_body": defaults["text_body"],
            "editor_json": None,
            "mjml_body": "",
            "editor_type": "templatical",
            "is_active": True,
            "notes": "",
            "last_updated": None,
            "created_at": None,
            "updated_by_name": None,
            "source": "file_default",
            "status": "file_default",
        }

    payload["merge_tags"] = metadata["merge_tags"]
    payload["required_placeholders"] = metadata["required_placeholders"]
    return payload


class EmailTemplateListView(APIView):
    permission_classes = [IsAuthenticated]
    pagination_class = None

    def get(self, request):
        if not is_admin_user(request.user):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        data = [get_email_template_payload(key) for key, _label in TEMPLATE_KEY_CHOICES]
        return Response(EmailTemplateSerializer(data, many=True).data)


class EmailTemplateDetailView(APIView):
    permission_classes = [IsAuthenticated]
    pagination_class = None

    def get(self, request, template_key):
        if not is_admin_user(request.user):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        payload = get_email_template_payload(template_key)
        if not payload:
            return Response({"detail": "Template not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(EmailTemplateSerializer(payload).data)

    def patch(self, request, template_key):
        if not is_platform_admin(request.user):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        if template_key not in VALID_TEMPLATE_KEYS:
            return Response({"detail": "Template not found."}, status=status.HTTP_404_NOT_FOUND)

        current = get_email_template_payload(template_key)
        incoming = dict(request.data)
        subject = incoming.get("subject", current["subject"])
        html_body = incoming.get("html_body", current["html_body"])
        text_body = incoming.get("text_body", current["text_body"])
        mjml_body = incoming.get("mjml_body", current["mjml_body"])

        if "mjml_body" in incoming and mjml_body:
            html_body = compile_mjml(mjml_body)

        serializer = EmailTemplateSerializer(data={
            **current,
            **incoming,
            "subject": subject,
            "html_body": html_body,
            "text_body": text_body,
            "mjml_body": mjml_body,
        }, partial=True)
        serializer.is_valid(raise_exception=True)
        validate_template_syntax(subject, html_body, text_body)
        validate_required_placeholders(template_key, html_body, mjml_body, text_body)

        obj, _created = EmailTemplate.objects.get_or_create(
            template_key=template_key,
            defaults={
                "subject": subject,
                "html_body": html_body or "",
                "text_body": text_body or "",
            },
        )
        for field in ("subject", "html_body", "text_body", "editor_json", "mjml_body", "editor_type", "is_active", "notes"):
            if field in serializer.validated_data:
                setattr(obj, field, serializer.validated_data[field])
        obj.updated_by = request.user
        try:
            obj.full_clean()
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.message_dict) from exc
        obj.save()
        return Response(EmailTemplateSerializer(get_email_template_payload(template_key)).data)


class EmailTemplatePreviewView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, template_key):
        if not is_admin_user(request.user):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        if template_key not in VALID_TEMPLATE_KEYS:
            return Response({"detail": "Template not found."}, status=status.HTTP_404_NOT_FOUND)

        payload = get_email_template_payload(template_key)
        serializer = EmailTemplatePreviewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        subject = data.get("subject", payload["subject"])
        html_body = data.get("html_body", payload["html_body"])
        text_body = data.get("text_body", payload["text_body"])
        mjml_body = data.get("mjml_body") if "mjml_body" in data else (payload.get("mjml_body") or "")
        if mjml_body and (not html_body or "<mjml" in (html_body or "")):
            html_body = compile_mjml(mjml_body)

        metadata = get_template_metadata(template_key)
        validate_required_placeholders(template_key, html_body, mjml_body, text_body)
        return Response(render_template_parts(subject, html_body, text_body, metadata["sample_context"]))


class EmailTemplateSendTestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, template_key):
        if not is_platform_admin(request.user):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        if template_key not in VALID_TEMPLATE_KEYS:
            return Response({"detail": "Template not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = EmailTemplateSendTestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payload = get_email_template_payload(template_key)
        metadata = get_template_metadata(template_key)
        if payload.get("mjml_body") and (not payload.get("html_body") or "<mjml" in (payload.get("html_body") or "")):
            payload["html_body"] = compile_mjml(payload["mjml_body"])
        rendered = render_template_parts(
            payload["subject"],
            payload["html_body"],
            payload["text_body"],
            metadata["sample_context"],
        )
        try:
            sent = send_platform_email(
                subject=rendered["rendered_subject"],
                message=rendered["rendered_text"],
                recipient_list=[serializer.validated_data["test_email"]],
                html_message=rendered["rendered_html"] or None,
                fail_silently=False,
            )
        except Exception as exc:
            return Response({"success": False, "detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"success": bool(sent), "sent": sent})


class EmailTemplateResetView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, template_key):
        if not is_platform_admin(request.user):
            return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
        if template_key not in VALID_TEMPLATE_KEYS:
            return Response({"detail": "Template not found."}, status=status.HTTP_404_NOT_FOUND)

        defaults = get_file_defaults(template_key)
        validate_template_syntax(defaults["subject"], defaults["html_body"], defaults["text_body"])
        validate_required_placeholders(template_key, defaults["html_body"], text_body=defaults["text_body"])
        obj, _created = EmailTemplate.objects.get_or_create(
            template_key=template_key,
            defaults={
                "subject": defaults["subject"],
                "html_body": defaults["html_body"],
                "text_body": defaults["text_body"],
            },
        )
        obj.subject = defaults["subject"]
        obj.html_body = defaults["html_body"]
        obj.text_body = defaults["text_body"]
        obj.editor_json = None
        obj.mjml_body = ""
        obj.editor_type = "templatical"
        obj.is_active = True
        obj.updated_by = request.user
        obj.full_clean()
        obj.save()
        return Response(EmailTemplateSerializer(get_email_template_payload(template_key)).data)
