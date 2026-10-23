"""IPDT-778: Event sponsor/partner showcase endpoints.

Read is public only for visible, published IMAA Connect events. Event creators
or Django superusers can edit assignments. Only superusers may edit the global
category taxonomy so one organizer cannot rename labels on other events.
"""
from pathlib import Path
from PIL import Image, UnidentifiedImageError
from django.db.models import ProtectedError
from django.shortcuts import get_object_or_404
from rest_framework import serializers, status
from rest_framework.parsers import JSONParser, MultiPartParser, FormParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import PermissionDenied, NotFound, ValidationError

from .models import Event, EventSupporter, EventSupporterCategory, IMAA_CONNECT_PLATFORM_SLUG

MAX_LOGO_BYTES = 5 * 1024 * 1024
ALLOWED_IMAGE_EXTENSIONS = {
    ".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG",
    ".webp": "WEBP", ".gif": "GIF",
}
MAX_LOGO_PIXELS = 20_000_000


def _owner(user, event):
    return bool(user and user.is_authenticated and (
        event.created_by_id == user.pk or user.is_superuser
    ))


def _event_for_request(request, event_id, *, write=False):
    event = get_object_or_404(Event.objects.select_related("community"), pk=event_id)
    if _owner(request.user, event):
        return event
    if write:
        if not request.user.is_authenticated:
            raise PermissionDenied("Sign in as the event owner to manage sponsors and partners.")
        raise PermissionDenied("Only this event's creator or a platform superuser can edit logos.")
    # Do not expose logos attached to draft/hidden/unpublished events.
    visible = (
        event.status in ("published", "live", "ended")
        and not event.is_hidden
        and not (event.archived_at and not event.restored_at)
        and event.publications.filter(
            platform__slug=IMAA_CONNECT_PLATFORM_SLUG,
            is_enabled=True,
        ).exists()
    )
    if not visible:
        raise NotFound("Event not found.")
    return event


class SupporterCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = EventSupporterCategory
        fields = ("id", "kind", "name", "display_order", "is_active")

    def validate_name(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Category name is required.")
        return value

    def validate(self, attrs):
        kind = attrs.get("kind", getattr(self.instance, "kind", None))
        name = attrs.get("name", getattr(self.instance, "name", None))
        if kind and name:
            existing = EventSupporterCategory.objects.filter(kind=kind, name__iexact=name)
            if self.instance:
                existing = existing.exclude(pk=self.instance.pk)
            if existing.exists():
                raise serializers.ValidationError({"name": "A category with this name already exists for this type."})
        if (self.instance and "kind" in attrs and attrs["kind"] != self.instance.kind
                and self.instance.supporters.exists()):
            raise serializers.ValidationError({"kind": "Reassign logos before changing an in-use category's type."})
        return attrs


class EventSupporterSerializer(serializers.ModelSerializer):
    category = serializers.PrimaryKeyRelatedField(queryset=EventSupporterCategory.objects.all())
    kind = serializers.CharField(source="category.kind", read_only=True)
    category_name = serializers.CharField(source="category.name", read_only=True)
    category_order = serializers.IntegerField(source="category.display_order", read_only=True)
    logo_url = serializers.SerializerMethodField()

    class Meta:
        model = EventSupporter
        fields = (
            "id", "name", "category", "kind", "category_name", "category_order",
            "logo", "logo_url", "website_url", "display_order",
        )
        extra_kwargs = {"logo": {"write_only": True, "required": False}}

    def get_logo_url(self, obj):
        if not obj.logo:
            return None
        url = obj.logo.url
        request = self.context.get("request")
        return request.build_absolute_uri(url) if request else url

    def validate_logo(self, value):
        if value.size > MAX_LOGO_BYTES:
            raise serializers.ValidationError("Logo must be 5 MB or smaller.")
        extension = Path(value.name).suffix.lower()
        expected_format = ALLOWED_IMAGE_EXTENSIONS.get(extension)
        if not expected_format:
            raise serializers.ValidationError("Logo filename must end in .png, .jpg, .jpeg, .webp or .gif.")
        try:
            image = Image.open(value)
            if image.format != expected_format:
                raise serializers.ValidationError("Image content must match its filename format.")
            if image.width * image.height > MAX_LOGO_PIXELS:
                raise serializers.ValidationError("Logo dimensions are too large.")
            image.verify()
        except (UnidentifiedImageError, OSError, ValueError):
            raise serializers.ValidationError("Upload a valid PNG, JPEG, WebP, or GIF image.")
        finally:
            value.seek(0)
        return value

    def validate_website_url(self, value):
        if value and not value.lower().startswith(("https://", "http://")):
            raise serializers.ValidationError("Use an http:// or https:// website URL.")
        return value

    def validate(self, attrs):
        if self.instance is None and not attrs.get("logo"):
            raise serializers.ValidationError({"logo": "A logo image is required."})
        category = attrs.get("category")
        if category and not category.is_active and (self.instance is None or self.instance.category_id != category.pk):
            raise serializers.ValidationError({"category": "Choose an active category."})
        return attrs


class SupporterCategoryListCreateView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        qs = EventSupporterCategory.objects.all()
        if not (request.user.is_authenticated and request.user.is_superuser):
            qs = qs.filter(is_active=True)
        return Response(SupporterCategorySerializer(qs, many=True).data)

    def post(self, request):
        if not (request.user.is_authenticated and request.user.is_superuser):
            raise PermissionDenied("Only platform superusers can manage sponsor and partner category types.")
        ser = SupporterCategorySerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data, status=status.HTTP_201_CREATED)


class SupporterCategoryDetailView(APIView):
    permission_classes = [AllowAny]

    def _get_category(self, request, pk):
        if not (request.user.is_authenticated and request.user.is_superuser):
            raise PermissionDenied("Only platform superusers can manage category types.")
        return get_object_or_404(EventSupporterCategory, pk=pk)

    def patch(self, request, pk):
        category = self._get_category(request, pk)
        ser = SupporterCategorySerializer(category, data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data)

    def delete(self, request, pk):
        category = self._get_category(request, pk)
        try:
            category.delete()
        except ProtectedError:
            return Response({"detail": "Category is in use. Reassign its logos before deleting."}, status=409)
        return Response(status=status.HTTP_204_NO_CONTENT)


class EventSupporterListCreateView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser, FormParser, MultiPartParser]

    def get(self, request, event_id):
        event = _event_for_request(request, event_id)
        items = EventSupporter.objects.filter(event=event).select_related("category")
        if not _owner(request.user, event):
            items = items.filter(category__is_active=True)
        return Response(EventSupporterSerializer(items, many=True, context={"request": request}).data)

    def post(self, request, event_id):
        event = _event_for_request(request, event_id, write=True)
        ser = EventSupporterSerializer(data=request.data, context={"request": request})
        ser.is_valid(raise_exception=True)
        ser.save(event=event)
        return Response(ser.data, status=status.HTTP_201_CREATED)


class EventSupporterDetailView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser, FormParser, MultiPartParser]

    def _item(self, request, event_id, pk):
        event = _event_for_request(request, event_id, write=True)
        return get_object_or_404(EventSupporter.objects.select_related("category"), event=event, pk=pk)

    def patch(self, request, event_id, pk):
        item = self._item(request, event_id, pk)
        ser = EventSupporterSerializer(item, data=request.data, partial=True, context={"request": request})
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data)

    def delete(self, request, event_id, pk):
        self._item(request, event_id, pk).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
