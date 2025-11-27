from django.contrib.contenttypes.models import ContentType
from rest_framework import viewsets, status, mixins
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from typing import Optional
from rest_framework.exceptions import ValidationError
from django.db.models import Count
from rest_framework.views import APIView
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiTypes


from activity_feed.models import FeedItem

from .models import Comment, Reaction, Share
from .serializers import (
    CommentSerializer,
    ReactionToggleSerializer,
    ReactionUserSerializer,
    ShareReadSerializer,
    ShareWriteSerializer
)

def _ct_for_feed_item() -> ContentType:
    # hard-wired to your real model without using settings
    return ContentType.objects.get_for_model(FeedItem)

def _ct_from_param_or_feeditem_default(value: Optional[str]) -> ContentType:
    """
    If value provided -> parse ('comment', numeric CT id, or 'app.Model').
    Otherwise -> default to FeedItem.
    """
    if value:
        v = value.strip()
        if v.lower() == "comment":
            return ContentType.objects.get_for_model(Comment)
        if v.isdigit():
            return ContentType.objects.get(id=int(v))
        if "." in v:
            app_label, model = v.split(".", 1)
            return ContentType.objects.get(app_label=app_label.lower(), model=model.lower())
        raise ValidationError({"target_type": ["Invalid format. Use 'comment', numeric id, or 'app.Model'."]})
    # no value => default to FeedItem
    return _ct_for_feed_item()

def _ct_from_param(value: str) -> ContentType:
    # accept 'comment' or 'app_label.ModelName' or numeric CT id
    if value.lower() == "comment":
        return ContentType.objects.get_for_model(Comment)
    if value.isdigit():
        return ContentType.objects.get(id=int(value))
    app_label, model = value.split(".", 1)
    return ContentType.objects.get(app_label=app_label.lower(), model=model.lower())


class EngagementMetricsView(APIView):
    """
    GET /api/engagements/metrics/?ids=1,2,3[&target_type=app.Model|comment|<ct_id>]
    Returns per-target reaction/comment/share counts and whether the current user reacted.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        ids_raw = request.query_params.get("ids", "") or ""
        ids = [int(x) for x in ids_raw.split(",") if x.strip().isdigit()]
        if not ids:
            return Response({}, status=status.HTTP_200_OK)

        # default content type = FeedItem, but allow overriding
        ct = _ct_from_param_or_feeditem_default(
            request.query_params.get("target_type")
        )

        # ✅ Reactions (all types, not only "like")
        reaction_qs = (
            Reaction.objects
            .filter(content_type=ct, object_id__in=ids)
            .values("object_id")
            .annotate(n=Count("id"))
        )

        # Root-level comments
        comment_qs = (
            Comment.objects
            .filter(content_type=ct, object_id__in=ids, parent__isnull=True)
            .values("object_id")
            .annotate(n=Count("id"))
        )

        # Shares
        share_qs = (
            Share.objects
            .filter(content_type=ct, object_id__in=ids)
            .values("object_id")
            .annotate(n=Count("id"))
        )

        # ✅ Has the current user reacted in ANY way?
        liked_by_me = set(
            Reaction.objects
            .filter(content_type=ct, object_id__in=ids, user=request.user)
            .values_list("object_id", flat=True)
        )

        # Build output skeleton
        out = {}
        for i in ids:
            out[i] = {
                "likes": 0,
                "comments": 0,
                "shares": 0,
                "me_liked": (i in liked_by_me),
                # duplicate keys for compatibility with other code paths
                "like_count": 0,
                "comment_count": 0,
                "share_count": 0,
                "user_has_liked": (i in liked_by_me),
            }

        for row in reaction_qs:
            o = out.get(row["object_id"])
            if o:
                o["likes"] = o["like_count"] = row["n"]

        for row in comment_qs:
            o = out.get(row["object_id"])
            if o:
                o["comments"] = o["comment_count"] = row["n"]

        for row in share_qs:
            o = out.get(row["object_id"])
            if o:
                o["shares"] = o["share_count"] = row["n"]

        return Response(out, status=status.HTTP_200_OK)

# ---------- Comments ----------
class CommentViewSet(viewsets.ModelViewSet):
    """
    List top-level comments for a target:
      GET /api/engagements/comments/?target_type=app.Model&target_id=123
    List replies for a parent:
      GET /api/engagements/comments/?parent=<comment_id>
    """
    permission_classes = [IsAuthenticated]
    serializer_class = CommentSerializer
    queryset = Comment.objects.select_related("user").all()

    def get_queryset(self):
        qs = super().get_queryset()

        # For detail routes, do NOT narrow the queryset
        if getattr(self, "action", None) in ("retrieve", "update", "partial_update", "destroy"):
            return qs

        parent = self.request.query_params.get("parent")
        ttype = self.request.query_params.get("target_type")
        tid = self.request.query_params.get("target_id")
        feed_item = self.request.query_params.get("feed_item")

        if parent:
            return qs.filter(parent_id=parent)

        if ttype and tid:
            if ttype.lower() == "comment":
                ct = ContentType.objects.get_for_model(Comment)
            elif ttype.isdigit():
                ct = ContentType.objects.get(id=int(ttype))
            else:
                app_label, model = ttype.split(".", 1)
                ct = ContentType.objects.get(app_label=app_label.lower(), model=model.lower())
            if not str(tid).isdigit():
                return qs.none()
            return qs.filter(content_type=ct, object_id=int(tid), parent__isnull=True)

        # Default to FeedItem when only an id is supplied
        if tid or feed_item:
            ct = ContentType.objects.get_for_model(FeedItem)
            oid = tid or feed_item
            if not str(oid).isdigit(): 
                return qs.none()
            return qs.filter(content_type=ct, object_id=int(oid), parent__isnull=True)

        # For plain list without filters, you can choose:
        # return qs            # (show all)
        return qs.none()        # (keep strict; list requires a filter)

    def perform_create(self, serializer):
        serializer.save()

    @action(methods=["get"], detail=True, url_path="replies")
    def replies(self, request, pk=None):
        qs = Comment.objects.select_related("user").filter(parent_id=pk)
        page = self.paginate_queryset(qs)
        ser = self.get_serializer(page or qs, many=True)
        if page is not None:
            return self.get_paginated_response(ser.data)
        return Response(ser.data)

# ---------- Reactions ----------
class ReactionViewSet(viewsets.GenericViewSet):
    """
    Toggle like on any target:
      POST /api/engagements/reactions/toggle/
      { "target_type": "app.Model" | "comment", "target_id": 123, "reaction": "like" }

    Who liked a target:
      GET /api/engagements/reactions/who-liked/?target_type=app.Model&target_id=123
    """
    permission_classes = [IsAuthenticated]
    serializer_class = ReactionToggleSerializer
    queryset = Reaction.objects.none()

    @action(methods=["post"], detail=False, url_path="toggle")
    def toggle(self, request):
        data = request.data.copy()

        # Allow aliases so you never need target_type:
        # { "feed_item": 144 } -> defaults to FeedItem
        if "feed_item" in data and "target_id" not in data:
            data["target_id"] = data["feed_item"]

        # { "comment_id": 45 } -> force comment type
        if "comment_id" in data and "target_id" not in data:
            data["target_id"] = data["comment_id"]
            data["target_type"] = "comment"

        ser = self.get_serializer(data=data)
        ser.is_valid(raise_exception=True)

        target_type = ser.validated_data.get("target_type")  # can be None/blank
        target_id = ser.validated_data["target_id"]
        reaction = ser.validated_data["reaction"]

        ct = _ct_from_param_or_feeditem_default(target_type)

        # ✅ one reaction per user+target
        existing = Reaction.objects.filter(
            user=request.user,
            content_type=ct,
            object_id=target_id,
        ).first()

        # Same reaction again -> remove (toggle off)
        if existing and existing.reaction == reaction:
            existing.delete()
            return Response({"status": "unliked"}, status=status.HTTP_200_OK)

        # Different reaction exists -> switch type
        if existing:
            existing.reaction = reaction
            existing.save(update_fields=["reaction"])
            return Response({"status": "liked", "reaction": reaction}, status=status.HTTP_200_OK)

        # No reaction yet -> create
        Reaction.objects.create(
            user=request.user,
            content_type=ct,
            object_id=target_id,
            reaction=reaction,
        )
        return Response({"status": "liked", "reaction": reaction}, status=status.HTTP_201_CREATED)

    
    @action(detail=False, methods=['get'], url_path='counts', permission_classes=[IsAuthenticated])
    def counts(self, request):
        target_type = (request.query_params.get("target_type") or "post").lower()
        raw_ids = (request.query_params.get("ids") or "").replace(" ", "")
        ids = [int(x) for x in raw_ids.split(",") if x.isdigit()]
        if not ids:
            return Response({"results": {}}, status=200)

        model_map = {
            "comment": Comment,
            "post": FeedItem,
            "feed": FeedItem,
            "feeditem": FeedItem,
        }
        Model = model_map.get(target_type)
        if not Model:
            return Response({"detail": "unsupported target_type"}, status=400)

        ct = ContentType.objects.get_for_model(Model)

        # ✅ count ALL reactions, not just "like"
        base = Reaction.objects.filter(
            content_type=ct,
            object_id__in=ids,
        )

        # aggregate counts
        rows = base.values("object_id").annotate(n=Count("id"))
        out = {
            str(r["object_id"]): {
                "like_count": r["n"],     # kept key name for compatibility
                "user_has_liked": False,  # actually: "user_has_reacted"
            }
            for r in rows
        }

        # mark which of these the current user has reacted to
        mine = set(
            base.filter(user=request.user).values_list("object_id", flat=True)
        )
        for oid in mine:
            key = str(oid)
            out.setdefault(key, {"like_count": 0, "user_has_liked": False})
            out[key]["user_has_liked"] = True

        return Response({"results": out}, status=200)


    @extend_schema(
        parameters=[
            OpenApiParameter(name="target_id", type=OpenApiTypes.INT, location=OpenApiParameter.QUERY,
                             required=False, description="FeedItem id (default type)"),
            OpenApiParameter(name="feed_item", type=OpenApiTypes.INT, location=OpenApiParameter.QUERY,
                             required=False, description="Alias for target_id (FeedItem)"),
            OpenApiParameter(name="comment_id", type=OpenApiTypes.INT, location=OpenApiParameter.QUERY,
                             required=False, description="Comment id (forces comment type)"),
            OpenApiParameter(name="target_type", type=OpenApiTypes.STR, location=OpenApiParameter.QUERY,
                             required=False, description="Optional explicit type: 'comment', numeric CT id, or 'app.Model'"),
        ]
    )
    @action(methods=["get"], detail=False, url_path="who-liked")
    def who_liked(self, request):
        target_type = request.query_params.get("target_type")
        target_id = request.query_params.get("target_id")
        feed_item = request.query_params.get("feed_item")
        comment_id = request.query_params.get("comment_id")

        # Aliases
        if comment_id and not target_type:
            target_type = "comment"
            target_id = comment_id
        if feed_item and not target_id:
            target_id = feed_item

        if not target_id:
            return Response(
                {"detail": "Provide target_id or feed_item or comment_id."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Use your existing helper that defaults to FeedItem when target_type missing
        ct = _ct_from_param_or_feeditem_default(target_type)

        qs = Reaction.objects.select_related("user").filter(content_type=ct, object_id=target_id)
        page = self.paginate_queryset(qs)
        ser = ReactionUserSerializer(page or qs, many=True)
        if page is not None:
            return self.get_paginated_response(ser.data)
        return Response(ser.data)

# ---------- Shares ----------
class ShareViewSet(mixins.CreateModelMixin,
                   mixins.DestroyModelMixin,
                   mixins.ListModelMixin,
                   viewsets.GenericViewSet):
    queryset = Share.objects.select_related("user").all()

    # --- CREATE (bulk) ---
    def get_serializer_class(self):
        if self.action == "create":
            return ShareWriteSerializer
        return ShareReadSerializer

    def create(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)
        rows = ser.save()  # returns List[Share]
        out = ShareReadSerializer(rows, many=True, context={"request": request})
        return Response(out.data, status=status.HTTP_201_CREATED)

    # --- LIST filters ---
    def get_queryset(self):
        qs = super().get_queryset()

        # which object is shared
        ttype = self.request.query_params.get("target_type")
        tid = self.request.query_params.get("target_id")
        feed_item = self.request.query_params.get("feed_item")
        if ttype or tid or feed_item:
            ct = _ct_from_param_or_feeditem_default(ttype)
            oid = tid or feed_item
            if oid:
                qs = qs.filter(content_type=ct, object_id=oid)

        # recipients filter (optional)
        user_id = self.request.query_params.get("user_id")  # recipient user
        if user_id:
            qs = qs.filter(to_user_id=user_id)
        group_id = self.request.query_params.get("group_id")  # recipient group
        if group_id:
            qs = qs.filter(to_group_id=group_id)

        # "mine" filter (shares I created)
        mine = self.request.query_params.get("mine")
        if mine is not None and str(mine).lower() in ("1", "true", "yes"):
            qs = qs.filter(user=self.request.user)

        return qs