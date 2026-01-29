from collections import defaultdict
from datetime import timedelta

from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models import Count, Max
from django.utils import timezone
from rest_framework import mixins, status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from activity_feed.models import FeedItem
from engagements.models import Comment
from users.serializers import UserMiniSerializer

from .models import Report, ModerationAction
from .permissions import IsStaffOrSuperuser
from .serializers import ReportCreateSerializer, ReportReadSerializer, ModerationActionSerializer, parse_target_type


def _is_reportable_feeditem(item: FeedItem) -> bool:
    meta = getattr(item, "metadata", None) or {}
    t = str(meta.get("type") or "").lower()
    return t not in {"event", "resource"}


def _resolve_target(ct: ContentType, object_id: int):
    if ct == ContentType.objects.get_for_model(FeedItem):
        obj = FeedItem.objects.filter(pk=object_id).select_related("actor").first()
        return obj, "post"
    if ct == ContentType.objects.get_for_model(Comment):
        obj = Comment.objects.filter(pk=object_id).select_related("user").first()
        return obj, "comment"
    return None, "unknown"


def _target_author_id(target, kind: str):
    if kind == "post":
        return getattr(target, "actor_id", None)
    if kind == "comment":
        return getattr(target, "user_id", None)
    return None


def _set_moderation_status(target, status_value: str):
    if hasattr(target, "moderation_status"):
        target.moderation_status = status_value
        if hasattr(target, "moderation_updated_at"):
            target.moderation_updated_at = timezone.now()
        target.save(update_fields=["moderation_status", "moderation_updated_at"])


def _allowed_patch_keys_for_feed(meta_type: str):
    base = {"text", "caption", "title", "description", "url"}
    if meta_type == "poll":
        return base | {"question", "options"}
    return base


def _summarize_feed_item(item: FeedItem, request):
    meta = getattr(item, "metadata", None) or {}
    t = str(meta.get("type") or "text").lower()
    summary = {
        "type": t or "text",
        "text": meta.get("text") or meta.get("caption") or meta.get("description") or "",
        "title": meta.get("title") or meta.get("url_title") or meta.get("question") or "",
        "url": meta.get("url") or meta.get("link_url") or "",
        "image_url": meta.get("image") or meta.get("image_url") or "",
        "community_id": item.community_id,
        "group_id": item.group_id,
    }
    return summary


def _summarize_comment(comment: Comment):
    return {
        "text": comment.text or "",
        "parent_id": comment.parent_id,
        "target_type": f"{comment.content_type.app_label}.{comment.content_type.model}",
        "target_id": comment.object_id,
    }


class ReportViewSet(mixins.CreateModelMixin, mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = Report.objects.all().select_related("content_type")

    def get_permissions(self):
        if self.action == "create":
            return [IsAuthenticated()]
        return [IsStaffOrSuperuser()]

    def get_serializer_class(self):
        if self.action == "create":
            return ReportCreateSerializer
        return ReportReadSerializer

    def create(self, request, *args, **kwargs):
        ser = self.get_serializer(data=request.data)
        ser.is_valid(raise_exception=True)

        ct = parse_target_type(ser.validated_data["target_type"])
        target_id = ser.validated_data["target_id"]
        reason = ser.validated_data["reason"]
        notes = (ser.validated_data.get("notes") or "").strip()

        target, kind = _resolve_target(ct, target_id)
        if not target:
            return Response({"detail": "Target not found."}, status=status.HTTP_404_NOT_FOUND)

        if kind == "post" and not _is_reportable_feeditem(target):
            return Response({"detail": "This content type cannot be reported."}, status=status.HTTP_400_BAD_REQUEST)

        if kind == "comment":
            # Only allow comments on FeedItems, and those FeedItems must be reportable
            if target.content_type != ContentType.objects.get_for_model(FeedItem):
                return Response({"detail": "This comment cannot be reported."}, status=status.HTTP_400_BAD_REQUEST)
            feed_target = FeedItem.objects.filter(pk=target.object_id).first()
            if not feed_target or not _is_reportable_feeditem(feed_target):
                return Response({"detail": "This comment cannot be reported."}, status=status.HTTP_400_BAD_REQUEST)

        author_id = _target_author_id(target, kind)
        if author_id and author_id == getattr(request.user, "id", None):
            return Response({"detail": "You cannot report your own content."}, status=status.HTTP_400_BAD_REQUEST)

        # prevent duplicates
        if Report.objects.filter(reporter=request.user, content_type=ct, object_id=target_id).exists():
            return Response({"detail": "You already reported this content."}, status=status.HTTP_409_CONFLICT)

        with transaction.atomic():
            report = Report.objects.create(
                reporter=request.user,
                content_type=ct,
                object_id=target_id,
                reason=reason,
                notes=notes,
            )

            report_count = Report.objects.filter(content_type=ct, object_id=target_id).count()
            threshold = int(getattr(settings, "MODERATION_AUTO_REVIEW_THRESHOLD", 3) or 3)

            # Move to under_review after a report (and ensure auto flagging on threshold)
            if getattr(target, "moderation_status", None) not in {"under_review", "removed"}:
                if report_count >= 1 or report_count >= threshold:
                    _set_moderation_status(target, "under_review")
                    ModerationAction.objects.create(
                        performed_by=request.user,
                        content_type=ct,
                        object_id=target_id,
                        action=ModerationAction.ACTION_AUTO_UNDER_REVIEW,
                        note="Auto-flagged after report",
                        meta={"report_count": report_count},
                    )

        return Response(
            {
                "ok": True,
                "report_id": report.id,
                "report_count": report_count,
                "status": getattr(target, "moderation_status", "under_review"),
            },
            status=status.HTTP_201_CREATED,
        )


class ModerationQueueView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, *args, **kwargs):
        feed_ct = ContentType.objects.get_for_model(FeedItem)
        comment_ct = ContentType.objects.get_for_model(Comment)

        base = Report.objects.filter(content_type_id__in=[feed_ct.id, comment_ct.id])

        # aggregate counts
        grouped = list(
            base.values("content_type_id", "object_id")
            .annotate(report_count=Count("id"), last_reported_at=Max("created_at"))
        )

        if not grouped:
            return Response({"results": []}, status=status.HTTP_200_OK)

        reason_rows = list(
            base.values("content_type_id", "object_id", "reason")
            .annotate(n=Count("id"))
        )
        reason_map = defaultdict(lambda: defaultdict(int))
        for row in reason_rows:
            key = (row["content_type_id"], row["object_id"])
            reason_map[key][row["reason"]] = row["n"]

        notes_rows = list(
            base.exclude(notes="")
            .values("content_type_id", "object_id", "notes", "created_at")
            .order_by("-created_at")
        )
        notes_map = defaultdict(list)
        for row in notes_rows:
            key = (row["content_type_id"], row["object_id"])
            if len(notes_map[key]) < 20:
                notes_map[key].append({"note": row["notes"], "created_at": row["created_at"]})

        feed_ids = [r["object_id"] for r in grouped if r["content_type_id"] == feed_ct.id]
        comment_ids = [r["object_id"] for r in grouped if r["content_type_id"] == comment_ct.id]

        feeds = {
            f.id: f
            for f in FeedItem.objects.filter(id__in=feed_ids).select_related("actor")
        }
        comments = {
            c.id: c
            for c in Comment.objects.filter(id__in=comment_ids).select_related("user")
        }

        status_filter = (request.query_params.get("status") or "").strip().lower()
        if status_filter == "all":
            status_filter = ""

        results = []
        for row in grouped:
            ct_id = row["content_type_id"]
            oid = row["object_id"]
            key = (ct_id, oid)
            ct = feed_ct if ct_id == feed_ct.id else comment_ct

            if ct_id == feed_ct.id:
                item = feeds.get(oid)
                if not item:
                    continue
                if not _is_reportable_feeditem(item):
                    continue
                status_value = getattr(item, "moderation_status", "clear")
                if status_filter and status_value != status_filter:
                    continue

                author = UserMiniSerializer(item.actor, context={"request": request}).data if item.actor else None
                results.append({
                    "target_type": "activity_feed.feeditem",
                    "target_id": item.id,
                    "content_kind": "post",
                    "status": status_value,
                    "report_count": row["report_count"],
                    "reason_breakdown": reason_map.get(key, {}),
                    "last_reported_at": row["last_reported_at"],
                    "notes": notes_map.get(key, []),
                    "author": author,
                    "created_at": item.created_at,
                    "content": _summarize_feed_item(item, request),
                })
            else:
                comment = comments.get(oid)
                if not comment:
                    continue
                status_value = getattr(comment, "moderation_status", "clear")
                if status_filter and status_value != status_filter:
                    continue

                author = UserMiniSerializer(comment.user, context={"request": request}).data if comment.user else None
                results.append({
                    "target_type": "comment",
                    "target_id": comment.id,
                    "content_kind": "comment",
                    "status": status_value,
                    "report_count": row["report_count"],
                    "reason_breakdown": reason_map.get(key, {}),
                    "last_reported_at": row["last_reported_at"],
                    "notes": notes_map.get(key, []),
                    "author": author,
                    "created_at": comment.created_at,
                    "content": _summarize_comment(comment),
                })

        results.sort(key=lambda r: r.get("last_reported_at") or r.get("created_at"), reverse=True)
        return Response({"results": results}, status=status.HTTP_200_OK)


class ModerationActionView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def post(self, request, *args, **kwargs):
        ser = ModerationActionSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        ct = parse_target_type(ser.validated_data["target_type"])
        target_id = ser.validated_data["target_id"]
        action = ser.validated_data["action"]
        note = (ser.validated_data.get("note") or "").strip()
        patch = ser.validated_data.get("patch") or {}
        set_status = ser.validated_data.get("set_status")

        target, kind = _resolve_target(ct, target_id)
        if not target:
            return Response({"detail": "Target not found."}, status=status.HTTP_404_NOT_FOUND)

        if kind == "post" and not _is_reportable_feeditem(target):
            return Response({"detail": "This content type cannot be moderated."}, status=status.HTTP_400_BAD_REQUEST)

        before = {}
        after = {}

        if action == ModerationAction.ACTION_APPROVE:
            _set_moderation_status(target, "clear")
            after["moderation_status"] = "clear"

        elif action == ModerationAction.ACTION_SOFT_DELETE:
            _set_moderation_status(target, "removed")
            after["moderation_status"] = "removed"

        elif action == ModerationAction.ACTION_EDIT:
            if kind == "comment":
                new_text = (patch.get("text") or patch.get("content") or "").strip()
                if not new_text:
                    return Response({"detail": "Comment text is required."}, status=status.HTTP_400_BAD_REQUEST)
                before["text"] = target.text
                target.text = new_text
                target.save(update_fields=["text"]) 
                after["text"] = new_text
            else:
                meta = dict(getattr(target, "metadata", None) or {})
                meta_type = str(meta.get("type") or "text").lower()
                allowed = _allowed_patch_keys_for_feed(meta_type)
                editable = {k: v for k, v in patch.items() if k in allowed}
                if not editable:
                    return Response({"detail": "No editable fields provided."}, status=status.HTTP_400_BAD_REQUEST)
                before["metadata"] = meta.copy()
                meta.update(editable)
                target.metadata = meta
                target.save(update_fields=["metadata"]) 
                after["metadata"] = meta

            if set_status:
                _set_moderation_status(target, set_status)
                after["moderation_status"] = set_status

        ModerationAction.objects.create(
            performed_by=request.user,
            content_type=ct,
            object_id=target_id,
            action=action,
            note=note,
            meta={"before": before, "after": after},
        )

        return Response({"ok": True}, status=status.HTTP_200_OK)


# Profile Moderation Views
class ProfileReportViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """
    ViewSet for reporting user profiles.
    POST /api/moderation/profile-reports/
    """
    permission_classes = [IsAuthenticated]
    serializer_class = None  # Set dynamically

    def get_serializer_class(self):
        from .serializers import ProfileReportCreateSerializer
        return ProfileReportCreateSerializer

    def create(self, request, *args, **kwargs):
        """
        Report a user profile.
        """
        from django.contrib.auth import get_user_model
        from .models import ProfileReportMetadata
        from .serializers import ProfileReportCreateSerializer

        User = get_user_model()

        ser = ProfileReportCreateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        target_user_id = ser.validated_data['target_user_id']
        reason = ser.validated_data['reason']
        notes = ser.validated_data.get('notes', '').strip()
        metadata = ser.validated_data.get('metadata', {})

        # Prevent self-reporting
        if target_user_id == request.user.id:
            return Response(
                {"detail": "You cannot report your own profile."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get target user
        target_user = User.objects.filter(id=target_user_id).first()
        if not target_user:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        user_ct = ContentType.objects.get_for_model(User)

        # Check for active/pending reports to avoid spamming the same reason immediately
        # We allow re-reporting if the previous report was dealt with (e.g. cleared),
        # but maybe we should still block if there's an OPEN report (under_review)?
        # For now, per user request, we remove the strict block or check status.
        
        # Let's check if there is a PENDING report from this user for this reason
        # We can unfortunately only infer pending status easily if we join on the profile/content status
        # but 'Report' itself doesn't have a status field (it relies on the target).
        # Given the requirement "After clearing... users should be able to submit a new report", 
        # we will simply ALLOW duplicates or at least not block based on OLD reports.
        
        # NOTE: We removed the unique constraint on the model, so we can just create a new one.
        # Use a time-based throttle if needed, but for now, just allow it.
        
        # (Optional) We could warn if reported recently (e.g. last 24h)
        recent_report = Report.objects.filter(
            reporter=request.user,
            content_type=user_ct,
            object_id=target_user_id,
            reason=reason,
            created_at__gte=timezone.now() - timedelta(hours=24) # simple spam check
        ).exists()

        if recent_report:
             return Response(
                {"detail": "You have recently reported this profile for this reason. Please wait before reporting again."},
                status=status.HTTP_409_CONFLICT
            )

        with transaction.atomic():
            # Create report
            report = Report.objects.create(
                reporter=request.user,
                content_type=user_ct,
                object_id=target_user_id,
                reason=reason,
                notes=notes
            )

            # Create extended metadata if provided
            if metadata:
                ProfileReportMetadata.objects.create(
                    report=report,
                    **metadata
                )

            # Count reports for this profile
            report_count = Report.objects.filter(
                content_type=user_ct,
                object_id=target_user_id
            ).count()

            # Auto-flag profile for review
            profile = target_user.profile
            if profile.profile_status == 'active':
                profile.profile_status = 'under_review'
                profile.profile_status_updated_at = timezone.now()
                profile.save(update_fields=['profile_status', 'profile_status_updated_at'])

                # Log moderation action
                ModerationAction.objects.create(
                    performed_by=request.user,
                    content_type=user_ct,
                    object_id=target_user_id,
                    action='auto_under_review',
                    note=f'Auto-flagged after profile report: {reason}',
                    meta={
                        'report_count': report_count,
                        'reason': reason,
                        'auto_flagged': True
                    }
                )

        return Response(
            {
                "ok": True,
                "report_id": report.id,
                "report_count": report_count,
                "profile_status": profile.profile_status,
            },
            status=status.HTTP_201_CREATED
        )


class ProfileModerationQueueView(APIView):
    """View profile reports in moderation queue."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        """
        GET /api/moderation/profile-queue/
        ?status=under_review  (active, under_review, suspended, deceased, fake, all)
        ?reason=profile_deceased  (filter by reason)
        """
        from django.contrib.auth import get_user_model
        from .models import ProfileReportMetadata
        from .serializers import ProfileReportMetadataSerializer

        User = get_user_model()
        user_ct = ContentType.objects.get_for_model(User)

        # Get all profile reports
        base = Report.objects.filter(
            content_type=user_ct,
            reason__startswith='profile_'
        ).select_related('reporter', 'content_type')

        # Filter by status if provided
        status_filter = request.query_params.get('status', '').strip().lower()
        reason_filter = request.query_params.get('reason', '').strip().lower()

        # Group by reported user
        grouped = list(
            base.values('object_id')
            .annotate(
                report_count=Count('id'),
                last_reported_at=Max('created_at')
            )
        )

        if not grouped:
            return Response({"results": []})

        # Get reason breakdown
        reason_rows = list(
            base.values('object_id', 'reason')
            .annotate(n=Count('id'))
        )
        reason_map = defaultdict(lambda: defaultdict(int))
        for row in reason_rows:
            reason_map[row['object_id']][row['reason']] = row['n']

        # Get all reports with metadata
        user_ids = [r['object_id'] for r in grouped]
        users = {
            u.id: u
            for u in User.objects.filter(id__in=user_ids).select_related('profile')
        }

        # Get all report metadata
        report_ids = list(base.filter(object_id__in=user_ids).values_list('id', flat=True))
        metadata_map = {
            m.report_id: m
            for m in ProfileReportMetadata.objects.filter(report_id__in=report_ids)
        }

        results = []
        for row in grouped:
            user_id = row['object_id']
            user = users.get(user_id)

            if not user or not hasattr(user, 'profile'):
                continue

            profile = user.profile

            # Filter by status
            if status_filter and status_filter != 'all':
                if profile.profile_status != status_filter:
                    continue

            # Filter by reason
            if reason_filter:
                if reason_filter not in reason_map[user_id]:
                    continue

            # Get sample report with metadata
            sample_report = base.filter(object_id=user_id).first()
            sample_metadata = metadata_map.get(sample_report.id) if sample_report else None

            results.append({
                'user_id': user.id,
                'user': {
                    'id': user.id,
                    'full_name': profile.full_name,
                    'username': user.username,
                    'email': user.email,
                    'avatar': profile.user_image.url if profile.user_image else None,
                    'bio': profile.bio,
                    'profile_status': profile.profile_status,
                },
                'report_count': row['report_count'],
                'reason_breakdown': dict(reason_map[user_id]),
                'last_reported_at': row['last_reported_at'],
                'sample_metadata': ProfileReportMetadataSerializer(sample_metadata).data if sample_metadata else None,
            })

        results.sort(key=lambda r: r['last_reported_at'], reverse=True)

        return Response({'results': results})


class ProfileModerationActionView(APIView):
    """Handle moderation actions on reported profiles."""

    permission_classes = [IsStaffOrSuperuser]

    def post(self, request):
        """
        POST /api/moderation/profile-action/
        {
            "user_id": 123,
            "action": "mark_deceased" | "suspend" | "clear" | "mark_fake",
            "reason": "Explanation",
            "notify_user": true,
            "deceased_data": {
                "death_date": "2024-01-15",
                "legacy_contact_ids": [456, 789]
            }
        }
        """
        from django.contrib.auth import get_user_model

        User = get_user_model()

        user_id = request.data.get('user_id')
        action = request.data.get('action')
        reason = request.data.get('reason', '').strip()
        notify_user = request.data.get('notify_user', False)
        deceased_data = request.data.get('deceased_data', {})

        if not user_id or not action:
            return Response(
                {"detail": "user_id and action are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = User.objects.filter(id=user_id).first()
        if not user or not hasattr(user, 'profile'):
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        profile = user.profile
        user_ct = ContentType.objects.get_for_model(User)

        with transaction.atomic():
            old_status = profile.profile_status

            if action == 'mark_deceased':
                profile.profile_status = 'deceased'
                profile.is_deceased = True
                profile.deceased_date = deceased_data.get('death_date')
                profile.memorialized_at = timezone.now()

                # Set legacy contacts if provided
                legacy_contact_ids = deceased_data.get('legacy_contact_ids', [])
                if legacy_contact_ids:
                    profile.legacy_contacts.set(legacy_contact_ids)

                profile.profile_status_reason = reason
                profile.profile_status_updated_by = request.user
                profile.profile_status_updated_at = timezone.now()
                profile.save()

            elif action == 'suspend':
                profile.profile_status = 'suspended'
                profile.profile_status_reason = reason
                profile.profile_status_updated_by = request.user
                profile.profile_status_updated_at = timezone.now()
                profile.save()

                # Invalidate all active sessions and tokens for the suspended user
                from users.suspension import invalidate_user_sessions, cognito_global_signout
                invalidation_stats = invalidate_user_sessions(user.id)
                # Also try to sign out from Cognito (optional, won't fail if unsuccessful)
                cognito_global_signout(user.username)

            elif action == 'mark_fake':
                profile.profile_status = 'fake'
                profile.profile_status_reason = reason
                profile.profile_status_updated_by = request.user
                profile.profile_status_updated_at = timezone.now()
                profile.save()

                # Invalidate all active sessions and tokens for the fake account
                from users.suspension import invalidate_user_sessions, cognito_global_signout
                invalidation_stats = invalidate_user_sessions(user.id)
                cognito_global_signout(user.username)

            elif action == 'clear':
                profile.profile_status = 'active'
                profile.profile_status_reason = reason
                profile.profile_status_updated_by = request.user
                profile.profile_status_updated_at = timezone.now()
                profile.save()

            else:
                return Response(
                    {"detail": f"Invalid action: {action}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Log moderation action
            ModerationAction.objects.create(
                performed_by=request.user,
                content_type=user_ct,
                object_id=user.id,
                action=action,
                note=reason,
                meta={
                    'before': {'profile_status': old_status},
                    'after': {'profile_status': profile.profile_status},
                    'deceased_data': deceased_data if action == 'mark_deceased' else None,
                }
            )

            # TODO: Send notification to user if notify_user=True

        return Response({"ok": True, "new_status": profile.profile_status})
