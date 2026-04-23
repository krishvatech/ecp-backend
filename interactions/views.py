from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db.models import BooleanField, Count, Exists, OuterRef, Prefetch, Q
from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth import get_user_model
import html
import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

from .models import (
    Question,
    QuestionGuestUpvote,
    QuestionUpvote,
    QnAEngagementPrompt,
    QnAEngagementPromptReceipt,
    QNA_PROMPT_MAX_PER_USER,
    QnAReply,
    QnAReplyUpvote,
    QnAReplyGuestUpvote,
    QnAContentContext,
    QnAAIPublicSuggestion,
    QnAAIPublicSuggestionAdoption,
)
from .serializers import (
    QuestionSerializer,
    PostEventAnswerSerializer,
    MarkAnsweredSerializer,
    QnAReplySerializer,
    QnAAIPublicSuggestionSerializer,
    QnAAIPublicSuggestionAdoptionSerializer,
)
from rest_framework.throttling import UserRateThrottle
import requests

User = get_user_model()


class PolishQuestionRateThrottle(UserRateThrottle):
    """
    Separate throttle scope for the AI polish endpoint.
    Default: 20 requests/minute per user (configurable via DRF_THROTTLE_POLISH env var).
    """
    scope = "polish_question"


class AiSuggestionsRateThrottle(UserRateThrottle):
    """
    Separate throttle scope for the private AI question suggestions endpoint.
    Default: 10/minute per user. Prevents abuse of expensive LLM calls.
    Configure via REST_FRAMEWORK settings: THROTTLE_RATES = {'ai_suggestions': '3/10min'}
    """
    scope = "ai_suggestions"

class QuestionViewSet(viewsets.ModelViewSet):
    """
    Q&A REST endpoints with real-time upvote broadcast.
    - GET /questions?event_id=...
    - POST /questions/{id}/upvote/
    """
    permission_classes = [IsAuthenticated]
    serializer_class = QuestionSerializer          # ✅ ADD THIS
    queryset = Question.objects.all()  # required by DRF, but we override get_queryset()

    @staticmethod
    def _is_guest_user(user) -> bool:
        return bool(getattr(user, "is_guest", False))

    @staticmethod
    def _get_active_registration(user, event):
        """Return the active EventRegistration for this user+event, or None."""
        from events.models import EventRegistration
        if not user or not user.is_authenticated:
            return None
        return EventRegistration.objects.filter(
            event=event,
            user=user,
            status='registered',
        ).first()

    # ------------------------------------------------------------------
    # Reply helpers
    # ------------------------------------------------------------------

    def _get_reply_author_snapshot(self, reply, *, reveal_anonymous_name=True):
        """Return author display info for a QnAReply."""
        author_name = "Audience"
        author_id = None
        author_avatar_url = ""

        guest_asker = getattr(reply, "guest_asker", None)
        author = getattr(reply, "user", None)

        if guest_asker:
            author_name = guest_asker.get_display_name()
            author_id = f"guest_{guest_asker.id}"
        elif author:
            author_name = (
                (getattr(author, "get_full_name", lambda: "")() or "").strip()
                or author.first_name
                or author.username
                or (author.email.split("@")[0] if author.email else f"User {author.id}")
            )
            author_id = reply.user_id

            profile = getattr(author, "profile", None)
            raw_avatar = (
                getattr(profile, "user_image", None)
                or getattr(author, "avatar", None)
                or getattr(profile, "avatar", None)
                or getattr(profile, "image", None)
            )
            if raw_avatar:
                try:
                    raw_avatar = raw_avatar.url
                except Exception:
                    raw_avatar = str(raw_avatar)
                author_avatar_url = self._build_absolute_media_url(raw_avatar)

        if reply.is_anonymous and not reveal_anonymous_name:
            author_name = "Anonymous"
            author_id = None
            author_avatar_url = ""

        return {
            "author_id": author_id,
            "author_name": author_name,
            "author_avatar_url": author_avatar_url,
        }

    def _serialize_reply(self, reply, *, is_host, user):
        """
        Serialize a QnAReply to a dict.

        Uses prefetch cache for upvoters/guest_upvotes — call this only
        after the replies queryset has been prefetched with both.
        """
        author_snapshot = self._get_reply_author_snapshot(
            reply, reveal_anonymous_name=is_host
        )

        # Determine upvote counts and whether current user voted.
        # list() forces use of the prefetch cache (no extra DB hit).
        upvoters_cached = list(reply.upvoters.all())
        guest_upvotes_cached = list(reply.guest_upvotes.all())
        upvote_count = len(upvoters_cached) + len(guest_upvotes_cached)

        is_guest = self._is_guest_user(user)
        if is_guest:
            guest = getattr(user, "guest", None)
            guest_id = guest.id if guest else None
            user_upvoted = any(gu.guest_id == guest_id for gu in guest_upvotes_cached)
        else:
            user_upvoted = any(u.id == user.id for u in upvoters_cached)

        # Build voter name list for host tooltip (same pattern as question upvoters)
        upvoters_list = []
        if is_host:
            for u in upvoters_cached:
                name = (f"{u.first_name} {u.last_name}".strip()) or getattr(u, "username", None) or f"User {u.id}"
                upvoters_list.append({"id": u.id, "name": name})
            for gu in guest_upvotes_cached:
                upvoters_list.append({"id": f"guest_{gu.guest_id}", "name": f"Guest {gu.guest_id}"})

        return {
            "id": reply.id,
            "question_id": reply.question_id,
            "content": reply.content,
            "author_id": author_snapshot["author_id"],
            "author_name": author_snapshot["author_name"],
            "author_avatar_url": author_snapshot["author_avatar_url"],
            "upvote_count": upvote_count,
            "user_upvoted": user_upvoted,
            "upvoters": upvoters_list,
            "created_at": reply.created_at.isoformat(),
            "updated_at": reply.updated_at.isoformat(),
            "is_anonymous": reply.is_anonymous,
            # Only expose moderation/hidden status to hosts
            "moderation_status": reply.moderation_status if is_host else None,
            "is_hidden": reply.is_hidden if is_host else False,
        }

    def _build_absolute_media_url(self, raw_url):
        if not raw_url:
            return ""
        if isinstance(raw_url, str) and raw_url.startswith(("http://", "https://")):
            return raw_url
        try:
            return self.request.build_absolute_uri(raw_url)
        except Exception:
            return str(raw_url)

    def _get_question_asker_snapshot(self, question, *, reveal_anonymous_name=True):
        asker_name = "Audience"
        asker_id = None
        asker_avatar_url = ""

        guest_asker = getattr(question, "guest_asker", None)
        asker = getattr(question, "user", None)

        if guest_asker:
            asker_name = guest_asker.get_display_name()
            asker_id = f"guest_{guest_asker.id}"
        elif asker:
            asker_name = (
                (getattr(asker, "get_full_name", lambda: "")() or "").strip()
                or asker.first_name
                or asker.username
                or (asker.email.split("@")[0] if asker.email else f"User {asker.id}")
            )
            asker_id = question.user_id

            profile = getattr(asker, "profile", None)
            raw_avatar = (
                getattr(profile, "user_image", None)
                or getattr(asker, "avatar", None)
                or getattr(profile, "avatar", None)
                or getattr(profile, "image", None)
            )
            if raw_avatar:
                try:
                    raw_avatar = raw_avatar.url
                except Exception:
                    raw_avatar = str(raw_avatar)
                asker_avatar_url = self._build_absolute_media_url(raw_avatar)

        if question.is_anonymous and not reveal_anonymous_name:
            asker_name = "Anonymous"
            asker_id = None
            asker_avatar_url = ""

        return {
            "asker_id": asker_id,
            "asker_name": asker_name,
            "asker_avatar_url": asker_avatar_url,
        }

    def _is_public_preview_url(self, raw_url):
        try:
            parsed = urlparse(str(raw_url or "").strip())
        except Exception:
            return False

        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False

        hostname = parsed.hostname.strip().lower()
        if hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(".local"):
            return False

        try:
            ip = ipaddress.ip_address(hostname)
            return not (
                ip.is_private or
                ip.is_loopback or
                ip.is_link_local or
                ip.is_multicast or
                ip.is_reserved
            )
        except ValueError:
            pass

        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            return False

        for info in infos:
            try:
                resolved_ip = ipaddress.ip_address(info[4][0])
            except Exception:
                continue
            if (
                resolved_ip.is_private or
                resolved_ip.is_loopback or
                resolved_ip.is_link_local or
                resolved_ip.is_multicast or
                resolved_ip.is_reserved
            ):
                return False
        return True

    def _extract_link_preview(self, raw_url):
        if not self._is_public_preview_url(raw_url):
            raise ValidationError({"url": "Only public http(s) URLs are allowed."})

        response = requests.get(
            raw_url,
            headers={
                "User-Agent": "EventsCommunityPlatformBot/1.0 (+link-preview)",
                "Accept": "text/html,application/xhtml+xml",
            },
            timeout=5,
            allow_redirects=True,
        )
        response.raise_for_status()

        final_url = response.url or raw_url
        text = response.text[:200000]

        def first_match(patterns):
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                if match:
                    value = html.unescape((match.group(1) or "").strip())
                    if value:
                        return value
            return ""

        title = first_match([
            r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']',
            r'<meta[^>]+name=["\']twitter:title["\'][^>]+content=["\']([^"\']+)["\']',
            r"<title[^>]*>(.*?)</title>",
        ])

        favicon = first_match([
            r'<link[^>]+rel=["\'][^"\']*(?:shortcut icon|icon)[^"\']*["\'][^>]+href=["\']([^"\']+)["\']',
        ])
        favicon_url = urljoin(final_url, favicon) if favicon else urljoin(final_url, "/favicon.ico")

        parsed_final = urlparse(final_url)
        return {
            "url": final_url,
            "title": title or parsed_final.netloc,
            "hostname": parsed_final.netloc,
            "favicon_url": favicon_url,
        }

    def get_queryset(self):
        event_id = self.request.query_params.get("event_id")
        # Optional: Filter by specific lounge table (or None for main room)
        # Frontend should send ?lounge_table_id=123 (or empty/missing for main room)
        lounge_table_id = self.request.query_params.get("lounge_table_id")
        
        user = self.request.user
        if self._is_guest_user(user):
            qs = (
                Question.objects
                .annotate(
                    upvotes_count=Count("upvoters", distinct=True) + Count("guest_upvotes", distinct=True),
                    user_upvoted=Exists(
                        QuestionGuestUpvote.objects.filter(
                            question=OuterRef("pk"),
                            guest=user.guest,
                        )
                    ),
                )
            )
        else:
            qs = (
                Question.objects
                .annotate(
                    upvotes_count=Count("upvoters", distinct=True) + Count("guest_upvotes", distinct=True),
                    user_upvoted=Exists(
                        QuestionUpvote.objects.filter(
                            question=OuterRef("pk"),
                            user=user
                        )
                    ),
                )
            )
        if event_id:
            qs = qs.filter(event_id=event_id)

        # Room Isolation Logic
        if lounge_table_id:
            qs = qs.filter(lounge_table_id=lounge_table_id)
        else:
            # If no table specified, return ONLY main room questions
            # This ensures isolation: Main Room users see ONLY main room questions
            qs = qs.filter(lounge_table__isnull=True)

        # Filter out hidden questions for non-hosts
        # Hosts/admins can see all questions including hidden ones
        # Also filter out non-approved questions when moderation is enabled
        if event_id:
            event = get_object_or_404(
                __import__('events.models', fromlist=['Event']).Event,
                id=event_id
            )
            is_host = self.request.user == event.created_by or getattr(self.request.user, "is_staff", False)
            if not is_host:
                qs = qs.filter(is_hidden=False)
                # When moderation is enabled, only show approved questions to attendees
                if event.qna_moderation_enabled:
                    qs = qs.filter(moderation_status="approved")

        # Optional: filter to seed questions only (used by EditEventForm pre-event setup)
        is_seed_filter = self.request.query_params.get("is_seed")
        if is_seed_filter in ("1", "true"):
            qs = qs.filter(is_seed=True)

        # Optional: filter by submission_phase (pre_event or live) — host/admin only
        if event_id:
            event = event or get_object_or_404(
                __import__('events.models', fromlist=['Event']).Event,
                id=event_id
            )
            is_host = self.request.user == event.created_by or getattr(self.request.user, "is_staff", False)
            phase_filter = self.request.query_params.get("submission_phase")
            if phase_filter in ("pre_event", "live") and is_host:
                qs = qs.filter(submission_phase=phase_filter)

        # Support sort parameter: newest, manual, hot/most_voted (default)
        sort = self.request.query_params.get("sort", "most_voted")
        if sort == "newest":
            return qs.order_by("-created_at")
        elif sort == "manual":
            return qs.order_by("display_order", "-created_at")
        else:  # hot or most_voted
            return qs.order_by("-upvotes_count", "-created_at")

    def perform_create(self, serializer):
        """
        Attach the current user when creating a question
        AND broadcast it to all connected QnA WebSocket clients.
        Handle moderation status based on event setting.
        Handle anonymous status based on event setting or user toggle.
        """
        # Capture optional table ID from request body
        lounge_table_id = self.request.data.get("lounge_table")

        # Save with user and table info
        # If lounge_table_id is None/empty, it saves as NULL (Main Room)
        adopted_suggestion_id = self.request.data.get("adopted_suggestion_id")
        extra_kwargs = {"lounge_table_id": lounge_table_id or None}
        if adopted_suggestion_id:
            extra_kwargs["adopted_suggestion_id"] = adopted_suggestion_id

        if self._is_guest_user(self.request.user):
            question = serializer.save(user=None, guest_asker=self.request.user.guest, **extra_kwargs)
        else:
            question = serializer.save(user=self.request.user, guest_asker=None, **extra_kwargs)

        # Log adoption if applicable
        if adopted_suggestion_id:
            try:
                suggestion = QnAAIPublicSuggestion.objects.get(pk=adopted_suggestion_id)
                QnAAIPublicSuggestionAdoption.objects.create(
                    suggestion=suggestion,
                    event_id=question.event_id,
                    user=self.request.user if not self._is_guest_user(self.request.user) else None,
                    guest=self.request.user.guest if self._is_guest_user(self.request.user) else None,
                    submitted_question=question,
                    final_text=question.content,
                )
            except QnAAIPublicSuggestion.DoesNotExist:
                pass

        # Check if event has moderation enabled and set status accordingly
        if question.event.qna_moderation_enabled:
            question.moderation_status = "pending"
            question.save(update_fields=["moderation_status"])

        # Check if anonymous mode is enabled (event-wide override) or user submitted with anonymous toggle
        user_default = False
        if self.request.user.is_authenticated and hasattr(self.request.user, "profile"):
            user_default = self.request.user.profile.default_qna_anonymous
        is_anonymous = bool(self.request.data.get("is_anonymous", user_default))
        if question.event.qna_anonymous_mode:
            is_anonymous = True  # Force all questions to be anonymous

        if is_anonymous != question.is_anonymous:
            question.is_anonymous = is_anonymous
            question.save(update_fields=["is_anonymous"])

        # Initialize display_order: new questions go to the end of their event+table group
        count = Question.objects.filter(
            event_id=question.event_id, lounge_table_id=question.lounge_table_id
        ).count()
        question.display_order = count
        question.save(update_fields=["display_order"])

        # Determine submission phase: pre-event vs live
        from django.utils import timezone as tz
        is_pre_event_eligible = (
            not self._is_guest_user(self.request.user)
            and question.event.pre_event_qna_enabled
            and question.event.start_time is not None
            and tz.now() < question.event.start_time
            and self._get_active_registration(self.request.user, question.event) is not None
        )
        if is_pre_event_eligible:
            question.submission_phase = "pre_event"
            question.save(update_fields=["submission_phase"])

        # Broadcast to the same Channels group used by QnAConsumer
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync

        channel_layer = get_channel_layer()

        # Determine the target group based on where the question was asked
        if question.lounge_table_id:
            # Broadcast ONLY to this table
            group = f"event_qna_{question.event_id}_table_{question.lounge_table_id}"
        else:
            # Broadcast ONLY to main room
            group = f"event_qna_{question.event_id}_main"

        asker_snapshot = self._get_question_asker_snapshot(
            question,
            reveal_anonymous_name=not question.is_anonymous,
        )

        payload = {
            "type": "qna.question",
            "event_id": question.event_id,
            "lounge_table_id": question.lounge_table_id,  # Include table ID in payload
            "question_id": question.id,
            "user_id": asker_snapshot["asker_id"],
            "uid": asker_snapshot["asker_id"],
            "user": asker_snapshot["asker_name"],
            "user_name": asker_snapshot["asker_name"],
            "user_avatar_url": asker_snapshot["asker_avatar_url"],
            "content": question.content,
            "upvote_count": 0,
            "created_at": question.created_at.isoformat(),
            "moderation_status": question.moderation_status,  # NEW: include status
            "is_anonymous": question.is_anonymous,  # Include anonymous status
            "display_order": question.display_order,  # Include sort order
            "submission_phase": question.submission_phase,  # Pre-event vs live
        }

        async_to_sync(channel_layer.group_send)(
            group,
            {"type": "qna.question", "payload": payload},
        )

        # Check if auto-grouping should trigger
        self._maybe_trigger_auto_grouping(question.event_id)

    def _maybe_trigger_auto_grouping(self, event_id):
        """
        Check if auto-grouping threshold is reached and trigger Celery task if so.
        Uses a cache key to throttle task invocations to once per 120 seconds.
        """
        import logging
        from django.core.cache import cache
        from django.conf import settings
        from .tasks import auto_group_questions_task

        logger = logging.getLogger(__name__)
        threshold = getattr(settings, "QNA_AUTO_GROUP_THRESHOLD", 5)
        cache_key = f"qna_autog_{event_id}"

        logger.info(f"[AUTO-GROUP] Checking event {event_id}, threshold={threshold}")

        if cache.get(cache_key):
            logger.info(f"[AUTO-GROUP] Throttled (cache hit) for event {event_id}")
            return  # Recently triggered, throttle

        ungrouped_count = Question.objects.filter(
            event_id=event_id,
            is_hidden=False,
            is_seed=False,
            moderation_status__in=["approved", "pending"],
        ).exclude(group_membership__isnull=False).count()

        logger.info(f"[AUTO-GROUP] Event {event_id}: {ungrouped_count} ungrouped questions")

        if ungrouped_count >= threshold:
            logger.info(f"[AUTO-GROUP] ✅ Threshold reached! Dispatching task for event {event_id}")
            cache.set(cache_key, True, timeout=120)
            auto_group_questions_task.delay(event_id)
        else:
            logger.info(f"[AUTO-GROUP] Not enough questions ({ungrouped_count} < {threshold})")

    def list(self, request, *args, **kwargs):
        from events.models import Event

        event_id = request.query_params.get("event_id")
        user = request.user

        # Determine host status once for the whole list
        is_host = False
        event = None
        if event_id:
            try:
                event = Event.objects.get(pk=event_id)
                is_host = (user == event.created_by or getattr(user, "is_staff", False))
            except Event.DoesNotExist:
                pass

        # Build replies prefetch: filter visibility for attendees
        replies_qs = (
            QnAReply.objects
            .select_related("user", "user__profile", "guest_asker")
            .prefetch_related("upvoters", "guest_upvotes")
            .order_by("created_at")
        )
        if not is_host:
            replies_qs = replies_qs.filter(is_hidden=False)
            if event and event.qna_moderation_enabled:
                replies_qs = replies_qs.filter(moderation_status="approved")

        # Optimize query by selecting related user + prefetch replies
        queryset = (
            self.get_queryset()
            .select_related("user", "user__profile", "guest_asker", "anonymized_by")
            .prefetch_related(Prefetch("replies", queryset=replies_qs))
        )

        data = []
        for q in queryset:
            # Fetch upvoters with their details
            upvoters = q.upvoters.all().values('id', 'username', 'first_name', 'last_name', 'email')
            guest_upvoters = q.guest_upvotes.select_related("guest").values(
                "guest_id", "guest__first_name", "guest__last_name", "guest__email"
            )
            upvoters_list = [
                {
                    'id': u['id'],
                    'name': f"{u.get('first_name', '')} {u.get('last_name', '')}".strip() or u.get('username', f"User {u['id']}"),
                    'username': u.get('username', ''),
                }
                for u in upvoters
            ] + [
                {
                    "id": f"guest_{g['guest_id']}",
                    "name": (
                        f"{(g.get('guest__first_name') or '').strip()} {(g.get('guest__last_name') or '').strip()}".strip()
                        or (g.get("guest__email", "").split("@")[0] if g.get("guest__email") else f"Guest {g['guest_id']}")
                    ),
                    "username": f"guest_{g['guest_id']}",
                }
                for g in guest_upvoters
            ]

            asker_snapshot = self._get_question_asker_snapshot(
                q,
                reveal_anonymous_name=is_host,
            )

            # Seed questions use attribution_label as the display name
            display_user_name = asker_snapshot["asker_name"]
            if q.is_seed and q.attribution_label:
                display_user_name = q.attribution_label

            # Serialize prefetched replies (no N+1 — uses prefetch cache)
            replies_data = [
                self._serialize_reply(r, is_host=is_host, user=user)
                for r in q.replies.all()
            ]

            data.append({
                "id": q.id,
                "content": q.content,
                "user_id": asker_snapshot["asker_id"],
                "user_name": display_user_name,
                "user_avatar_url": asker_snapshot["asker_avatar_url"],
                "upvote_count": q.upvotes_count,  # annotated
                "user_upvoted": q.user_upvoted,  # annotated boolean
                "upvoters": upvoters_list,  # list of users who upvoted
                "event_id": q.event_id,
                "lounge_table_id": q.lounge_table_id,
                "created_at": q.created_at.isoformat(),
                "is_answered": q.is_answered,
                "answered_at": q.answered_at.isoformat() if q.answered_at else None,
                "answered_by": q.answered_by_id,
                "answer_text": q.answer_text,
                "answered_phase": q.answered_phase,
                "requires_followup": q.requires_followup,
                "is_pinned": q.is_pinned,
                "pinned_at": q.pinned_at.isoformat() if q.pinned_at else None,
                "is_anonymous": q.is_anonymous,
                "anonymized_by": q.anonymized_by_id,
                "display_order": q.display_order,
                "is_seed": q.is_seed,
                "attribution_label": q.attribution_label,
                "submission_phase": q.submission_phase,
                # speaker_note is only returned to the host
                "speaker_note": q.speaker_note if (q.is_seed and is_host) else "",
                # threaded replies
                "replies": replies_data,
                "reply_count": len(replies_data),
            })
        return Response(data)

    @action(detail=False, methods=["get"], url_path="link-preview")
    def link_preview(self, request):
        raw_url = request.query_params.get("url", "")
        if not raw_url:
            raise ValidationError({"url": "This query parameter is required."})

        try:
            preview = self._extract_link_preview(raw_url)
        except requests.RequestException:
            return Response({"detail": "Unable to fetch link preview."}, status=status.HTTP_502_BAD_GATEWAY)

        return Response(preview, status=status.HTTP_200_OK)
    

    @action(detail=False, methods=["post"], url_path="seed")
    def create_seed(self, request):
        """
        POST /questions/seed/
        Create a seed (pre-arranged) question for an event. Host only.
        Seed questions are always approved and shown with a custom attribution label
        (e.g. "Event Team", "Dr. Smith") instead of the host's real name.
        An optional speaker_note is stored privately and returned only to the host.
        """
        from rest_framework.exceptions import PermissionDenied
        from events.models import Event

        event_id = request.data.get("event")
        if not event_id:
            return Response({"detail": "event is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            event = Event.objects.get(pk=event_id)
        except Event.DoesNotExist:
            return Response({"detail": "Event not found."}, status=status.HTTP_404_NOT_FOUND)

        is_host = (request.user == event.created_by or request.user.is_staff)
        if not is_host:
            raise PermissionDenied("Only event host/admin can create seed questions.")

        content = (request.data.get("content") or "").strip()
        if not content:
            return Response({"detail": "content is required."}, status=status.HTTP_400_BAD_REQUEST)

        attribution_label = (request.data.get("attribution_label") or "").strip()
        speaker_note = (request.data.get("speaker_note") or "").strip()

        # Assign display_order at the end of the current list
        count = Question.objects.filter(event_id=event_id, lounge_table__isnull=True).count()

        question = Question.objects.create(
            event=event,
            user=request.user,
            content=content,
            is_seed=True,
            attribution_label=attribution_label,
            speaker_note=speaker_note,
            moderation_status="approved",  # Seed questions skip moderation
            display_order=count,
        )

        # Broadcast to main room WebSocket group so live attendees see it immediately
        channel_layer = get_channel_layer()
        group = f"event_qna_{event.id}_main"
        display_name = attribution_label or "Event Team"

        ws_payload = {
            "type": "qna.question",
            "event_id": event.id,
            "lounge_table_id": None,
            "question_id": question.id,
            "user_id": request.user.id,
            "uid": request.user.id,
            "user": display_name,
            "user_name": display_name,
            "user_avatar_url": "",
            "content": question.content,
            "upvote_count": 0,
            "created_at": question.created_at.isoformat(),
            "moderation_status": "approved",
            "is_anonymous": False,
            "display_order": question.display_order,
            "is_seed": True,
            "attribution_label": attribution_label,
        }
        async_to_sync(channel_layer.group_send)(
            group,
            {"type": "qna.question", "payload": ws_payload},
        )

        return Response({
            "id": question.id,
            "content": question.content,
            "event_id": question.event_id,
            "is_seed": True,
            "attribution_label": question.attribution_label,
            "speaker_note": question.speaker_note,
            "moderation_status": "approved",
            "upvote_count": 0,
            "user_name": display_name,
            "is_pinned": False,
            "is_answered": False,
            "is_hidden": False,
            "display_order": question.display_order,
            "created_at": question.created_at.isoformat(),
        }, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["patch"], url_path="seed")
    def update_seed(self, request, pk=None):
        """
        PATCH /questions/{id}/seed/
        Update content, attribution_label, or speaker_note of a seed question. Host only.
        """
        from rest_framework.exceptions import PermissionDenied

        question = get_object_or_404(Question, pk=pk)
        if not question.is_seed:
            return Response({"detail": "This question is not a seed question."}, status=status.HTTP_400_BAD_REQUEST)

        is_host = (request.user == question.event.created_by or request.user.is_staff)
        if not is_host:
            raise PermissionDenied("Only event host/admin can edit seed questions.")

        if "content" in request.data:
            content = (request.data["content"] or "").strip()
            if content:
                question.content = content

        if "attribution_label" in request.data:
            question.attribution_label = (request.data["attribution_label"] or "").strip()

        if "speaker_note" in request.data:
            question.speaker_note = (request.data["speaker_note"] or "").strip()

        question.save(update_fields=["content", "attribution_label", "speaker_note"])

        return Response({
            "id": question.id,
            "content": question.content,
            "attribution_label": question.attribution_label,
            "speaker_note": question.speaker_note,
        }, status=status.HTTP_200_OK)

    # ------------------------------------------------------------------
    # AI draft polish
    # ------------------------------------------------------------------

    @action(
        detail=False,
        methods=["post"],
        url_path="polish-draft",
        throttle_classes=[PolishQuestionRateThrottle],
    )
    def polish_draft(self, request):
        """
        POST /api/interactions/questions/polish-draft/

        Accepts a rough question draft and returns an AI-improved version.
        Does NOT create, update, or persist any Question object.
        Does NOT broadcast over WebSocket.

        Request body:
            { "event_id": 123, "content": "rough question text" }

        Response (200):
            { "original": "...", "improved": "...", "changed": true }

        Errors:
            400 — validation failure
            503 — AI unavailable
        """
        from events.models import Event
        from .ai_question_polish import polish_question

        event_id = request.data.get("event_id")
        content = (request.data.get("content") or "").strip()

        # ── validation ──────────────────────────────────────────────────────────
        if not event_id:
            return Response(
                {"detail": "event_id is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not content:
            return Response(
                {"detail": "content is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if len(content) < 5:
            return Response(
                {"detail": "content must be at least 5 characters."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if len(content) > 1000:
            return Response(
                {"detail": "content must be at most 1000 characters."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ── event access check ───────────────────────────────────────────────────
        event = get_object_or_404(Event, id=event_id)  # 404 if event not found

        # Guests can only polish if they have a valid guest session for this event
        user = request.user
        if self._is_guest_user(user):
            guest = getattr(user, "guest", None)
            if not guest or guest.event_id != event.id:
                return Response(
                    {"detail": "You do not have access to this event's Q&A."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        # ── call AI service ──────────────────────────────────────────────────────
        try:
            improved = polish_question(content)
        except ValueError as exc:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning("polish_draft AI failure: %s", exc)
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


        return Response(
            {
                "original": content,
                "improved": improved,
                "changed": improved != content,
            },
            status=status.HTTP_200_OK,
        )

    # ------------------------------------------------------------------
    # A2: Private AI question suggestions
    # ------------------------------------------------------------------

    @action(
        detail=False,
        methods=["post"],
        url_path="ai-suggestions",
        throttle_classes=[AiSuggestionsRateThrottle],
    )
    def ai_suggestions(self, request):
        """
        POST /api/interactions/questions/ai-suggestions/

        Privately suggest 2–3 questions an attendee might want to ask,
        grounded in the event's presentation context.

        Request body:
            {
              "event_id": 123,
              "session_id": 456,       # optional
              "current_topic": "...",  # optional
              "count": 3               # max 3
            }

        Response (200):
            {
              "suggestions": [
                { "id": "uuid", "question": "...", "reason": "..." }
              ]
            }

        Rules:
            - Suggestions are private — no WebSocket broadcast.
            - No Question record is created.
            - Returns 404 if no context exists for the event.
            - Rate-limited via AiSuggestionsRateThrottle.
        """
        from events.models import Event
        from .ai_question_suggestions import suggest_questions

        event_id = request.data.get("event_id")
        session_id = request.data.get("session_id")
        count = request.data.get("count", 3)

        # ── validation ──────────────────────────────────────────────────────
        if not event_id:
            return Response(
                {"detail": "event_id is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            count = max(1, min(3, int(count)))
        except (TypeError, ValueError):
            count = 3

        # ── event access check ───────────────────────────────────────────────
        event = get_object_or_404(Event, id=event_id)

        user = request.user
        if self._is_guest_user(user):
            guest = getattr(user, "guest", None)
            if not guest or guest.event_id != event.id:
                return Response(
                    {"detail": "You do not have access to this event's Q&A."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        # ── load presentation context ────────────────────────────────────────
        context_qs = QnAContentContext.objects.filter(event=event)
        if session_id:
            context_qs = context_qs.filter(
                Q(session_id=session_id) | Q(session__isnull=True)
            )

        contexts = list(context_qs.order_by("-created_at"))
        if not contexts:
            return Response(
                {"detail": "No presentation context available for this event."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Concatenate context records (newest first, up to 4000 chars total)
        context_parts = []
        for ctx in contexts:
            label = ctx.source_title or ctx.get_source_type_display()
            context_parts.append(f"[{label}]\n{ctx.content_text}")
        combined_context = "\n\n".join(context_parts)

        session_title = ""
        if session_id:
            try:
                from events.models import EventSession
                session_obj = EventSession.objects.get(pk=session_id, event=event)
                session_title = session_obj.title or ""
            except Exception:
                pass

        # ── call AI service ──────────────────────────────────────────────────
        try:
            suggestions = suggest_questions(
                event_title=event.title or "",
                session_title=session_title,
                context_text=combined_context,
                count=count,
            )
        except ValueError:
            return Response(
                {"detail": "Could not generate suggestions right now. Please try again."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        # Suggestions are ephemeral — no Question record created, no WS broadcast.
        return Response({"suggestions": suggestions}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def upvote(self, request, pk=None):
        """
        Toggle upvote for a question. Broadcast the new count to the WebSocket group
        so everyone sees it update in real time. Also broadcast group updates if question
        is part of a question group.
        """
        question = get_object_or_404(Question, pk=pk)
        user = request.user

        if self._is_guest_user(user):
            guest = getattr(user, "guest", None)
            if not guest:
                return Response({"detail": "Invalid guest session."}, status=status.HTTP_401_UNAUTHORIZED)

            link = QuestionGuestUpvote.objects.filter(question=question, guest=guest)
            if link.exists():
                link.delete()
                upvoted = False
            else:
                QuestionGuestUpvote.objects.create(question=question, guest=guest)
                upvoted = True
            actor_id = f"guest_{guest.id}"
        else:
            # Toggle
            if question.upvoters.filter(id=user.id).exists():
                question.upvoters.remove(user)
                upvoted = False
            else:
                question.upvoters.add(user)
                upvoted = True
            actor_id = user.id

        upvote_count = (
            QuestionUpvote.objects.filter(question=question).count()
            + QuestionGuestUpvote.objects.filter(question=question).count()
        )

        # 🔊 Broadcast to the same Channels group used by QnAConsumer
        # QnA group name shape: event_qna_{event_id}_table_{table_id} OR event_qna_{event_id}_main
        if question.lounge_table_id:
            group = f"event_qna_{question.event_id}_table_{question.lounge_table_id}"
        else:
            group = f"event_qna_{question.event_id}_main"

        channel_layer = get_channel_layer()
        payload = {
            "type": "qna.upvote",
            "event_id": question.event_id,
            "question_id": question.id,
            "upvote_count": upvote_count,
            "upvoted": upvoted,
            "user_id": actor_id,
        }
        async_to_sync(channel_layer.group_send)(
            group, {"type": "qna.upvote", "payload": payload}
        )

        # 🔊 If this question is part of a question group, also broadcast the updated group vote count
        if question.grouped_answer_parent:
            parent_group = question.grouped_answer_parent
            group_vote_count = sum(
                m.question.upvote_count()
                for m in parent_group.memberships.select_related("question").all()
            )
            group_payload = {
                "type": "qna.group_upvote",
                "event_id": question.event_id,
                "group_id": parent_group.id,
                "group_vote_count": group_vote_count,
            }
            async_to_sync(channel_layer.group_send)(
                group, {"type": "qna.group_upvote", "payload": group_payload}
            )

        return Response(
            {
                "question_id": question.id,
                "upvoted": upvoted,
                "upvote_count": upvote_count,
            },
            status=status.HTTP_200_OK,
        )
        
    @action(detail=True, methods=["get"])
    def upvoters(self, request, pk=None):
        """
        GET /questions/{id}/upvoters/
        Returns list of users who upvoted this question
        """
        question = get_object_or_404(Question, pk=pk)
        upvoters = question.upvoters.all().values('id', 'username', 'first_name', 'last_name')
        guest_upvoters = question.guest_upvotes.select_related("guest").values(
            "guest_id", "guest__first_name", "guest__last_name", "guest__email"
        )
        upvoters_list = [
            {
                'id': u['id'],
                'name': f"{u.get('first_name', '')} {u.get('last_name', '')}".strip() or u.get('username', f"User {u['id']}"),
                'username': u.get('username', ''),
            }
            for u in upvoters
        ] + [
            {
                "id": f"guest_{g['guest_id']}",
                "name": (
                    f"{(g.get('guest__first_name') or '').strip()} {(g.get('guest__last_name') or '').strip()}".strip()
                    or (g.get("guest__email", "").split("@")[0] if g.get("guest__email") else f"Guest {g['guest_id']}")
                ),
                "username": f"guest_{g['guest_id']}",
            }
            for g in guest_upvoters
        ]
        return Response({
            "question_id": question.id,
            "upvote_count": question.upvoters.count() + question.guest_upvotes.count(),
            "upvoters": upvoters_list
        })

    @action(detail=True, methods=["post"])
    def toggle_visibility(self, request, pk=None):
        """
        PATCH /questions/{id}/toggle_visibility/
        Toggle whether a question is hidden from attendees.
        Permission: Host/Admin only (event.created_by or is_staff).
        Broadcast: 'qna.visibility_change'
        """
        from django.utils import timezone
        from rest_framework.exceptions import PermissionDenied

        question = get_object_or_404(Question, pk=pk)
        user = request.user

        # Permission check: Only host/admin can hide/unhide
        is_host = (user == question.event.created_by or user.is_staff)

        if not is_host:
            raise PermissionDenied("Only event host/admin can toggle question visibility.")

        # Toggle visibility
        question.is_hidden = not question.is_hidden
        if question.is_hidden:
            question.hidden_by = user
            question.hidden_at = timezone.now()
        else:
            question.hidden_by = None
            question.hidden_at = None

        question.save(update_fields=["is_hidden", "hidden_by", "hidden_at"])

        # Broadcast visibility change to WebSocket group
        if question.lounge_table_id:
            group = f"event_qna_{question.event_id}_table_{question.lounge_table_id}"
        else:
            group = f"event_qna_{question.event_id}_main"

        channel_layer = get_channel_layer()

        payload = {
            "type": "qna.visibility_change",
            "event_id": question.event_id,
            "question_id": question.id,
            "is_hidden": question.is_hidden,
            "hidden_by": user.id if question.is_hidden else None,
            "hidden_at": question.hidden_at.isoformat() if question.hidden_at else None,
        }

        async_to_sync(channel_layer.group_send)(
            group,
            {"type": "qna.visibility_change", "payload": payload},
        )

        # Return updated question
        serializer = self.get_serializer(question)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        """
        Host approves a pending question → visible to all attendees.
        Broadcasts qna.approved so attendees can render it.
        Permission: Host/Admin only.
        """
        from rest_framework.exceptions import PermissionDenied
        from django.utils import timezone

        question = get_object_or_404(Question, pk=pk)
        user = request.user

        # Permission check: Only host/admin can approve
        is_host = (user == question.event.created_by or user.is_staff)
        if not is_host:
            raise PermissionDenied("Only event host/admin can approve questions.")

        # Update status
        question.moderation_status = "approved"
        question.save(update_fields=["moderation_status"])

        # Determine broadcast group
        if question.lounge_table_id:
            group = f"event_qna_{question.event_id}_table_{question.lounge_table_id}"
        else:
            group = f"event_qna_{question.event_id}_main"

        channel_layer = get_channel_layer()

        asker_snapshot = self._get_question_asker_snapshot(question, reveal_anonymous_name=True)

        payload = {
            "type": "qna.approved",
            "event_id": question.event_id,
            "question_id": question.id,
            "content": question.content,
            "user_id": asker_snapshot["asker_id"],
            "user_name": asker_snapshot["asker_name"],
            "user_avatar_url": asker_snapshot["asker_avatar_url"],
            "upvote_count": question.upvoters.count() + question.guest_upvotes.count(),
            "created_at": question.created_at.isoformat(),
        }

        async_to_sync(channel_layer.group_send)(
            group,
            {"type": "qna.approved", "payload": payload},
        )

        serializer = self.get_serializer(question)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def reject(self, request, pk=None):
        """
        Host rejects a question (removed from queue, optionally with reason).
        Broadcasts qna.rejected so queue is updated.
        Permission: Host/Admin only.
        """
        from rest_framework.exceptions import PermissionDenied

        question = get_object_or_404(Question, pk=pk)
        user = request.user

        # Permission check: Only host/admin can reject
        is_host = (user == question.event.created_by or user.is_staff)
        if not is_host:
            raise PermissionDenied("Only event host/admin can reject questions.")

        # Get reason from request if provided
        reason = request.data.get("reason", "")

        # Update status
        question.moderation_status = "rejected"
        question.rejection_reason = reason
        question.save(update_fields=["moderation_status", "rejection_reason"])

        # Determine broadcast group
        if question.lounge_table_id:
            group = f"event_qna_{question.event_id}_table_{question.lounge_table_id}"
        else:
            group = f"event_qna_{question.event_id}_main"

        channel_layer = get_channel_layer()

        payload = {
            "type": "qna.rejected",
            "event_id": question.event_id,
            "question_id": question.id,
            "reason": reason,
        }

        async_to_sync(channel_layer.group_send)(
            group,
            {"type": "qna.rejected", "payload": payload},
        )

        serializer = self.get_serializer(question)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def mark_answered(self, request, pk=None):
        """
        Toggle answered status for a question. Host only.

        Request body (optional):
        {
            "answer_text": "Optional answer text to provide during live session (max 5000 chars)",
            "requires_followup": true/false (optional)
        }

        If answer_text is provided, sets answered_phase="live" and stores the answer text.
        Broadcasts qna.answered with full question state when status changes.

        Returns: Updated question with all fields.
        """
        from django.utils import timezone
        from rest_framework.exceptions import PermissionDenied

        question = get_object_or_404(Question, pk=pk)
        user = request.user

        # Permission check: Only host/admin can mark answered
        is_host = (user == question.event.created_by or user.is_staff)
        if not is_host:
            raise PermissionDenied("Only event host/admin can mark questions as answered.")

        # Validate request data
        serializer = MarkAnsweredSerializer(data=request.data)
        if not serializer.is_valid():
            print(f"[DEBUG] MarkAnsweredSerializer errors: {serializer.errors}")
            serializer.is_valid(raise_exception=True)

        print(f"[DEBUG] mark_answered called - answer_text: {serializer.validated_data.get('answer_text')}")

        # Toggle answered status
        question.is_answered = not question.is_answered
        update_fields = ["is_answered", "answered_by", "answered_at", "requires_followup"]

        if question.is_answered:
            question.answered_by = user
            question.answered_at = timezone.now()

            # Handle optional answer_text (for live answers)
            answer_text = serializer.validated_data.get("answer_text", "").strip()
            print(f"[DEBUG] answer_text after strip: '{answer_text}' (length: {len(answer_text)})")
            if answer_text:
                question.answer_text = answer_text
                question.answered_phase = "live"
                update_fields.extend(["answer_text", "answered_phase"])
                print(f"[DEBUG] Setting answer_text on question - will update fields: {update_fields}")
        else:
            question.answered_by = None
            question.answered_at = None

        # Handle requires_followup flag
        requires_followup = serializer.validated_data.get("requires_followup", question.requires_followup)
        question.requires_followup = requires_followup

        question.save(update_fields=update_fields)
        print(f"[DEBUG] Question saved - is_answered: {question.is_answered}, answer_text: {question.answer_text}, answered_phase: {question.answered_phase}")

        # Verify by re-fetching from database
        fresh_question = Question.objects.get(pk=question.pk)
        print(f"[DEBUG] Fresh from DB - answer_text: {fresh_question.answer_text}, answered_phase: {fresh_question.answered_phase}")

        # Broadcast to WebSocket group
        if question.lounge_table_id:
            group = f"event_qna_{question.event_id}_table_{question.lounge_table_id}"
        else:
            group = f"event_qna_{question.event_id}_main"

        channel_layer = get_channel_layer()

        payload = {
            "type": "qna.answered",
            "event_id": question.event_id,
            "question_id": question.id,
            "is_answered": question.is_answered,
            "answered_at": question.answered_at.isoformat() if question.answered_at else None,
            "answered_by": question.answered_by_id,
            "answer_text": question.answer_text,
            "answered_phase": question.answered_phase,
            "requires_followup": question.requires_followup,
        }

        async_to_sync(channel_layer.group_send)(
            group,
            {"type": "qna.answered", "payload": payload},
        )

        serializer = self.get_serializer(question)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def pin(self, request, pk=None):
        """
        Toggle pin status for a question. Host only.
        Auto-unpins the oldest question when a 4th is pinned.
        Broadcasts qna.pinned when status changes.
        """
        from django.utils import timezone
        from rest_framework.exceptions import PermissionDenied

        question = get_object_or_404(Question, pk=pk)
        user = request.user

        # Permission check: Only host/admin can pin questions
        is_host = (user == question.event.created_by or user.is_staff)
        if not is_host:
            raise PermissionDenied("Only event host/admin can pin questions.")

        unpinned_id = None

        # Toggle pin status
        if question.is_pinned:
            # Unpin
            question.is_pinned = False
            question.pinned_by = None
            question.pinned_at = None
        else:
            # Check if already 3 pinned questions - auto-unpin oldest if so
            pinned_count = Question.objects.filter(
                event=question.event, is_pinned=True
            ).count()

            if pinned_count >= 3:
                # Get oldest pinned question and unpin it
                oldest_pinned = Question.objects.filter(
                    event=question.event, is_pinned=True
                ).order_by("pinned_at").first()

                if oldest_pinned:
                    oldest_pinned.is_pinned = False
                    oldest_pinned.pinned_by = None
                    oldest_pinned.pinned_at = None
                    oldest_pinned.save(update_fields=["is_pinned", "pinned_by", "pinned_at"])
                    unpinned_id = oldest_pinned.id

            # Pin the current question
            question.is_pinned = True
            question.pinned_by = user
            question.pinned_at = timezone.now()

        question.save(update_fields=["is_pinned", "pinned_by", "pinned_at"])

        # Broadcast to WebSocket group
        if question.lounge_table_id:
            group = f"event_qna_{question.event_id}_table_{question.lounge_table_id}"
        else:
            group = f"event_qna_{question.event_id}_main"

        channel_layer = get_channel_layer()

        payload = {
            "type": "qna.pinned",
            "event_id": question.event_id,
            "question_id": question.id,
            "is_pinned": question.is_pinned,
            "pinned_at": question.pinned_at.isoformat() if question.pinned_at else None,
            "unpinned_question_id": unpinned_id,
        }

        async_to_sync(channel_layer.group_send)(
            group,
            {"type": "qna.pinned", "payload": payload},
        )

        return Response(
            {"question_id": question.id, "is_pinned": question.is_pinned},
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=["post"])
    def anonymize(self, request, pk=None):
        """
        Toggle anonymous status for a question. Host only.
        Broadcasts qna.anonymized when status changes.
        """
        from rest_framework.exceptions import PermissionDenied

        question = get_object_or_404(Question, pk=pk)
        user = request.user

        # Permission check: Only host/admin can anonymize questions
        is_host = (user == question.event.created_by or user.is_staff)
        if not is_host:
            raise PermissionDenied("Only event host/admin can anonymize questions.")

        # Toggle anonymous status
        question.is_anonymous = not question.is_anonymous
        question.anonymized_by = user if question.is_anonymous else None
        question.save(update_fields=["is_anonymous", "anonymized_by"])

        # Broadcast to WebSocket group
        if question.lounge_table_id:
            group = f"event_qna_{question.event_id}_table_{question.lounge_table_id}"
        else:
            group = f"event_qna_{question.event_id}_main"

        channel_layer = get_channel_layer()

        payload = {
            "type": "qna.anonymized",
            "event_id": question.event_id,
            "question_id": question.id,
            "is_anonymous": question.is_anonymous,
        }

        async_to_sync(channel_layer.group_send)(
            group,
            {"type": "qna.anonymized", "payload": payload},
        )

        return Response(
            {"question_id": question.id, "is_anonymous": question.is_anonymous},
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=["patch"])
    def reorder(self, request, pk=None):
        """
        Update display_order for manual host reorder. Host only.
        """
        from rest_framework.exceptions import PermissionDenied

        question = get_object_or_404(Question, pk=pk)
        if request.user != question.event.created_by and not request.user.is_staff:
            raise PermissionDenied("Only event host/admin can reorder questions.")

        new_order = request.data.get("display_order")
        if new_order is None:
            return Response({"detail": "display_order is required."}, status=status.HTTP_400_BAD_REQUEST)

        question.display_order = int(new_order)
        question.save(update_fields=["display_order"])
        return Response(
            {"question_id": question.id, "display_order": question.display_order},
            status=status.HTTP_200_OK
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Post-Event Q&A Answer Feature
    # ──────────────────────────────────────────────────────────────────────────

    @action(detail=False, methods=["get"], url_path="unanswered")
    def unanswered(self, request):
        """
        GET /api/interactions/questions/unanswered/?event_id=<id>
        List all unanswered questions for an event. Host/staff only.
        Returns questions ordered by upvote count (descending).
        """
        from rest_framework.exceptions import PermissionDenied
        from events.models import Event

        event_id = request.query_params.get("event_id")
        if not event_id:
            return Response(
                {"detail": "event_id query parameter is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            event = Event.objects.get(pk=event_id)
        except Event.DoesNotExist:
            return Response({"detail": "Event not found."}, status=status.HTTP_404_NOT_FOUND)

        # Permission check
        user = request.user
        is_host = (user == event.created_by or user.is_staff)
        if not is_host:
            raise PermissionDenied("Only event host/admin can access unanswered questions.")

        # Get unanswered questions, ordered by upvote count (descending)
        questions = (
            Question.objects
            .filter(event=event, is_answered=False)
            .annotate(upvote_count=Count("upvoters") + Count("guest_upvotes"))
            .order_by("-upvote_count", "-created_at")
            .select_related("user", "guest_asker")
            .prefetch_related("upvoters", "guest_upvotes")
        )

        serializer = self.get_serializer(questions, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"], url_path="post_event_answered")
    def post_event_answered(self, request):
        """
        GET /api/interactions/questions/post_event_answered/?event_id=<id>
        List all questions answered in post-event phase. Host/staff only.
        """
        from rest_framework.exceptions import PermissionDenied
        from events.models import Event

        event_id = request.query_params.get("event_id")
        if not event_id:
            return Response(
                {"detail": "event_id query parameter is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            event = Event.objects.get(pk=event_id)
        except Event.DoesNotExist:
            return Response({"detail": "Event not found."}, status=status.HTTP_404_NOT_FOUND)

        # Permission check
        user = request.user
        is_host = (user == event.created_by or user.is_staff)
        if not is_host:
            raise PermissionDenied("Only event host/admin can access post-event answered questions.")

        # Get post-event answered questions
        questions = (
            Question.objects
            .filter(event=event, answered_phase="post_event")
            .select_related("user", "guest_asker", "answered_by")
            .prefetch_related("upvoters", "guest_upvotes")
            .order_by("-answered_at")
        )

        serializer = self.get_serializer(questions, many=True)
        return Response(serializer.data)

    # ──────────────────────────────────────────────────────────────────────────
    # Pre-Event Q&A Management (Attendee-Owned)
    # ──────────────────────────────────────────────────────────────────────────

    @action(detail=False, methods=["get"], url_path="my-pre-event")
    def my_pre_event_questions(self, request):
        """
        GET /api/interactions/questions/my-pre-event/?event_id=<id>

        Returns all non-deleted pre-event questions submitted by the currently
        authenticated user for the given event.

        Only available to authenticated (non-guest) users.

        Response fields per question:
          id, content, created_at, updated_at, moderation_status,
          is_anonymous, submission_phase, is_deleted
        """
        from events.models import Event

        event_id = request.query_params.get("event_id")
        if not event_id:
            return Response(
                {"detail": "event_id query parameter is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = request.user
        if self._is_guest_user(user):
            return Response(
                {"detail": "Guest users cannot manage pre-event questions."},
                status=status.HTTP_403_FORBIDDEN,
            )

        event = get_object_or_404(Event, id=event_id)

        # Verify the user is registered
        registration = self._get_active_registration(user, event)
        if not registration:
            return Response(
                {"detail": "You are not registered for this event."},
                status=status.HTTP_403_FORBIDDEN,
            )

        questions = (
            Question.objects
            .filter(
                event=event,
                user=user,
                submission_phase="pre_event",
                is_deleted=False,
            )
            .order_by("-created_at")
        )

        data = [
            {
                "id": q.id,
                "content": q.content,
                "created_at": q.created_at.isoformat(),
                "updated_at": q.updated_at.isoformat(),
                "moderation_status": q.moderation_status,
                "is_anonymous": q.is_anonymous,
                "submission_phase": q.submission_phase,
                "is_answered": q.is_answered,
                "is_hidden": q.is_hidden,
            }
            for q in questions
        ]
        return Response(data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["patch"], url_path="pre-event-edit")
    def pre_event_edit(self, request, pk=None):
        """
        PATCH /api/interactions/questions/{id}/pre-event-edit/

        Allows an attendee to edit their own pre-event question before the
        event starts.

        Body (all optional):
          { "content": "new text", "is_anonymous": true/false }

        Enforcement rules (all checked server-side):
          - Must be authenticated (non-guest).
          - Must be the owner of the question (question.user == request.user).
          - question.submission_phase must be "pre_event".
          - question must not be soft-deleted.
          - Event must not have started yet (timezone.now() < event.start_time).

        Moderation:
          - If event.qna_moderation_enabled, editing resets moderation_status
            to "pending" so the host re-reviews the updated content.
          - If moderation is disabled, moderation_status remains unchanged.
        """
        from django.utils import timezone
        from rest_framework.exceptions import PermissionDenied

        question = get_object_or_404(Question, pk=pk)
        user = request.user

        if self._is_guest_user(user):
            return Response(
                {"detail": "Guest users cannot edit pre-event questions."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Ownership check
        if question.user_id != user.id:
            raise PermissionDenied("You can only edit your own questions.")

        # Phase check
        if question.submission_phase != "pre_event":
            return Response(
                {"detail": "Only pre-event questions can be edited through this endpoint."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Soft-delete check
        if question.is_deleted:
            return Response(
                {"detail": "This question has been deleted."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Time-gate: block editing after event has started
        event = question.event
        if event.start_time and timezone.now() >= event.start_time:
            return Response(
                {"detail": "The event has already started. Pre-event questions can no longer be edited."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Apply updates
        update_fields = ["updated_at"]

        new_content = (request.data.get("content") or "").strip()
        if new_content:
            if len(new_content) < 5:
                return Response(
                    {"detail": "Question must be at least 5 characters."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if len(new_content) > 1000:
                return Response(
                    {"detail": "Question must be at most 1000 characters."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            question.content = new_content
            update_fields.append("content")

        if "is_anonymous" in request.data:
            # Respect event-level anonymous override
            if event.qna_anonymous_mode:
                # Force anonymous — attendee cannot turn it off
                question.is_anonymous = True
            else:
                question.is_anonymous = bool(request.data["is_anonymous"])
            update_fields.append("is_anonymous")

        # Reset moderation if event has moderation enabled
        if event.qna_moderation_enabled and "content" in update_fields:
            question.moderation_status = "pending"
            update_fields.append("moderation_status")

        question.save(update_fields=update_fields)

        return Response(
            {
                "id": question.id,
                "content": question.content,
                "moderation_status": question.moderation_status,
                "is_anonymous": question.is_anonymous,
                "updated_at": question.updated_at.isoformat(),
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["delete"], url_path="pre-event-delete")
    def pre_event_delete(self, request, pk=None):
        """
        DELETE /api/interactions/questions/{id}/pre-event-delete/

        Soft-deletes an attendee's own pre-event question before the event starts.

        Enforcement rules (server-side):
          - Must be authenticated (non-guest).
          - Must be the owner.
          - submission_phase must be "pre_event".
          - Must not already be deleted.
          - Event must not have started.

        No WebSocket broadcast is sent because the question was never in the
        live Q&A stream.  Returns 204 No Content on success.
        """
        from django.utils import timezone
        from rest_framework.exceptions import PermissionDenied

        question = get_object_or_404(Question, pk=pk)
        user = request.user

        if self._is_guest_user(user):
            return Response(
                {"detail": "Guest users cannot delete pre-event questions."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if question.user_id != user.id:
            raise PermissionDenied("You can only delete your own questions.")

        if question.submission_phase != "pre_event":
            return Response(
                {"detail": "Only pre-event questions can be deleted through this endpoint."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if question.is_deleted:
            return Response(
                {"detail": "This question has already been deleted."},
                status=status.HTTP_404_NOT_FOUND,
            )

        event = question.event
        if event.start_time and timezone.now() >= event.start_time:
            return Response(
                {"detail": "The event has already started. Pre-event questions can no longer be deleted."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Soft-delete
        question.is_deleted = True
        question.deleted_at = timezone.now()
        question.save(update_fields=["is_deleted", "deleted_at"])

        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=["post"], url_path="pre-event-duplicate-check",
            throttle_classes=[PolishQuestionRateThrottle])
    def pre_event_duplicate_check(self, request):
        """
        POST /api/interactions/questions/pre-event-duplicate-check/

        Checks whether a draft question is semantically similar to the user's
        existing pre-event questions for the same event.

        Request body:
            { "event_id": 123, "content": "draft text" }

        Response (200):
            {
              "duplicates": [
                {
                  "question_id": <int>,
                  "existing_text": "...",
                  "similarity_reason": "...",
                  "suggested_merge": "..." or null,
                  "suggestions": ["keep both", "edit existing", "replace existing", "cancel"]
                }
              ],
              "has_duplicates": <bool>
            }

        Safety rules:
          - Never auto-merges or modifies anything.
          - Returns 503 if the AI key is not configured.
          - Returns a safe empty result {"duplicates": [], "has_duplicates": false}
            on AI timeout/network error (soft failure) rather than crashing.
          - Private to the requesting attendee only.
        """
        from events.models import Event
        from .ai_pre_event_advisor import check_duplicate_questions

        event_id = request.data.get("event_id")
        content = (request.data.get("content") or "").strip()

        if not event_id:
            return Response(
                {"detail": "event_id is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not content:
            return Response(
                {"detail": "content is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if len(content) < 5:
            return Response(
                {"detail": "content must be at least 5 characters."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = request.user
        if self._is_guest_user(user):
            return Response(
                {"detail": "Guest users cannot use the duplicate checker."},
                status=status.HTTP_403_FORBIDDEN,
            )

        event = get_object_or_404(Event, id=event_id)

        # Load user's existing pre-event questions for this event
        existing_qs = (
            Question.objects
            .filter(
                event=event,
                user=user,
                submission_phase="pre_event",
                is_deleted=False,
            )
            .values("id", "content")
        )
        existing = list(existing_qs)

        if not existing:
            return Response(
                {"duplicates": [], "has_duplicates": False},
                status=status.HTTP_200_OK,
            )

        try:
            result = check_duplicate_questions(draft=content, existing_questions=existing)
        except ValueError as exc:
            # Configuration error (no API key)
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        return Response(result, status=status.HTTP_200_OK)


    @action(detail=True, methods=["post"], url_path="post_event_answer")
    def post_event_answer(self, request, pk=None):
        """
        POST /api/interactions/questions/{id}/post_event_answer/
        Publish a post-event answer to a question. Host/staff only.

        Body: {
            answer_text: string (required, max 5000 chars),
            notify_author: boolean (default true),
            notify_interested_participants: boolean (default true),
            notify_all_participants: boolean (default false)
        }

        Validates:
        - Event must be ended (status == "ended")
        - User must be host/staff
        - Question must belong to the event
        - If question already answered live, returns 409
        """
        from rest_framework.exceptions import PermissionDenied
        from .services.post_event_qna_service import (
            publish_post_event_answer,
            resolve_notification_recipients,
            send_answer_notifications,
        )

        question = get_object_or_404(Question, pk=pk)
        user = request.user

        # Permission check
        is_host = (user == question.event.created_by or user.is_staff)
        if not is_host:
            raise PermissionDenied("Only event host/admin can answer questions after event.")

        # Validate event is ended
        if question.event.status != "ended":
            return Response(
                {"detail": "Event must be ended before post-event answers can be published."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate question not already answered live
        if question.is_answered and question.answered_phase == "live":
            return Response(
                {"detail": "This question was already answered during the live event."},
                status=status.HTTP_409_CONFLICT
            )

        # Validate request body
        serializer = PostEventAnswerSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Publish answer
        answer_text = serializer.validated_data["answer_text"]
        notify_author = serializer.validated_data["notify_author"]
        notify_interested = serializer.validated_data["notify_interested_participants"]
        notify_all = serializer.validated_data["notify_all_participants"]

        publish_post_event_answer(question, answer_text, user)

        # Resolve and send notifications
        recipient_ids = resolve_notification_recipients(
            question=question,
            notify_author=notify_author,
            notify_interested=notify_interested,
            notify_all_participants=notify_all,
            answering_user=user,
        )
        if recipient_ids:
            send_answer_notifications(question, user, recipient_ids)

        serializer = self.get_serializer(question)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["post"], url_path="engagement-prompt/trigger")
    def engagement_prompt_trigger(self, request):
        """
        POST /interactions/questions/engagement-prompt/trigger/
        Host/moderator only.

        Creates a QnAEngagementPrompt for the given event and broadcasts
        a 'qna.engagement_prompt' websocket event to all attendees in the
        main room so they can call the ack endpoint.

        Body: { event_id, message?, auto_hide_seconds? }
        Returns: { prompt_id, event_id, message, auto_hide_seconds, created_at }
        """
        from rest_framework.exceptions import PermissionDenied
        from events.models import Event

        event_id = request.data.get("event_id")
        if not event_id:
            return Response({"detail": "event_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            event = Event.objects.get(pk=event_id)
        except Event.DoesNotExist:
            return Response({"detail": "Event not found."}, status=status.HTTP_404_NOT_FOUND)

        is_host = (request.user == event.created_by or getattr(request.user, "is_staff", False))
        if not is_host:
            raise PermissionDenied("Only event host/admin can send Q&A engagement prompts.")

        # Allow host to override message/auto_hide_seconds/prompt_type
        message = (
            (request.data.get("message") or "").strip()
            or "Have a question? Submit it in Q&A now."
        )
        try:
            auto_hide_seconds = int(request.data.get("auto_hide_seconds") or 10)
        except (TypeError, ValueError):
            auto_hide_seconds = 10

        prompt_type = request.data.get("prompt_type", "banner")
        if prompt_type not in ("banner", "modal"):
            return Response(
                {"detail": "prompt_type must be 'banner' or 'modal'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        prompt = QnAEngagementPrompt.objects.create(
            event=event,
            triggered_by=request.user,
            message=message,
            auto_hide_seconds=auto_hide_seconds,
            prompt_type=prompt_type,
        )

        # Broadcast to main room QnA group
        channel_layer = get_channel_layer()
        group = f"event_qna_{event.id}_main"
        ws_payload = {
            "type": "qna.engagement_prompt",
            "prompt_id": prompt.id,
            "event_id": event.id,
            "prompt_type": prompt.prompt_type,
            "created_at": prompt.created_at.isoformat(),
        }
        async_to_sync(channel_layer.group_send)(
            group,
            {"type": "qna.engagement_prompt", "payload": ws_payload},
        )

        return Response(
            {
                "prompt_id": prompt.id,
                "event_id": event.id,
                "message": prompt.message,
                "auto_hide_seconds": prompt.auto_hide_seconds,
                "prompt_type": prompt.prompt_type,
                "created_at": prompt.created_at.isoformat(),
            },
            status=status.HTTP_201_CREATED,
        )

    @action(detail=False, methods=["post"], url_path=r"engagement-prompt/(?P<prompt_id>[0-9]+)/ack")
    def engagement_prompt_ack(self, request, prompt_id=None):
        """
        POST /interactions/questions/engagement-prompt/{id}/ack/
        Attendee (auth or guest) acknowledges receiving a prompt.

        Checks whether this attendee has already reached QNA_PROMPT_MAX_PER_USER
        receipts for this event. If under cap, creates a receipt and returns
        show=true with banner payload. Otherwise returns show=false.

        Returns: { show, prompt_id, message, auto_hide_seconds, max_reached }
        """
        try:
            prompt = QnAEngagementPrompt.objects.select_related("event").get(pk=prompt_id)
        except QnAEngagementPrompt.DoesNotExist:
            return Response({"detail": "Prompt not found."}, status=status.HTTP_404_NOT_FOUND)

        user = request.user
        is_guest = self._is_guest_user(user)
        guest = getattr(user, "guest", None) if is_guest else None

        # Count existing receipts for this attendee in this event
        if is_guest and guest:
            shown_count = QnAEngagementPromptReceipt.objects.filter(
                event=prompt.event,
                guest=guest,
            ).count()
        else:
            shown_count = QnAEngagementPromptReceipt.objects.filter(
                event=prompt.event,
                user=user,
            ).count()

        if shown_count >= QNA_PROMPT_MAX_PER_USER:
            return Response(
                {
                    "show": False,
                    "prompt_id": prompt.id,
                    "message": prompt.message,
                    "auto_hide_seconds": prompt.auto_hide_seconds,
                    "prompt_type": prompt.prompt_type,
                    "max_reached": True,
                },
                status=status.HTTP_200_OK,
            )

        # Create the receipt (prompt will be shown)
        receipt_kwargs = {
            "prompt": prompt,
            "event": prompt.event,
        }
        if is_guest and guest:
            receipt_kwargs["guest"] = guest
        else:
            receipt_kwargs["user"] = user

        QnAEngagementPromptReceipt.objects.create(**receipt_kwargs)

        return Response(
            {
                "show": True,
                "prompt_id": prompt.id,
                "message": prompt.message,
                "auto_hide_seconds": prompt.auto_hide_seconds,
                "prompt_type": prompt.prompt_type,
                "max_reached": False,
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["post"], url_path=r"engagement-prompt/(?P<prompt_id>[0-9]+)/dismiss")
    def engagement_prompt_dismiss(self, request, prompt_id=None):
        """
        POST /interactions/questions/engagement-prompt/{id}/dismiss/
        Attendee (auth or guest) manually dismissed the banner.

        Finds the existing unacknowledged or shown receipt for this attendee
        and sets dismissed_at. Used for analytics and future tuning.

        Returns: { dismissed: true, prompt_id }
        """
        from django.utils import timezone as tz

        try:
            prompt = QnAEngagementPrompt.objects.get(pk=prompt_id)
        except QnAEngagementPrompt.DoesNotExist:
            return Response({"detail": "Prompt not found."}, status=status.HTTP_404_NOT_FOUND)

        user = request.user
        is_guest = self._is_guest_user(user)
        guest = getattr(user, "guest", None) if is_guest else None

        if is_guest and guest:
            receipt = QnAEngagementPromptReceipt.objects.filter(
                prompt=prompt, guest=guest, dismissed_at__isnull=True
            ).first()
        else:
            receipt = QnAEngagementPromptReceipt.objects.filter(
                prompt=prompt, user=user, dismissed_at__isnull=True
            ).first()

        if receipt:
            receipt.dismissed_at = tz.now()
            receipt.save(update_fields=["dismissed_at"])

        return Response(
            {"dismissed": True, "prompt_id": prompt.id},
            status=status.HTTP_200_OK,
        )

    def perform_update(self, serializer):

        """
        Update a question.
        Permission: Owner OR Host (event.created_by).
        Broadcast: 'qna.update'
        """
        instance = serializer.instance
        user = self.request.user
        
        # Permission check
        is_owner = (
            (not self._is_guest_user(user) and user == instance.user)
            or (self._is_guest_user(user) and instance.guest_asker_id == getattr(user.guest, "id", None))
        )
        is_host = (user == instance.event.created_by)
        
        if not (is_owner or is_host):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("You do not have permission to edit this question.")

        question = serializer.save()

        # Broadcast update
        if question.lounge_table_id:
            group = f"event_qna_{question.event_id}_table_{question.lounge_table_id}"
        else:
            group = f"event_qna_{question.event_id}_main"

        channel_layer = get_channel_layer()
        
        payload = {
            "type": "qna.update",
            "event_id": question.event_id,
            "question_id": question.id,
            "content": question.content,
        }
        
        async_to_sync(channel_layer.group_send)(
            group,
            {"type": "qna.question", "payload": payload}, 
        )

    def perform_destroy(self, instance):
        """
        Delete a question.
        Permission: Owner OR Host.
        Broadcast: 'qna.delete'
        """
        user = self.request.user
        event_id = instance.event_id
        q_id = instance.id
        
        # Permission check
        is_owner = (
            (not self._is_guest_user(user) and user == instance.user)
            or (self._is_guest_user(user) and instance.guest_asker_id == getattr(user.guest, "id", None))
        )
        is_host = (user == instance.event.created_by)
        
        if not (is_owner or is_host):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("You do not have permission to delete this question.")

        instance.delete()

        # Broadcast delete
        if instance.lounge_table_id:
            group = f"event_qna_{event_id}_table_{instance.lounge_table_id}"
        else:
            group = f"event_qna_{event_id}_main"

        channel_layer = get_channel_layer()

        payload = {
            "type": "qna.delete",
            "event_id": event_id,
            "question_id": q_id,
        }

        async_to_sync(channel_layer.group_send)(
            group,
            {"type": "qna.question", "payload": payload},
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Threaded Replies
    # GET  /api/interactions/questions/{id}/replies/   – list replies
    # POST /api/interactions/questions/{id}/replies/   – create reply
    # ──────────────────────────────────────────────────────────────────────────

    @action(detail=True, methods=["get", "post"], url_path="replies")
    def replies(self, request, pk=None):
        from events.models import Event

        question = get_object_or_404(
            Question.objects.select_related("event"),
            pk=pk,
        )
        event = question.event
        user = request.user
        is_host = (user == event.created_by or getattr(user, "is_staff", False))

        # ── GET: list replies ────────────────────────────────────────────────
        if request.method == "GET":
            replies_qs = (
                QnAReply.objects
                .filter(question=question)
                .select_related("user", "user__profile", "guest_asker")
                .prefetch_related("upvoters", "guest_upvotes")
                .order_by("created_at")
            )
            if not is_host:
                replies_qs = replies_qs.filter(is_hidden=False)
                if event.qna_moderation_enabled:
                    replies_qs = replies_qs.filter(moderation_status="approved")

            data = [
                self._serialize_reply(r, is_host=is_host, user=user)
                for r in replies_qs
            ]
            return Response(data, status=status.HTTP_200_OK)

        # ── POST: create reply ───────────────────────────────────────────────
        content = (request.data.get("content") or "").strip()
        if not content:
            return Response({"detail": "content is required."}, status=status.HTTP_400_BAD_REQUEST)

        is_anonymous = bool(request.data.get("is_anonymous", False))
        if event.qna_anonymous_mode:
            is_anonymous = True

        moderation_status = "pending" if event.qna_moderation_enabled else "approved"

        create_kwargs = dict(
            question=question,
            event=event,
            lounge_table=question.lounge_table,
            content=content,
            is_anonymous=is_anonymous,
            moderation_status=moderation_status,
        )
        if self._is_guest_user(user):
            guest = getattr(user, "guest", None)
            if not guest:
                return Response({"detail": "Invalid guest session."}, status=status.HTTP_401_UNAUTHORIZED)
            create_kwargs["guest_asker"] = guest
        else:
            create_kwargs["user"] = user

        reply = QnAReply.objects.create(**create_kwargs)

        # Broadcast new reply to Q&A group
        if question.lounge_table_id:
            group = f"event_qna_{event.id}_table_{question.lounge_table_id}"
        else:
            group = f"event_qna_{event.id}_main"

        author_snapshot = self._get_reply_author_snapshot(
            reply, reveal_anonymous_name=not reply.is_anonymous
        )

        channel_layer = get_channel_layer()
        ws_payload = {
            "type": "qna.reply",
            "event_id": event.id,
            "question_id": question.id,
            "reply_id": reply.id,
            "author_id": author_snapshot["author_id"],
            "author_name": author_snapshot["author_name"],
            "author_avatar_url": author_snapshot["author_avatar_url"],
            "content": reply.content,
            "upvote_count": 0,
            "created_at": reply.created_at.isoformat(),
            "moderation_status": reply.moderation_status,
            "is_anonymous": reply.is_anonymous,
        }
        async_to_sync(channel_layer.group_send)(
            group, {"type": "qna.reply", "payload": ws_payload}
        )

        return Response(ws_payload, status=status.HTTP_201_CREATED)

    # ──────────────────────────────────────────────────────────────────────────
    # Q&A Export  (host / staff only, event must be ended)
    # GET /api/interactions/questions/export/?event_id=<id>&format=csv|pdf
    # ──────────────────────────────────────────────────────────────────────────

    @action(detail=False, methods=["get"], url_path="export")
    def export(self, request):
        from rest_framework.exceptions import PermissionDenied, ValidationError
        from django.shortcuts import get_object_or_404
        from events.models import Event
        from .exporters import build_export_rows, generate_csv_response, generate_pdf_response

        # ── validate query params ─────────────────────────────────────────────
        event_id = request.query_params.get("event_id", "").strip()
        fmt = request.query_params.get("format", "").strip().lower()

        if not event_id:
            raise ValidationError({"event_id": "This parameter is required."})
        if fmt not in ("csv", "pdf"):
            raise ValidationError({"format": "Must be 'csv' or 'pdf'."})

        # ── load event ────────────────────────────────────────────────────────
        event = get_object_or_404(Event, pk=event_id)

        # ── permission: host or staff only ────────────────────────────────────
        user = request.user
        is_host = (not self._is_guest_user(user)) and (user == event.created_by)
        is_staff = (not self._is_guest_user(user)) and user.is_staff

        if not (is_host or is_staff):
            raise PermissionDenied("Only the event host or platform staff can export Q&A data.")

        # ── event must be ended ───────────────────────────────────────────────
        if event.status != "ended":
            from rest_framework.response import Response
            from rest_framework import status as http_status
            return Response(
                {"detail": "Q&A export is only available after the event has ended."},
                status=http_status.HTTP_403_FORBIDDEN,
            )

        # ── build normalised rows (shared by both formats) ────────────────────
        rows = build_export_rows(event)

        # ── generate response ─────────────────────────────────────────────────
        if fmt == "csv":
            return generate_csv_response(rows, event)

        exported_by = (
            (getattr(user, "get_full_name", lambda: "")() or "").strip()
            or user.username
            or user.email
            or f"User {user.pk}"
        )
        return generate_pdf_response(rows, event, exported_by=exported_by)


# ──────────────────────────────────────────────────────────────────────────────
# QnAReplyViewSet
# Handles individual reply operations:
#   PATCH  /api/interactions/replies/{id}/
#   DELETE /api/interactions/replies/{id}/
#   POST   /api/interactions/replies/{id}/upvote/
#   POST   /api/interactions/replies/{id}/approve/
#   POST   /api/interactions/replies/{id}/reject/
#   POST   /api/interactions/replies/{id}/anonymize/
# ──────────────────────────────────────────────────────────────────────────────

class QnAReplyViewSet(viewsets.GenericViewSet):
    """
    Individual reply CRUD + moderation operations.
    List/create lives on QuestionViewSet.replies action.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = QnAReplySerializer
    queryset = QnAReply.objects.select_related("question__event", "user", "guest_asker")

    @staticmethod
    def _is_guest_user(user) -> bool:
        return bool(getattr(user, "is_guest", False))

    def _is_host(self, reply, user) -> bool:
        return user == reply.event.created_by or getattr(user, "is_staff", False)

    def _is_owner(self, reply, user) -> bool:
        if self._is_guest_user(user):
            guest = getattr(user, "guest", None)
            return reply.guest_asker_id is not None and guest is not None and reply.guest_asker_id == guest.id
        return reply.user_id is not None and reply.user_id == user.id

    def _broadcast(self, reply, msg_type: str, payload: dict) -> None:
        if reply.question.lounge_table_id:
            group = f"event_qna_{reply.event_id}_table_{reply.question.lounge_table_id}"
        else:
            group = f"event_qna_{reply.event_id}_main"
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            group, {"type": msg_type, "payload": payload}
        )

    def partial_update(self, request, pk=None):
        """PATCH /api/interactions/replies/{id}/  – owner or host can edit content."""
        from rest_framework.exceptions import PermissionDenied

        reply = get_object_or_404(
            QnAReply.objects.select_related("question__event", "user", "guest_asker"),
            pk=pk,
        )
        user = request.user
        if not (self._is_owner(reply, user) or self._is_host(reply, user)):
            raise PermissionDenied("You do not have permission to edit this reply.")

        content = (request.data.get("content") or "").strip()
        if not content:
            return Response({"detail": "content is required."}, status=status.HTTP_400_BAD_REQUEST)

        reply.content = content
        reply.save(update_fields=["content", "updated_at"])

        self._broadcast(reply, "qna.reply_update", {
            "type": "qna.reply_update",
            "event_id": reply.event_id,
            "question_id": reply.question_id,
            "reply_id": reply.id,
            "content": reply.content,
        })

        return Response({"reply_id": reply.id, "content": reply.content}, status=status.HTTP_200_OK)

    def destroy(self, request, pk=None):
        """DELETE /api/interactions/replies/{id}/  – owner or host can delete."""
        from rest_framework.exceptions import PermissionDenied

        reply = get_object_or_404(
            QnAReply.objects.select_related("question__event", "user", "guest_asker"),
            pk=pk,
        )
        user = request.user
        if not (self._is_owner(reply, user) or self._is_host(reply, user)):
            raise PermissionDenied("You do not have permission to delete this reply.")

        event_id = reply.event_id
        question_id = reply.question_id
        reply_id = reply.id
        lounge_table_id = reply.question.lounge_table_id
        reply.delete()

        if lounge_table_id:
            group = f"event_qna_{event_id}_table_{lounge_table_id}"
        else:
            group = f"event_qna_{event_id}_main"
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            group,
            {"type": "qna.reply_delete", "payload": {
                "type": "qna.reply_delete",
                "event_id": event_id,
                "question_id": question_id,
                "reply_id": reply_id,
            }},
        )

        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=["post"])
    def upvote(self, request, pk=None):
        """POST /api/interactions/replies/{id}/upvote/ – toggle upvote."""
        reply = get_object_or_404(
            QnAReply.objects.select_related("question__event"),
            pk=pk,
        )
        user = request.user

        if self._is_guest_user(user):
            guest = getattr(user, "guest", None)
            if not guest:
                return Response({"detail": "Invalid guest session."}, status=status.HTTP_401_UNAUTHORIZED)
            link_qs = QnAReplyGuestUpvote.objects.filter(reply=reply, guest=guest)
            if link_qs.exists():
                link_qs.delete()
                upvoted = False
            else:
                QnAReplyGuestUpvote.objects.create(reply=reply, guest=guest)
                upvoted = True
            actor_id = f"guest_{guest.id}"
        else:
            if reply.upvoters.filter(id=user.id).exists():
                reply.upvoters.remove(user)
                upvoted = False
            else:
                reply.upvoters.add(user)
                upvoted = True
            actor_id = user.id

        upvote_count = (
            QnAReplyUpvote.objects.filter(reply=reply).count()
            + QnAReplyGuestUpvote.objects.filter(reply=reply).count()
        )

        self._broadcast(reply, "qna.reply_upvote", {
            "type": "qna.reply_upvote",
            "event_id": reply.event_id,
            "question_id": reply.question_id,
            "reply_id": reply.id,
            "upvote_count": upvote_count,
            "upvoted": upvoted,
            "user_id": actor_id,
        })

        return Response(
            {"reply_id": reply.id, "upvoted": upvoted, "upvote_count": upvote_count},
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        """POST /api/interactions/replies/{id}/approve/ – host approves a pending reply."""
        from rest_framework.exceptions import PermissionDenied

        reply = get_object_or_404(
            QnAReply.objects.select_related("question__event"),
            pk=pk,
        )
        if not self._is_host(reply, request.user):
            raise PermissionDenied("Only event host/admin can approve replies.")

        reply.moderation_status = "approved"
        reply.save(update_fields=["moderation_status"])

        self._broadcast(reply, "qna.reply_approved", {
            "type": "qna.reply_approved",
            "event_id": reply.event_id,
            "question_id": reply.question_id,
            "reply_id": reply.id,
            "content": reply.content,
        })

        return Response({"reply_id": reply.id, "moderation_status": "approved"}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def reject(self, request, pk=None):
        """POST /api/interactions/replies/{id}/reject/ – host rejects a reply."""
        from rest_framework.exceptions import PermissionDenied

        reply = get_object_or_404(
            QnAReply.objects.select_related("question__event"),
            pk=pk,
        )
        if not self._is_host(reply, request.user):
            raise PermissionDenied("Only event host/admin can reject replies.")

        reason = (request.data.get("reason") or "").strip()
        reply.moderation_status = "rejected"
        reply.rejection_reason = reason
        reply.save(update_fields=["moderation_status", "rejection_reason"])

        self._broadcast(reply, "qna.reply_rejected", {
            "type": "qna.reply_rejected",
            "event_id": reply.event_id,
            "question_id": reply.question_id,
            "reply_id": reply.id,
            "reason": reason,
        })

        return Response({"reply_id": reply.id, "moderation_status": "rejected", "reason": reason}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def anonymize(self, request, pk=None):
        """POST /api/interactions/replies/{id}/anonymize/ – host toggles anonymous."""
        from rest_framework.exceptions import PermissionDenied

        reply = get_object_or_404(
            QnAReply.objects.select_related("question__event"),
            pk=pk,
        )
        if not self._is_host(reply, request.user):
            raise PermissionDenied("Only event host/admin can anonymize replies.")

        reply.is_anonymous = not reply.is_anonymous
        reply.anonymized_by = request.user if reply.is_anonymous else None
        reply.save(update_fields=["is_anonymous", "anonymized_by"])

        self._broadcast(reply, "qna.reply_anonymized", {
            "type": "qna.reply_anonymized",
            "event_id": reply.event_id,
            "question_id": reply.question_id,
            "reply_id": reply.id,
            "is_anonymous": reply.is_anonymous,
        })

        return Response({"reply_id": reply.id, "is_anonymous": reply.is_anonymous}, status=status.HTTP_200_OK)


# ──────────────────────────────────────────────────────────────────────────────
# QnAQuestionGroupViewSet
# ──────────────────────────────────────────────────────────────────────────────

from .models import (
    QnAQuestionGroup,
    QnAQuestionGroupMembership,
    QnAQuestionGroupSuggestion,
)
from .serializers import (
    QnAQuestionGroupSerializer,
    QnAQuestionGroupSuggestionSerializer,
)

class QnAQuestionGroupViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = QnAQuestionGroupSerializer

    def get_queryset(self):
        if self.action in ["retrieve", "update", "partial_update", "destroy", "add_questions", "remove_questions", "reorder_questions"]:
            return QnAQuestionGroup.objects.all().prefetch_related("memberships")
            
        event_id = self.request.query_params.get("event_id")
        if not event_id:
            return QnAQuestionGroup.objects.none()
        return QnAQuestionGroup.objects.filter(event_id=event_id).prefetch_related("memberships")

    def perform_create(self, serializer):
        from rest_framework.exceptions import PermissionDenied, ValidationError
        from events.models import Event
        
        event_id = self.request.data.get('event')
        if not event_id:
            raise ValidationError("event is required")
            
        try:
            event = Event.objects.get(id=event_id)
        except Event.DoesNotExist:
            raise ValidationError("event not found")
            
        if not (self.request.user == event.created_by or getattr(self.request.user, "is_staff", False)):
            raise PermissionDenied("Only event host/admin can create groups.")
            
        group = serializer.save(event=event, created_by=self.request.user, source=QnAQuestionGroup.SOURCE_MANUAL)
        
        # Broadcast group_created
        channel_layer = get_channel_layer()
        group_name = f"event_qna_{group.event_id}_main"
        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "qna.group_created",
                "payload": {"type": "qna.group_created", "group": QnAQuestionGroupSerializer(group).data}
            }
        )

    def update(self, request, pk=None, *args, **kwargs):
        """Handle PATCH/PUT requests, including question_ids."""
        from rest_framework.exceptions import PermissionDenied
        import logging

        logger = logging.getLogger(__name__)
        group = self.get_object()

        if not (request.user == group.event.created_by or getattr(request.user, "is_staff", False)):
            raise PermissionDenied("Only event host/admin can update groups.")

        # Extract question_ids if provided
        question_ids = request.data.get("question_ids")

        # Update group fields (title, summary, etc.)
        serializer = self.get_serializer(group, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        updated_group = serializer.save()

        # Handle question_ids update
        if question_ids is not None:
            logger.info(f"[GROUP-EDIT] Updating group {group.id} with question_ids: {question_ids}")

            # Delete all existing memberships
            QnAQuestionGroupMembership.objects.filter(group=group).delete()

            # Create new memberships
            for q_id in question_ids:
                try:
                    QnAQuestionGroupMembership.objects.create(
                        group=group,
                        question_id=q_id,
                        added_by=request.user
                    )
                except Exception as e:
                    logger.error(f"[GROUP-EDIT] Error adding question {q_id}: {str(e)}")

            logger.info(f"[GROUP-EDIT] Successfully updated group {group.id} with {len(question_ids)} questions")

        # Broadcast group_updated
        channel_layer = get_channel_layer()
        group_name = f"event_qna_{updated_group.event_id}_main"
        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "qna.group_updated",
                "payload": {"type": "qna.group_updated", "group": QnAQuestionGroupSerializer(updated_group).data}
            }
        )

        return Response(QnAQuestionGroupSerializer(updated_group).data)

    def perform_update(self, serializer):
        """Deprecated - use update() instead."""
        from rest_framework.exceptions import PermissionDenied
        group = self.get_object()
        if not (self.request.user == group.event.created_by or getattr(self.request.user, "is_staff", False)):
            raise PermissionDenied("Only event host/admin can update groups.")
        serializer.save()

    def perform_destroy(self, instance):
        from rest_framework.exceptions import PermissionDenied
        if not (self.request.user == instance.event.created_by or getattr(self.request.user, "is_staff", False)):
            raise PermissionDenied("Only event host/admin can delete groups.")
        
        event_id = instance.event_id
        group_id = instance.id
        instance.delete()
        
        # Broadcast group_deleted
        channel_layer = get_channel_layer()
        group_name = f"event_qna_{event_id}_main"
        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "qna.group_deleted",
                "payload": {"type": "qna.group_deleted", "group_id": group_id, "event_id": event_id}
            }
        )

    @action(detail=True, methods=["post"])
    def add_questions(self, request, pk=None):
        group = self.get_object()
        question_ids = request.data.get("question_ids", [])
        
        added = []
        for q_id in question_ids:
            QnAQuestionGroupMembership.objects.filter(question_id=q_id).delete()
            mem = QnAQuestionGroupMembership.objects.create(
                group=group,
                question_id=q_id,
                added_by=request.user
            )
            added.append(q_id)
            
        # Broadcast
        channel_layer = get_channel_layer()
        group_name = f"event_qna_{group.event_id}_main"
        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "qna.group_membership_updated",
                "payload": {
                    "type": "qna.group_membership_updated", 
                    "group_id": group.id, 
                    "added": added,
                    "event_id": group.event_id
                }
            }
        )
        return Response({"status": "questions added"}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def remove_questions(self, request, pk=None):
        group = self.get_object()
        question_ids = request.data.get("question_ids", [])
        QnAQuestionGroupMembership.objects.filter(group=group, question_id__in=question_ids).delete()
        
        # Broadcast
        channel_layer = get_channel_layer()
        group_name = f"event_qna_{group.event_id}_main"
        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "qna.group_membership_updated",
                "payload": {
                    "type": "qna.group_membership_updated", 
                    "group_id": group.id, 
                    "removed": question_ids,
                    "event_id": group.event_id
                }
            }
        )
        return Response({"status": "questions removed"}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def reorder_questions(self, request, pk=None):
        group = self.get_object()
        # expect [{"question_id": 1, "display_order": 0}, ...]
        order_data = request.data.get("order", [])
        for item in order_data:
            QnAQuestionGroupMembership.objects.filter(group=group, question_id=item["question_id"]).update(display_order=item["display_order"])
        
        return Response({"status": "questions reordered"}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], url_path="ai-suggest")
    def ai_suggest(self, request):
        event_id = request.data.get("event_id")
        if not event_id:
            return Response({"detail": "event_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        from .ai_grouping import suggest_groups
        try:
            suggestions = suggest_groups(event_id, request.user)
            # Create a group suggestion notification?
            # Actually, return all pending suggestions for the event
            # Broadcast the creation of suggestions later? User will fetch them, or we can broadcast here.
            # But we return the new suggestions.
            return Response(
                QnAQuestionGroupSuggestionSerializer(suggestions, many=True).data,
                status=status.HTTP_201_CREATED
            )
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class QnAQuestionGroupSuggestionViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = QnAQuestionGroupSuggestionSerializer

    def get_queryset(self):
        if self.action in ["approve", "reject", "retrieve"]:
            return QnAQuestionGroupSuggestion.objects.all()
            
        event_id = self.request.query_params.get("event_id")
        if not event_id:
            return QnAQuestionGroupSuggestion.objects.none()
        return QnAQuestionGroupSuggestion.objects.filter(event_id=event_id).order_by("-created_at")

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        from django.utils import timezone
        suggestion = self.get_object()
        if suggestion.status != "pending":
            return Response({"detail": "Only pending suggestions can be approved."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Admin check
        if not (request.user == suggestion.event.created_by or getattr(request.user, "is_staff", False)):
            return Response({"detail": "Not authorized."}, status=status.HTTP_403_FORBIDDEN)
            
        suggestion.status = "approved"
        suggestion.reviewed_at = timezone.now()
        suggestion.reviewed_by = request.user
        suggestion.save()
        
        # Allow editing info at approval time inside payload
        title = request.data.get("title", suggestion.suggested_title)
        summary = request.data.get("summary", suggestion.suggested_summary)
        question_ids = request.data.get("question_ids", suggestion.suggested_question_ids)
        
        # Create group
        group = QnAQuestionGroup.objects.create(
            event=suggestion.event,
            title=title,
            summary=summary,
            created_by=request.user,
            source=QnAQuestionGroup.SOURCE_AI,
            ai_suggestion=suggestion
        )
        
        for q_id in question_ids:
            QnAQuestionGroupMembership.objects.filter(question_id=q_id).delete()
            QnAQuestionGroupMembership.objects.create(
                group=group,
                question_id=q_id,
                added_by=request.user
            )
        # Refresh the group to include all the newly created memberships accurately in the WebSocket broadcast
        group_refreshed = QnAQuestionGroup.objects.prefetch_related("memberships").get(id=group.id)
        
        channel_layer = get_channel_layer()
        group_name = f"event_qna_{suggestion.event_id}_main"
        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "qna.group_created",
                "payload": {"type": "qna.group_created", "group": QnAQuestionGroupSerializer(group_refreshed).data}
            }
        )
        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "qna.group_suggestion_reviewed",
                "payload": {"type": "qna.group_suggestion_reviewed", "suggestion_id": suggestion.id, "status": "approved"}
            }
        )
        
        return Response({"status": "approved", "group_id": group.id}, status=status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def reject(self, request, pk=None):
        from django.utils import timezone
        suggestion = self.get_object()
        
        # Admin check
        if not (request.user == suggestion.event.created_by or getattr(request.user, "is_staff", False)):
            return Response({"detail": "Not authorized."}, status=status.HTTP_403_FORBIDDEN)

        suggestion.status = "rejected"
        suggestion.reviewed_at = timezone.now()
        suggestion.reviewed_by = request.user
        suggestion.save()
        
        channel_layer = get_channel_layer()
        group_name = f"event_qna_{suggestion.event_id}_main"
        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                "type": "qna.group_suggestion_reviewed",
                "payload": {"type": "qna.group_suggestion_reviewed", "suggestion_id": suggestion.id, "status": "rejected"}
            }
        )

        return Response({"status": "rejected"}, status=status.HTTP_200_OK)


# -----------------------------------------------------------------
# QnAContentContext ViewSet (host/admin context management)
# -----------------------------------------------------------------

class QnAContentContextViewSet(viewsets.ModelViewSet):
    """
    CRUD API for Q&A presentation context records.

    Only event hosts and staff can create or view context for their events.
    Attendees never call this endpoint directly; their AI suggestion requests
    use the context internally server-side.

    GET  /api/interactions/qna-context/?event_id=<id>  — list context for event
    POST /api/interactions/qna-context/               — add a context record
    """
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]

    def get_queryset(self):
        from events.models import Event

        event_id = self.request.query_params.get("event_id")
        if not event_id:
            return QnAContentContext.objects.none()

        event = get_object_or_404(Event, id=event_id)
        user = self.request.user
        is_host = (user == event.created_by or getattr(user, "is_staff", False))
        if not is_host:
            return QnAContentContext.objects.none()

        return QnAContentContext.objects.filter(event=event).order_by("-created_at")

    def _get_event_and_assert_host(self, event_id):
        """Helper: resolve event and confirm requester is host/staff."""
        from events.models import Event
        from rest_framework.exceptions import PermissionDenied

        event = get_object_or_404(Event, id=event_id)
        user = self.request.user
        if not (user == event.created_by or getattr(user, "is_staff", False)):
            raise PermissionDenied("Only event hosts or admin can manage Q&A context.")
        return event

    def list(self, request, *args, **kwargs):
        """GET /qna-context/?event_id=<id>"""
        event_id = request.query_params.get("event_id")
        if not event_id:
            return Response(
                {"detail": "event_id query parameter is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        qs = self.get_queryset()
        data = [
            {
                "id": c.id,
                "event_id": c.event_id,
                "session_id": c.session_id,
                "source_type": c.source_type,
                "source_title": c.source_title,
                "content_text": c.content_text,
                "created_at": c.created_at.isoformat(),
                "updated_at": c.updated_at.isoformat(),
            }
            for c in qs
        ]
        return Response(data, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        """POST /qna-context/"""
        event_id = request.data.get("event_id")
        if not event_id:
            return Response(
                {"detail": "event_id is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        event = self._get_event_and_assert_host(event_id)

        content_text = (request.data.get("content_text") or "").strip()
        if not content_text:
            return Response(
                {"detail": "content_text is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        source_type = request.data.get("source_type", QnAContentContext.SOURCE_HOST_NOTES)
        valid_types = [c[0] for c in QnAContentContext.SOURCE_TYPE_CHOICES]
        if source_type not in valid_types:
            return Response(
                {"detail": f"source_type must be one of: {', '.join(valid_types)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        ctx = QnAContentContext.objects.create(
            event=event,
            session_id=request.data.get("session_id") or None,
            source_type=source_type,
            source_title=(request.data.get("source_title") or "").strip(),
            content_text=content_text,
        )

        return Response(
            {
                "id": ctx.id,
                "event_id": ctx.event_id,
                "session_id": ctx.session_id,
                "source_type": ctx.source_type,
                "source_title": ctx.source_title,
                "content_text": ctx.content_text,
                "created_at": ctx.created_at.isoformat(),
            },
            status=status.HTTP_201_CREATED,
        )

    def destroy(self, request, *args, **kwargs):
        """DELETE /qna-context/<id>/"""
        ctx = get_object_or_404(QnAContentContext, pk=kwargs["pk"])
        self._get_event_and_assert_host(ctx.event_id)
        ctx.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def partial_update(self, request, *args, **kwargs):
        """PATCH /qna-context/<id>/"""
        ctx = get_object_or_404(QnAContentContext, pk=kwargs["pk"])
        self._get_event_and_assert_host(ctx.event_id)

        if "content_text" in request.data:
            ctx.content_text = (request.data["content_text"] or "").strip()
        if "source_title" in request.data:
            ctx.source_title = (request.data["source_title"] or "").strip()
        if "source_type" in request.data:
            ctx.source_type = request.data["source_type"]
        ctx.save()

        return Response(
            {
                "id": ctx.id,
                "source_type": ctx.source_type,
                "source_title": ctx.source_title,
                "content_text": ctx.content_text,
                "updated_at": ctx.updated_at.isoformat(),
            },
            status=status.HTTP_200_OK,
        )


# -----------------------------------------------------------------
# A3: Public AI Question Suggestions ViewSet
# -----------------------------------------------------------------

class AiPublicSuggestionViewSet(viewsets.ModelViewSet):
    """
    Host endpoints for generating and managing public candidate suggestions.
    Participant endpoints for viewing and adopting published suggestions.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = QnAAIPublicSuggestionSerializer
    queryset = QnAAIPublicSuggestion.objects.all()

    def _is_guest_user(self, user) -> bool:
        return bool(getattr(user, "is_guest", False))

    def _get_event_and_assert_host(self, event_id):
        from events.models import Event
        event = get_object_or_404(Event, id=event_id)
        if self.request.user != event.created_by and not getattr(self.request.user, "is_staff", False):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("Only event host/admin can perform this action.")
        return event

    def get_queryset(self):
        # Allow retrieving by PK (detail actions) without event_id query param
        if "pk" in self.kwargs:
            return QnAAIPublicSuggestion.objects.all()

        event_id = self.request.query_params.get("event_id")
        if not event_id:
            return QnAAIPublicSuggestion.objects.none()

        user = self.request.user
        from events.models import Event
        event = get_object_or_404(Event, id=event_id)
        is_host = user == event.created_by or getattr(user, "is_staff", False)

        qs = QnAAIPublicSuggestion.objects.filter(event_id=event_id)
        if not is_host:
            # Attendees only see published suggestions
            qs = qs.filter(status="published")
        return qs

    @action(detail=False, methods=["post"], throttle_classes=[AiSuggestionsRateThrottle])
    def generate(self, request):
        """
        POST /api/interactions/ai-public-suggestions/generate/
        Body: { event_id, session_id?, count? }
        Host only. Generates candidate suggestions using AI.
        """
        from .ai_public_question_suggestions import generate_public_suggestions
        from .models import QnAContentContext

        event_id = request.data.get("event_id")
        session_id = request.data.get("session_id")
        count = int(request.data.get("count", 5))

        event = self._get_event_and_assert_host(event_id)

        # Load context
        context_qs = QnAContentContext.objects.filter(event=event)
        if session_id:
            context_qs = context_qs.filter(
                Q(session_id=session_id) | Q(session__isnull=True)
            )

        contexts = list(context_qs.order_by("-created_at"))
        if not contexts:
            return Response(
                {"detail": "No presentation context available for this event."},
                status=status.HTTP_404_NOT_FOUND,
            )

        context_parts = []
        for ctx in contexts:
            label = ctx.source_title or ctx.get_source_type_display()
            context_parts.append(f"[{label}]\n{ctx.content_text}")
        combined_context = "\n\n".join(context_parts)

        session_title = ""
        if session_id:
            try:
                from events.models import EventSession
                session_obj = EventSession.objects.get(pk=session_id, event=event)
                session_title = session_obj.title or ""
            except Exception:
                pass

        try:
            suggestions = generate_public_suggestions(
                event_title=event.title or "",
                session_title=session_title,
                context_text=combined_context,
                count=count,
            )
        except ValueError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        # Create draft suggestions in DB
        created_suggestions = []
        for s in suggestions:
            obj = QnAAIPublicSuggestion.objects.create(
                event=event,
                session_id=session_id if session_id else None,
                question_text=s["question"],
                rationale=s.get("rationale", ""),
                status="draft",
                source_type="ai",
                created_by=request.user,
                confidence_score=s.get("confidence_score", 0.0),
            )
            created_suggestions.append(obj)

        serializer = self.get_serializer(created_suggestions, many=True)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def publish(self, request, pk=None):
        """POST /api/interactions/ai-public-suggestions/{id}/publish/"""
        suggestion = self.get_object()
        self._get_event_and_assert_host(suggestion.event_id)

        from django.utils import timezone
        suggestion.status = "published"
        suggestion.reviewed_by = request.user
        suggestion.published_at = timezone.now()
        suggestion.save(update_fields=["status", "reviewed_by", "published_at"])

        # WebSocket broadcast to refresh suggestions for all participants
        self._broadcast_refresh(suggestion.event_id)

        return Response(self.get_serializer(suggestion).data)

    @action(detail=True, methods=["post"])
    def reject(self, request, pk=None):
        """POST /api/interactions/ai-public-suggestions/{id}/reject/"""
        suggestion = self.get_object()
        self._get_event_and_assert_host(suggestion.event_id)

        suggestion.status = "rejected"
        suggestion.reviewed_by = request.user
        suggestion.save(update_fields=["status", "reviewed_by"])

        return Response(self.get_serializer(suggestion).data)

    @action(detail=True, methods=["post"])
    def archive(self, request, pk=None):
        """POST /api/interactions/ai-public-suggestions/{id}/archive/"""
        suggestion = self.get_object()
        self._get_event_and_assert_host(suggestion.event_id)

        suggestion.status = "archived"
        suggestion.save(update_fields=["status"])

        # WebSocket broadcast to refresh suggestions for all participants
        self._broadcast_refresh(suggestion.event_id)

        return Response(self.get_serializer(suggestion).data)

    @action(detail=True, methods=["patch"])
    def reorder(self, request, pk=None):
        """PATCH /api/interactions/ai-public-suggestions/{id}/reorder/"""
        suggestion = self.get_object()
        self._get_event_and_assert_host(suggestion.event_id)

        new_order = request.data.get("display_order")
        if new_order is not None:
            suggestion.display_order = int(new_order)
            suggestion.save(update_fields=["display_order"])

        return Response(self.get_serializer(suggestion).data)

    def _broadcast_refresh(self, event_id):
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        channel_layer = get_channel_layer()
        # Broadcast to main room Q&A group
        group = f"event_qna_{event_id}_main"
        async_to_sync(channel_layer.group_send)(
            group,
            {
                "type": "qna.ai_public_suggestions_refresh",
                "payload": {"event_id": event_id}
            }
        )
