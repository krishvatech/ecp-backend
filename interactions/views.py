from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db.models import BooleanField, Count, Exists, OuterRef
from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth import get_user_model

from .models import Question, QuestionGuestUpvote, QuestionUpvote
from .serializers import QuestionSerializer

User = get_user_model()

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

        return qs.order_by("-upvotes_count", "-created_at")

    def perform_create(self, serializer):
        """
        Attach the current user when creating a question
        AND broadcast it to all connected QnA WebSocket clients.
        Handle moderation status based on event setting.
        """
        # Capture optional table ID from request body
        lounge_table_id = self.request.data.get("lounge_table")

        # Save with user and table info
        # If lounge_table_id is None/empty, it saves as NULL (Main Room)
        if self._is_guest_user(self.request.user):
            question = serializer.save(user=None, guest_asker=self.request.user.guest, lounge_table_id=lounge_table_id or None)
        else:
            question = serializer.save(user=self.request.user, guest_asker=None, lounge_table_id=lounge_table_id or None)

        # Check if event has moderation enabled and set status accordingly
        if question.event.qna_moderation_enabled:
            question.moderation_status = "pending"
            question.save(update_fields=["moderation_status"])

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

        # Build payload shape consistent with QnAConsumer.receive_json
        user = self.request.user
        if self._is_guest_user(user):
            display_name = user.guest.get_display_name()
            asker_id = f"guest_{user.guest.id}"
        else:
            display_name = (
                (getattr(user, "get_full_name", lambda: "")() or "").strip()
                or user.first_name
                or user.username
                or (user.email.split("@")[0] if user.email else f"User {user.id}")
            )
            asker_id = question.user_id

        payload = {
            "type": "qna.question",
            "event_id": question.event_id,
            "lounge_table_id": question.lounge_table_id,  # Include table ID in payload
            "question_id": question.id,
            "user_id": asker_id,
            "uid": asker_id,
            "user": display_name,
            "content": question.content,
            "upvote_count": 0,
            "created_at": question.created_at.isoformat(),
            "moderation_status": question.moderation_status,  # NEW: include status
        }

        async_to_sync(channel_layer.group_send)(
            group,
            {"type": "qna.question", "payload": payload},
        )

    def list(self, request, *args, **kwargs):
        # Optimize query by selecting related user
        queryset = self.get_queryset().select_related("user")
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

            # Resolve asker name
            asker = q.user
            guest_asker = getattr(q, "guest_asker", None)
            asker_name = "Audience"
            asker_id = None
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
                asker_id = q.user_id
            
            data.append({
                "id": q.id,
                "content": q.content,
                "user_id": asker_id,
                "user_name": asker_name, # ✅ Fixed: explicit name field
                "upvote_count": q.upvotes_count,  # annotated
                "user_upvoted": q.user_upvoted,  # annotated boolean
                "upvoters": upvoters_list,  # NEW: list of users who upvoted
                "event_id": q.event_id,
                "lounge_table_id": q.lounge_table_id, # Return to client
                "created_at": q.created_at.isoformat(),
                "is_answered": q.is_answered,
                "answered_at": q.answered_at.isoformat() if q.answered_at else None,
                "requires_followup": q.requires_followup,
                "is_pinned": q.is_pinned,
                "pinned_at": q.pinned_at.isoformat() if q.pinned_at else None,
            })
        return Response(data)
    

    @action(detail=True, methods=["post"])
    def upvote(self, request, pk=None):
        """
        Toggle upvote for a question. Broadcast the new count to the WebSocket group
        so everyone sees it update in real time.
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

        # Get asker display name
        if question.guest_asker:
            display_name = question.guest_asker.get_display_name()
            asker_id = f"guest_{question.guest_asker.id}"
        elif question.user:
            display_name = (
                (getattr(question.user, "get_full_name", lambda: "")() or "").strip()
                or question.user.first_name
                or question.user.username
                or (question.user.email.split("@")[0] if question.user.email else f"User {question.user.id}")
            )
            asker_id = question.user_id
        else:
            display_name = "Audience"
            asker_id = None

        payload = {
            "type": "qna.approved",
            "event_id": question.event_id,
            "question_id": question.id,
            "content": question.content,
            "user_id": asker_id,
            "user_name": display_name,
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
        Broadcasts qna.answered when status changes.
        """
        from django.utils import timezone
        from rest_framework.exceptions import PermissionDenied

        question = get_object_or_404(Question, pk=pk)
        user = request.user

        # Permission check: Only host/admin can mark answered
        is_host = (user == question.event.created_by or user.is_staff)
        if not is_host:
            raise PermissionDenied("Only event host/admin can mark questions as answered.")

        # Toggle answered status
        question.is_answered = not question.is_answered
        if question.is_answered:
            question.answered_by = user
            question.answered_at = timezone.now()
        else:
            question.answered_by = None
            question.answered_at = None

        # Handle requires_followup flag
        requires_followup = request.data.get("requires_followup", question.requires_followup)
        question.requires_followup = requires_followup

        question.save(update_fields=["is_answered", "answered_by", "answered_at", "requires_followup"])

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
