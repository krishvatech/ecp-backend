from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db.models import Count, Exists, OuterRef
from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth import get_user_model

from .models import Question, QuestionUpvote
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

    def get_queryset(self):
        event_id = self.request.query_params.get("event_id")
        # Optional: Filter by specific lounge table (or None for main room)
        # Frontend should send ?lounge_table_id=123 (or empty/missing for main room)
        lounge_table_id = self.request.query_params.get("lounge_table_id")
        
        qs = (
            Question.objects
            .annotate(
                upvotes_count=Count("upvoters"),
                user_upvoted=Exists(
                    QuestionUpvote.objects.filter(
                        question=OuterRef("pk"),
                        user=self.request.user
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
        if event_id:
            event = get_object_or_404(
                __import__('events.models', fromlist=['Event']).Event,
                id=event_id
            )
            is_host = self.request.user == event.created_by or self.request.user.is_staff
            if not is_host:
                qs = qs.filter(is_hidden=False)

        return qs.order_by("-upvotes_count", "-created_at")

    def perform_create(self, serializer):
        """
        Attach the current user when creating a question
        AND broadcast it to all connected QnA WebSocket clients.
        """
        # Capture optional table ID from request body
        lounge_table_id = self.request.data.get("lounge_table")
        
        # Save with user and table info
        # If lounge_table_id is None/empty, it saves as NULL (Main Room)
        question = serializer.save(user=self.request.user, lounge_table_id=lounge_table_id or None)

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
        display_name = (
            (getattr(user, "get_full_name", lambda: "")() or "").strip()
            or user.first_name
            or user.username
            or (user.email.split("@")[0] if user.email else f"User {user.id}")
        )

        payload = {
            "type": "qna.question",
            "event_id": question.event_id,
            "lounge_table_id": question.lounge_table_id,  # Include table ID in payload
            "question_id": question.id,
            "user_id": question.user_id,
            "uid": question.user_id,
            "user": display_name,
            "content": question.content,
            "upvote_count": 0,
            "created_at": question.created_at.isoformat(),
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
            upvoters_list = [
                {
                    'id': u['id'],
                    'name': f"{u.get('first_name', '')} {u.get('last_name', '')}".strip() or u.get('username', f"User {u['id']}"),
                    'username': u.get('username', ''),
                }
                for u in upvoters
            ]

            # Resolve asker name
            asker = q.user
            asker_name = "Audience"
            if asker:
                asker_name = (
                    (getattr(asker, "get_full_name", lambda: "")() or "").strip()
                    or asker.first_name
                    or asker.username
                    or (asker.email.split("@")[0] if asker.email else f"User {asker.id}")
                )
            
            data.append({
                "id": q.id,
                "content": q.content,
                "user_id": q.user_id,
                "user_name": asker_name, # ✅ Fixed: explicit name field
                "upvote_count": q.upvotes_count,  # annotated
                "user_upvoted": q.user_upvoted,  # annotated boolean
                "upvoters": upvoters_list,  # NEW: list of users who upvoted
                "event_id": q.event_id,
                "lounge_table_id": q.lounge_table_id, # Return to client
                "created_at": q.created_at.isoformat(),
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

        # Toggle
        if question.upvoters.filter(id=user.id).exists():
            question.upvoters.remove(user)
            upvoted = False
        else:
            question.upvoters.add(user)
            upvoted = True

        upvote_count = question.upvoters.count()

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
            "user_id": user.id,
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
        upvoters_list = [
            {
                'id': u['id'],
                'name': f"{u.get('first_name', '')} {u.get('last_name', '')}".strip() or u.get('username', f"User {u['id']}"),
                'username': u.get('username', ''),
            }
            for u in upvoters
        ]
        return Response({
            "question_id": question.id,
            "upvote_count": question.upvoters.count(),
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

    def perform_update(self, serializer):
        """
        Update a question.
        Permission: Owner OR Host (event.created_by).
        Broadcast: 'qna.update'
        """
        instance = serializer.instance
        user = self.request.user
        
        # Permission check
        is_owner = (user == instance.user)
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
        is_owner = (user == instance.user)
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
