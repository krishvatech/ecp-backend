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

User = get_user_model()

class QuestionViewSet(viewsets.ModelViewSet):
    """
    Q&A REST endpoints with real-time upvote broadcast.
    - GET /questions?event_id=...
    - POST /questions/{id}/upvote/
    """
    permission_classes = [IsAuthenticated]
    queryset = Question.objects.all()  # required by DRF, but we override get_queryset()

    def get_queryset(self):
        event_id = self.request.query_params.get("event_id")
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
        return qs.order_by("-upvotes_count", "-created_at")

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
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
            
            data.append({
                "id": q.id,
                "content": q.content,
                "user_id": q.user_id,
                "upvote_count": q.upvotes_count,  # annotated
                "user_upvoted": q.user_upvoted,  # annotated boolean
                "upvoters": upvoters_list,  # NEW: list of users who upvoted
                "event_id": q.event_id,
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
        # QnA group name shape: f"event_qna_{event_id}_qnaconsumer"
        group = f"event_qna_{question.event_id}_qnaconsumer"
        channel_layer = get_channel_layer()
        payload = {
            "type": "qna.upvote",
            "event_id": question.event_id,
            "question_id": question.id,
            "upvote_count": upvote_count,
            "upvoted": upvoted,
            "user_id": user.id,
        }
        async_to_sync(channel_layer.group_send)(group, {"type": "qna.upvote", "payload": payload})

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
