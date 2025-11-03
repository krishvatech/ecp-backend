from django.db.models import Q
from rest_framework import permissions, viewsets
from .models import Community
from .serializers import CommunitySerializer

class CommunityViewSet(viewsets.ModelViewSet):
    serializer_class = CommunitySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Community.objects.filter(Q(owner=user) | Q(members=user)).distinct()

    def perform_create(self, serializer):
        serializer.save()
