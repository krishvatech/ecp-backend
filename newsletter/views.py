from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import (
    NewsletterPreferencesResponseSerializer,
    NewsletterPreferencesUpdateSerializer,
)
from .services import (
    InvalidNewsletterCategories,
    list_user_preferences,
    update_user_preferences,
)


class NewsletterPreferencesView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        data = {"preferences": list_user_preferences(request.user)}
        serializer = NewsletterPreferencesResponseSerializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request):
        serializer = NewsletterPreferencesUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            preferences = update_user_preferences(
                request.user,
                serializer.validated_data["preferences"],
            )
        except InvalidNewsletterCategories as exc:
            return Response(
                {
                    "preferences": {
                        "slug": [
                            f"Unknown or inactive newsletter category: {slug}"
                            for slug in exc.slugs
                        ]
                    }
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        response_serializer = NewsletterPreferencesResponseSerializer(
            {"preferences": preferences}
        )
        return Response(
            response_serializer.data,
            status=status.HTTP_200_OK,
        )
