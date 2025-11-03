# realtime/serializers.py
from rest_framework import serializers

class EventTokenRequestSerializer(serializers.Serializer):
    role = serializers.ChoiceField(
        choices=["audience", "publisher"],
        required=False,
        help_text='Defaults to "audience".'
    )
    uid = serializers.IntegerField(required=False, help_text="UID to sign the token for.")
