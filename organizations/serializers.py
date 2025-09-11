from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from .models import Organization

User = get_user_model()

class OrganizationSerializer(serializers.ModelSerializer):
    owner_id = serializers.IntegerField(read_only=True)
    members_count = serializers.IntegerField(read_only=True)

    members = serializers.SlugRelatedField(
        slug_field="username",
        queryset=User.objects.all(),
        many=True,
        required=False,
    )

    class Meta:
        model = Organization
        fields = [
            "id",
            "name",
            "slug",
            "description",
            "owner_id",
            "members",
            "members_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "slug", "owner_id", "members_count", "created_at", "updated_at"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["members_count"] = instance.members.count()
        data["owner_id"] = instance.owner_id
        return data

    def create(self, validated_data):
        user = self.context["request"].user
        members = validated_data.pop("members", [])   
        org = Organization.objects.create(owner=user, **validated_data)
        if user not in members:
            members.append(user)
        org.members.set(members)                     
        return org

    def update(self, instance, validated_data):
        members = validated_data.pop("members", None)  
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if members is not None:
            instance.members.set(members)
        return instance
    

