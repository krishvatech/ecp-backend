"""
Serializers for the users app.

Defines serializers for listing users, registering new users with nested
profiles, and serializing user profiles.
"""
from django.contrib.auth.models import User
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import UserProfile


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for the UserProfile model."""

    class Meta:
        model = UserProfile
        fields = ["full_name", "timezone", "bio"]


class UserSerializer(serializers.ModelSerializer):
    """Serializer for the Django User model with nested profile."""
    profile = UserProfileSerializer()

    class Meta:
        model = User
        fields = ["id", "username", "email", "profile", "is_active", "date_joined"]
        read_only_fields = ["id", "is_active", "date_joined"]


class RegisterSerializer(serializers.ModelSerializer):
    """Serializer used for user registration with nested profile."""
    password = serializers.CharField(write_only=True)
    profile = UserProfileSerializer(required=False)

    class Meta:
        model = User
        fields = ["username", "email", "password", "profile"]

    def create(self, validated_data):
        profile_data = validated_data.pop("profile", {})
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        # Update the profile with provided data, if any
        for key, value in profile_data.items():
            setattr(user.profile, key, value)
        user.profile.save()
        return user
    
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, trim_whitespace=False)
    new_password = serializers.CharField(write_only=True, trim_whitespace=False)
    confirm_new_password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_new_password"]:
            raise serializers.ValidationError({"confirm_new_password": "Passwords do not match."})
        # Run Django’s password validators (length, common, numeric, etc.)
        validate_password(attrs["new_password"], self.context["request"].user)
        return attrs
    

