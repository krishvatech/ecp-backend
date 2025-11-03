# groups/admin.py
from django.contrib import admin
from .models import Group, GroupMembership, PromotionRequest

@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'slug', 'visibility', 'created_by', 'created_at')
    list_filter = ('visibility', 'created_at')
    search_fields = ('name', 'slug', 'description')
    readonly_fields = ('created_at', 'updated_at')

@admin.register(GroupMembership)
class GroupMembershipAdmin(admin.ModelAdmin):
    list_display = ('id', 'group', 'user', 'role', 'status', 'joined_at')
    list_filter = ('role', 'status')
    search_fields = ('group__name', 'user__email', 'user__username')

@admin.register(PromotionRequest)
class PromotionRequestAdmin(admin.ModelAdmin):
    list_display = ('id', 'group', 'user', 'role_requested', 'status', 'created_at', 'reviewed_by', 'reviewed_at')
    list_filter = ('status', 'role_requested')
    search_fields = ('group__name', 'user__email', 'user__username')
    readonly_fields = ('created_at', 'reviewed_at')
