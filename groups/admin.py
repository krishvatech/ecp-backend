# groups/admin.py
from django.contrib import admin
from .models import Group, GroupMembership, PromotionRequest

@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'slug', 'visibility', 'created_by', 'created_at')
    list_filter = ('visibility', 'created_at', 'posts_comments_enabled', 'posts_creation_restricted', 'forum_enabled')
    search_fields = ('name', 'slug', 'description')
    readonly_fields = ('created_at', 'updated_at')

    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'slug', 'description', 'visibility', 'join_policy')
        }),
        ('Images', {
            'fields': ('cover_image', 'logo')
        }),
        ('Chat Settings', {
            'fields': ('message_mode',)
        }),
        ('Communication Settings', {
            'fields': ('posts_comments_enabled', 'posts_creation_restricted', 'forum_enabled'),
            'description': 'Control how members interact within the group.'
        }),
        ('Organization', {
            'fields': ('community', 'parent', 'owner', 'created_by', 'created_at', 'updated_at')
        }),
    )

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
