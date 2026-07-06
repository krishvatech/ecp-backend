# groups/admin.py
from django.contrib import admin
from .models import Group, GroupMembership, PromotionRequest, WordPressGroupSource

@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'slug', 'visibility', 'source', 'source_group_id', 'created_by', 'created_at')
    list_filter = ('visibility', 'source', 'created_at', 'posts_comments_enabled', 'posts_creation_restricted', 'forum_enabled')
    search_fields = ('name', 'slug', 'description', 'source_group_id', 'source_slug')
    readonly_fields = ('created_at', 'updated_at', 'source_synced_at')

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
        ('External Source', {
            'fields': ('source', 'source_group_id', 'source_slug', 'source_url', 'source_synced_at'),
            'description': 'Used by WordPress IMAA group sync. Manual groups keep source=manual.'
        }),
        ('Organization', {
            'fields': ('community', 'parent', 'owner', 'created_by', 'created_at', 'updated_at')
        }),
    )


@admin.register(WordPressGroupSource)
class WordPressGroupSourceAdmin(admin.ModelAdmin):
    list_display = (
        'wp_group_id', 'name', 'slug', 'status', 'member_count',
        'sync_enabled', 'linked_group', 'last_fetched_at', 'last_synced_at'
    )
    list_filter = ('sync_enabled', 'status', 'last_fetched_at')
    search_fields = ('name', 'slug', 'description', 'wp_group_id')
    readonly_fields = (
        'wp_group_id', 'name', 'slug', 'description', 'status', 'member_count',
        'group_url', 'raw_payload', 'last_fetched_at', 'last_synced_at',
        'created_at', 'updated_at'
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
