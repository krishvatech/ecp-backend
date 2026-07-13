# groups/admin.py
from django.contrib import admin, messages
from django.db.models import Q

from .models import Group, GroupMembership, PromotionRequest, WordPressGroupSource
from .soft_delete import restore_group_deletion_batches, soft_delete_group_tree


@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'name', 'slug', 'visibility', 'source', 'source_group_id',
        'is_deleted', 'deleted_at', 'created_by', 'created_at',
    )
    list_filter = (
        'is_deleted', 'deletion_source', 'visibility', 'source', 'created_at',
        'posts_comments_enabled', 'posts_creation_restricted', 'forum_enabled',
    )
    search_fields = ('name', 'slug', 'description', 'source_group_id', 'source_slug')
    readonly_fields = (
        'created_at', 'updated_at', 'source_synced_at', 'is_deleted', 'deleted_at',
        'deleted_by', 'deletion_source', 'deletion_batch_id',
    )
    actions = ('soft_delete_selected_groups', 'restore_selected_groups')

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
        ('Soft Delete', {
            'fields': (
                'is_deleted', 'deleted_at', 'deleted_by', 'deletion_reason',
                'deletion_source', 'deletion_batch_id',
            ),
            'description': (
                'Soft-deleted groups remain stored with memberships, posts, polls, '
                'messages, reports, and WordPress mappings.'
            ),
        }),
        ('Organization', {
            'fields': ('community', 'parent', 'owner', 'created_by', 'created_at', 'updated_at')
        }),
    )

    def get_queryset(self, request):
        return Group.all_objects.all()

    @admin.action(description='Soft delete selected Connect groups')
    def soft_delete_selected_groups(self, request, queryset):
        protected_filter = (
            Q(source=Group.SOURCE_WORDPRESS)
            | ~Q(source_group_id="")
            | Q(wordpress_source__isnull=False)
        )
        protected = queryset.filter(protected_filter).distinct().count()
        deleted = 0
        candidates = queryset.exclude(protected_filter).filter(is_deleted=False).distinct()
        for group in candidates:
            if not Group.all_objects.filter(pk=group.pk, is_deleted=False).exists():
                continue
            result = soft_delete_group_tree(
                group,
                actor=request.user,
                reason='Deleted from Django administration.',
                deletion_source=Group.DELETION_SOURCE_CONNECT,
            )
            deleted += result.deleted_count

        if deleted:
            self.message_user(
                request,
                f'Soft-deleted {deleted} group row(s). All related history remains stored.',
                level=messages.SUCCESS,
            )
        if protected:
            self.message_user(
                request,
                f'Skipped {protected} WordPress-managed group(s). Change them on WordPress.',
                level=messages.WARNING,
            )

    @admin.action(description='Restore selected soft-deleted groups')
    def restore_selected_groups(self, request, queryset):
        restored = restore_group_deletion_batches(queryset.filter(is_deleted=True))
        self.message_user(
            request,
            f'Restored {restored} group row(s).',
            level=messages.SUCCESS,
        )

    def delete_model(self, request, obj):
        wordpress_managed = (
            obj.source == Group.SOURCE_WORDPRESS
            or bool(obj.source_group_id)
            or WordPressGroupSource.objects.filter(linked_group_id=obj.id).exists()
        )
        if wordpress_managed:
            self.message_user(
                request,
                'This group is managed by WordPress and was not deleted locally.',
                level=messages.ERROR,
            )
            return
        result = soft_delete_group_tree(
            obj,
            actor=request.user,
            reason='Deleted from Django administration.',
            deletion_source=Group.DELETION_SOURCE_CONNECT,
        )
        self.message_user(
            request,
            f'Soft-deleted {result.deleted_count} group row(s). Related data remains stored.',
            level=messages.SUCCESS,
        )

    def delete_queryset(self, request, queryset):
        self.soft_delete_selected_groups(request, queryset)


@admin.register(WordPressGroupSource)
class WordPressGroupSourceAdmin(admin.ModelAdmin):
    list_display = (
        'wp_group_id', 'name', 'slug', 'status', 'member_count',
        'sync_enabled', 'linked_group', 'last_fetched_at', 'last_synced_at', 'last_members_synced_at'
    )
    list_filter = ('sync_enabled', 'status', 'last_fetched_at')
    search_fields = ('name', 'slug', 'description', 'wp_group_id')
    readonly_fields = (
        'wp_group_id', 'name', 'slug', 'description', 'status', 'member_count',
        'group_url', 'raw_payload', 'last_fetched_at', 'last_synced_at', 'last_members_synced_at',
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
