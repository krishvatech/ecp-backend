from django.contrib import admin

from .models import BlogCategory, BlogPost, BlogTag


@admin.register(BlogPost)
class BlogPostAdmin(admin.ModelAdmin):
    list_display = (
        "title", "status", "author", "published_at",
        "imported_from_wordpress", "updated_at",
    )
    list_filter = ("status", "imported_from_wordpress", "categories")
    search_fields = ("title", "slug", "legacy_author_name")
    raw_id_fields = ("author", "created_by", "updated_by")
    filter_horizontal = ("categories", "tags")
    readonly_fields = ("created_by", "updated_by", "created_at", "updated_at")
    prepopulated_fields = {"slug": ("title",)}
    ordering = ("-updated_at",)

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(BlogCategory)
class BlogCategoryAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "updated_at")
    search_fields = ("name", "slug")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(BlogTag)
class BlogTagAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "updated_at")
    search_fields = ("name", "slug")
    prepopulated_fields = {"slug": ("name",)}
