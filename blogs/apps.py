from django.apps import AppConfig


class BlogsConfig(AppConfig):
    """Standalone ECP blog (not Wagtail, not activity feed)."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "blogs"
    verbose_name = "Blogs"
