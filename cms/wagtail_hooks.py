"""
Wagtail hooks for custom admin behavior for EmailTemplate.
Provides custom admin URLs for preview/test send functionality,
and delete-warning hooks. The EmailTemplate model is registered
as a snippet via @register_snippet decorator in cms/models.py.
"""
from wagtail import hooks


@hooks.register("register_admin_urls")
def register_email_template_urls():
    """Register custom admin URLs for preview and test-send actions."""
    from django.urls import path
    from cms.admin_views import email_template_preview, email_template_test_send

    return [
        path(
            "email-templates/<int:pk>/preview/",
            email_template_preview,
            name="email_template_preview",
        ),
        path(
            "email-templates/<int:pk>/test-send/",
            email_template_test_send,
            name="email_template_test_send",
        ),
    ]


@hooks.register("before_delete_snippet")
def warn_before_email_template_delete(request, instances):
    """Show a warning when deleting an EmailTemplate snippet."""
    from django.contrib import messages

    for instance in instances:
        if isinstance(instance, EmailTemplate):
            messages.warning(
                request,
                f"Warning: Deleting '{instance.template_key}' will cause the system "
                f"to fall back to the file-based template. "
                f"Consider deactivating (is_active=False) instead.",
            )
