"""
Wagtail hooks for custom CMS admin behavior.

This module keeps existing EmailTemplate admin helpers and converts Wagtail CMS
page deletes into soft deletes so CMS content remains recoverable from the DB.
"""
from django.contrib import messages
from django.shortcuts import redirect

from wagtail import hooks
from wagtail.models import Page

from cms.models import (
    AboutPage,
    EmailTemplate,
    EventsLandingPage,
    HomePage,
    ProfileLayoutPage,
    StandardPage,
)


CMS_PAGE_TYPES = (
    HomePage,
    StandardPage,
    AboutPage,
    EventsLandingPage,
    ProfileLayoutPage,
)


def _specific_page(page):
    return page.specific if isinstance(page, Page) else page


def is_ecp_cms_page(page):
    return isinstance(_specific_page(page), CMS_PAGE_TYPES)


def soft_delete_page_tree(page, user=None, reason="Deleted from Wagtail CMS"):
    """Soft-delete a Wagtail page and its descendants when they are ECP CMS pages."""
    archived_count = 0

    for child in page.get_descendants(inclusive=True).specific():
        if isinstance(child, CMS_PAGE_TYPES) and not getattr(child, "cms_is_deleted", False):
            child.soft_delete(user=user, reason=reason)
            archived_count += 1

    return archived_count


def soft_deleted_cms_page_ids():
    """Collect base wagtailcore_page IDs for archived ECP CMS pages."""
    ids = []
    for model in CMS_PAGE_TYPES:
        ids.extend(
            model.objects.filter(cms_is_deleted=True).values_list("page_ptr_id", flat=True)
        )
    return ids


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
    for instance in instances:
        if isinstance(instance, EmailTemplate):
            messages.warning(
                request,
                f"Warning: Deleting '{instance.template_key}' will cause the system "
                f"to fall back to the file-based template. "
                f"Consider deactivating (is_active=False) instead.",
            )


@hooks.register("before_delete_page")
def convert_cms_page_delete_to_soft_delete(request, page):
    """Archive ECP CMS pages instead of permanently deleting them from Wagtail."""
    if not is_ecp_cms_page(page):
        return None

    # Allow Wagtail's confirmation screen to render on GET.
    if request.method != "POST":
        return None

    parent = page.get_parent()
    archived_count = soft_delete_page_tree(
        page,
        user=request.user,
        reason="Deleted from Wagtail CMS",
    )

    if archived_count == 1:
        messages.success(request, f'"{page.title}" was archived instead of permanently deleted.')
    else:
        messages.success(request, f"{archived_count} CMS pages were archived instead of permanently deleted.")

    return redirect("wagtailadmin_explore", parent.id if parent else Page.get_first_root_node().id)


@hooks.register("before_bulk_action")
def convert_cms_bulk_delete_to_soft_delete(request, action_type, objects, action_class_instance):
    """Archive selected ECP CMS pages for Wagtail bulk delete actions."""
    if action_type != "delete":
        return None

    cms_pages = [page for page in objects if is_ecp_cms_page(page)]
    if not cms_pages:
        return None

    parent_id = None
    archived_count = 0
    for page in cms_pages:
        parent = page.get_parent()
        if parent_id is None and parent:
            parent_id = parent.id
        archived_count += soft_delete_page_tree(
            page,
            user=request.user,
            reason="Bulk deleted from Wagtail CMS",
        )

    messages.success(
        request,
        f"{archived_count} CMS page(s) archived instead of permanently deleted.",
    )
    return redirect("wagtailadmin_explore", parent_id or Page.get_first_root_node().id)


@hooks.register("construct_explorer_page_queryset")
def hide_soft_deleted_cms_pages_from_explorer(parent_page, pages, request):
    """Hide archived CMS pages from the normal Wagtail explorer listing."""
    # Emergency/admin escape hatch: append ?show_deleted=1 in Wagtail explorer.
    if request.GET.get("show_deleted") == "1":
        return pages

    deleted_ids = soft_deleted_cms_page_ids()
    if deleted_ids:
        pages = pages.exclude(id__in=deleted_ids)
    return pages
