"""
Invalidate the Blog reader cache (blogs.cache) on every Blog write.

Covers ORM saves/deletes of posts and terms and changes to a post's
categories/tags. Queryset ``.update()`` bypasses signals; code that uses it on
Blog posts (the WordPress sync) calls ``blogs.cache.invalidate()`` itself.
"""
from django.db.models.signals import m2m_changed, post_delete, post_save
from django.dispatch import receiver

from . import cache as blog_cache
from .models import BlogCategory, BlogPost, BlogTag

_M2M_WRITES = {"post_add", "post_remove", "post_clear"}


@receiver(post_save, sender=BlogPost, dispatch_uid="blogs_cache_post_saved")
@receiver(post_delete, sender=BlogPost, dispatch_uid="blogs_cache_post_deleted")
@receiver(post_save, sender=BlogCategory, dispatch_uid="blogs_cache_category_saved")
@receiver(post_delete, sender=BlogCategory, dispatch_uid="blogs_cache_category_deleted")
@receiver(post_save, sender=BlogTag, dispatch_uid="blogs_cache_tag_saved")
@receiver(post_delete, sender=BlogTag, dispatch_uid="blogs_cache_tag_deleted")
def invalidate_on_write(sender, **kwargs):
    blog_cache.invalidate()


@receiver(m2m_changed, sender=BlogPost.categories.through, dispatch_uid="blogs_cache_post_categories")
@receiver(m2m_changed, sender=BlogPost.tags.through, dispatch_uid="blogs_cache_post_tags")
def invalidate_on_terms_changed(sender, action, **kwargs):
    if action in _M2M_WRITES:
        blog_cache.invalidate()
