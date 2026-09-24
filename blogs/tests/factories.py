from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import override_settings
from rest_framework.test import APITestCase

from blogs.models import BlogPost


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                        "LOCATION": "blogs-tests"}}
)
class BlogAPITestCase(APITestCase):
    """Isolates DRF throttle counters from the shared Redis cache."""

    def setUp(self):
        super().setUp()
        cache.clear()


def make_user(username, **extra):
    return User.objects.create_user(
        username=username,
        email=f"{username}@example.com",
        password="test-pass-123",
        **extra,
    )


def make_superuser(username="blog-admin"):
    return User.objects.create_superuser(
        username=username,
        email=f"{username}@example.com",
        password="test-pass-123",
    )


def make_post(**overrides):
    values = {
        "title": "Sample post",
        "content_html": "<p>Body</p>",
    }
    values.update(overrides)
    return BlogPost.objects.create(**values)


def make_published_post(**overrides):
    post = make_post(**overrides)
    post.publish()
    return post
