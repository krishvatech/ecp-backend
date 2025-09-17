"""
Pagination utilities for the project.

Defines a default page number pagination class used across DRF
endpoints.  The page size is controlled centrally here rather than
duplicated throughout the codebase.
"""
from rest_framework.pagination import PageNumberPagination

class DefaultPagination(PageNumberPagination):
    """A simple page number paginator with a default page size."""
    page_size = 20
