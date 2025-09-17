"""
django-filter FilterSet definitions for the users app.

The ``UserFilter`` enables advanced searching and filtering of users
through query parameters.  It supports a full‑text like search via
the ``q`` parameter across first/last names and several profile fields
and allows filtering by company, job title, location, skills and
organization membership.

Non‑staff users will still only see users who share an organization with
them (enforced in the view).
"""
from django.contrib.auth.models import User
from django.db.models import Q
from django_filters import rest_framework as filters


class UserFilter(filters.FilterSet):
    """Filter set for the User directory search."""

    q = filters.CharFilter(method="filter_q")
    company = filters.CharFilter(field_name="profile__company", lookup_expr="icontains")
    job_title = filters.CharFilter(field_name="profile__job_title", lookup_expr="icontains")
    location = filters.CharFilter(field_name="profile__location", lookup_expr="icontains")
    skills = filters.CharFilter(method="filter_skills")
    organization = filters.NumberFilter(method="filter_organization")

    class Meta:
        model = User
        fields = []

    def filter_q(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(
            Q(first_name__icontains=value)
            | Q(last_name__icontains=value)
            | Q(profile__full_name__icontains=value)
            | Q(profile__headline__icontains=value)
            | Q(profile__company__icontains=value)
            | Q(profile__skills__icontains=[value])
        )

    def filter_skills(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(profile__skills__contains=[value])

    def filter_organization(self, queryset, name, value):
        if not value:
            return queryset
        return queryset.filter(Q(organizations__id=value) | Q(owned_organizations__id=value))
