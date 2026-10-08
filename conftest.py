"""Test-wide defaults that must not depend on the developer's environment.

The Mautic per-user identity settings are read from the environment, so a
developer who enables per-user execution locally would otherwise change the
behaviour of suites that assert service-account behaviour. Pinned here so the
suite is hermetic; tests that exercise per-user execution opt in with
``override_settings``, which nests inside this and still wins.

The Marketing Hub response cache is off for the same reason: it lives in the
shared Redis, so a response cached by one test would be served to the next.
Its own tests turn it on against a local-memory cache. Background-processing
health (task heartbeats, Redis and worker probes) is off for the same reason.
"""

import pytest
from django.test import override_settings


@pytest.fixture(autouse=True, scope="session")
def dormant_mautic_identity_by_default():
    with override_settings(
        ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=False,
        ECP_MAUTIC_IDENTITY_PRIVATE_KEY="",
        ECP_MAUTIC_IDENTITY_KEY_ID="",
        MARKETING_RESPONSE_CACHE_ENABLED=False,
        NEWSLETTER_BACKGROUND_HEALTH_ENABLED=False,
    ):
        yield
