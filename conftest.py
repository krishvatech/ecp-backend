"""Test-wide defaults that must not depend on the developer's environment.

The Mautic per-user identity settings are read from the environment, so a
developer who enables per-user execution locally would otherwise change the
behaviour of suites that assert service-account behaviour. Pinned here so the
suite is hermetic; tests that exercise per-user execution opt in with
``override_settings``, which nests inside this and still wins.
"""

import pytest
from django.test import override_settings


@pytest.fixture(autouse=True, scope="session")
def dormant_mautic_identity_by_default():
    with override_settings(
        ECP_MAUTIC_PER_USER_EXECUTION_ENABLED=False,
        ECP_MAUTIC_IDENTITY_PRIVATE_KEY="",
        ECP_MAUTIC_IDENTITY_KEY_ID="",
    ):
        yield
