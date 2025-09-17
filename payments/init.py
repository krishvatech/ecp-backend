"""
Payments app package for the events & community platform backend.

This package provides models and API endpoints for managing paid ticketing
plans and purchases.  It integrates with Stripe via the dj-stripe
library and exposes REST endpoints to create plans, initiate
checkout sessions and handle Stripe webhook callbacks.  See
payments/views.py for API details.
"""

default_app_config = "payments.apps.PaymentsConfig"
