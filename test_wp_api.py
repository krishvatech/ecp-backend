#!/usr/bin/env python3
"""Test WordPress API connection"""
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ecp_backend.settings.base')
django.setup()

from users.wordpress_api import get_wordpress_client

wp_client = get_wordpress_client()

# Test 1: Try to get a user by email
print("=" * 60)
print("TEST 1: Fetching user by email 'testing@edtechprof.com'")
print("=" * 60)
try:
    user = wp_client.get_user_by_email('testing@edtechprof.com')
    if user:
        print(f"✓ User found!")
        print(f"  ID: {user.get('id')}")
        print(f"  Name: {user.get('name')}")
        print(f"  Email: {user.get('email')}")
        print(f"  Fields: {list(user.keys())}")
        print(f"\nFull response:")
        import json
        print(json.dumps(user, indent=2, default=str)[:1000])
    else:
        print("✗ User not found")
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()

# Test 2: Check WordPress config
print("\n" + "=" * 60)
print("TEST 2: WordPress Configuration")
print("=" * 60)
from django.conf import settings
print(f"WP_IMAA_API_URL: {settings.WP_IMAA_API_URL}")
print(f"WP_IMAA_AUTH_TYPE: {getattr(settings, 'WP_IMAA_AUTH_TYPE', 'basic')}")
print(f"WP_IMAA_API_USER: {settings.WP_IMAA_API_USER}")
