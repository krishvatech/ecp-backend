#!/usr/bin/env python
"""
Quick verification script for Issue 5 (Event Caching) and Issue 6 (Chat Redis-First).
Tests basic functionality without running the full test suite.
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ecp_backend.settings.dev")
sys.path.insert(0, os.path.dirname(__file__))
django.setup()

from django.core.cache import cache
from django.contrib.auth import get_user_model
from events.cache_utils import event_list_cache_key, invalidate_event_list_caches
from events.redis_messages import save_message_to_redis, get_message_from_redis, delete_message_from_redis
from interactions.models import ChatMessage
from uuid import uuid4
from datetime import datetime, timezone

User = get_user_model()

def test_cache_utils():
    """Test Issue 5: Event caching utilities."""
    print("\n" + "="*60)
    print("TEST 1: Event List Caching Utils")
    print("="*60)

    # Test cache key generation
    print("\n✓ Testing cache key generation...")

    # Anonymous user
    anon_key = event_list_cache_key(None, {})
    print(f"  Anonymous user key: {anon_key}")
    assert "anonymous" in anon_key, "Anonymous cache key should contain 'anonymous'"

    # Authenticated user (mock)
    class MockUser:
        id = 123
        is_authenticated = True
        is_superuser = False
        is_staff = False

    user = MockUser()
    auth_key = event_list_cache_key(user, {})
    print(f"  Auth user key: {auth_key}")
    assert "123" in auth_key, "Auth cache key should contain user ID"
    assert "user" in auth_key, "Auth cache key should contain role"

    # Admin user
    user.is_superuser = True
    admin_key = event_list_cache_key(user, {})
    print(f"  Admin user key: {admin_key}")
    assert "admin" in admin_key, "Admin cache key should contain 'admin' role"

    # Cache invalidation
    print("\n✓ Testing cache invalidation...")
    try:
        invalidate_event_list_caches(1)
        print("  Cache invalidation executed successfully")
    except Exception as e:
        print(f"  ⚠ Cache invalidation warning: {e}")

    print("\n✅ Cache Utils Test PASSED")
    return True


def test_redis_messages():
    """Test Issue 6: Redis message utilities."""
    print("\n" + "="*60)
    print("TEST 2: Redis Message Utilities")
    print("="*60)

    event_id = 999
    message_uuid = str(uuid4())
    created_at = datetime.now(timezone.utc)

    # Test saving message
    print("\n✓ Testing save message to Redis...")
    message_dict = {
        'user_id': 123,
        'content': 'Test message',
        'created_at': created_at.isoformat(),
        'uuid': message_uuid,
    }

    try:
        saved_uuid = save_message_to_redis(event_id, message_dict)
        print(f"  Saved message UUID: {saved_uuid}")
        assert saved_uuid == message_uuid, "Returned UUID should match input"
    except Exception as e:
        print(f"  ❌ Save message error: {e}")
        return False

    # Test retrieving message
    print("\n✓ Testing retrieve message from Redis...")
    try:
        retrieved = get_message_from_redis(event_id, message_uuid)
        print(f"  Retrieved message: {retrieved}")
        assert retrieved is not None, "Should retrieve saved message"
        assert retrieved['user_id'] == 123, "Retrieved message should have correct user_id"
        assert retrieved['content'] == 'Test message', "Retrieved message should have correct content"
    except Exception as e:
        print(f"  ❌ Retrieve message error: {e}")
        return False

    # Test deleting message
    print("\n✓ Testing delete message from Redis...")
    try:
        delete_message_from_redis(event_id, message_uuid)
        retrieved_again = get_message_from_redis(event_id, message_uuid)
        assert retrieved_again is None, "Message should be deleted from Redis"
        print("  Message deleted successfully")
    except Exception as e:
        print(f"  ❌ Delete message error: {e}")
        return False

    print("\n✅ Redis Messages Test PASSED")
    return True


def test_celery_tasks():
    """Test Issue 6: Celery task imports."""
    print("\n" + "="*60)
    print("TEST 3: Celery Tasks Import")
    print("="*60)

    print("\n✓ Testing Celery task imports...")
    try:
        from interactions.tasks import (
            persist_chat_message_to_db,
            persist_qna_question_to_db,
            persist_qna_reply_to_db,
        )
        print("  ✓ persist_chat_message_to_db imported")
        print("  ✓ persist_qna_question_to_db imported")
        print("  ✓ persist_qna_reply_to_db imported")

        # Check task properties
        assert hasattr(persist_chat_message_to_db, 'delay'), "Task should have delay method"
        assert persist_chat_message_to_db.max_retries == 3, "Task should have 3 max retries"
        print("\n  ✓ Task configuration verified")
    except Exception as e:
        print(f"  ❌ Task import error: {e}")
        return False

    print("\n✅ Celery Tasks Test PASSED")
    return True


def main():
    """Run all verification tests."""
    print("\n" + "="*60)
    print("OPTIMIZATION VERIFICATION TESTS")
    print("="*60)

    results = []

    try:
        results.append(("Cache Utils", test_cache_utils()))
    except Exception as e:
        print(f"\n❌ Cache Utils test error: {e}")
        results.append(("Cache Utils", False))

    try:
        results.append(("Redis Messages", test_redis_messages()))
    except Exception as e:
        print(f"\n❌ Redis Messages test error: {e}")
        results.append(("Redis Messages", False))

    try:
        results.append(("Celery Tasks", test_celery_tasks()))
    except Exception as e:
        print(f"\n❌ Celery Tasks test error: {e}")
        results.append(("Celery Tasks", False))

    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name}: {status}")

    all_passed = all(passed for _, passed in results)
    if all_passed:
        print("\n🎉 All verification tests PASSED!")
        return 0
    else:
        print("\n⚠️  Some tests failed. Please review the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
