import pytest

import events.consumers as consumers_module


def test_event_exists_cached_uses_cache_hit(monkeypatch):
    db_calls = {"count": 0}

    def fake_get(_key):
        return True

    def fake_add(*_args, **_kwargs):
        raise AssertionError("lock acquisition should not run on cache hit")

    def fake_set(*_args, **_kwargs):
        raise AssertionError("cache set should not run on cache hit")

    def fake_delete(*_args, **_kwargs):
        raise AssertionError("cache delete should not run on cache hit")

    def fake_db(_event_id):
        db_calls["count"] += 1
        return True

    monkeypatch.setattr(consumers_module.cache, "get", fake_get)
    monkeypatch.setattr(consumers_module.cache, "add", fake_add)
    monkeypatch.setattr(consumers_module.cache, "set", fake_set)
    monkeypatch.setattr(consumers_module.cache, "delete", fake_delete)
    monkeypatch.setattr(consumers_module, "_event_exists_db_sync", fake_db)

    assert consumers_module._event_exists_cached_sync(123) is True
    assert db_calls["count"] == 0


def test_event_exists_cached_waits_for_existing_refresh(monkeypatch):
    db_calls = {"count": 0}
    get_results = [None, None, True]

    def fake_get(_key):
        return get_results.pop(0)

    def fake_add(*_args, **_kwargs):
        return False

    def fake_set(*_args, **_kwargs):
        raise AssertionError("cache set should not run in wait path")

    def fake_delete(*_args, **_kwargs):
        raise AssertionError("cache delete should not run in wait path")

    def fake_db(_event_id):
        db_calls["count"] += 1
        return True

    monkeypatch.setattr(consumers_module.cache, "get", fake_get)
    monkeypatch.setattr(consumers_module.cache, "add", fake_add)
    monkeypatch.setattr(consumers_module.cache, "set", fake_set)
    monkeypatch.setattr(consumers_module.cache, "delete", fake_delete)
    monkeypatch.setattr(consumers_module, "_event_exists_db_sync", fake_db)

    assert consumers_module._event_exists_cached_sync(456) is True
    assert db_calls["count"] == 0


def test_event_exists_cached_returns_none_on_db_failure(monkeypatch):
    delete_calls = {"count": 0}

    def fake_get(_key):
        return None

    def fake_add(*_args, **_kwargs):
        return True

    def fake_set(*_args, **_kwargs):
        raise AssertionError("cache set should not run when db fails")

    def fake_delete(*_args, **_kwargs):
        delete_calls["count"] += 1

    def fake_db(_event_id):
        raise RuntimeError("db unavailable")

    monkeypatch.setattr(consumers_module.cache, "get", fake_get)
    monkeypatch.setattr(consumers_module.cache, "add", fake_add)
    monkeypatch.setattr(consumers_module.cache, "set", fake_set)
    monkeypatch.setattr(consumers_module.cache, "delete", fake_delete)
    monkeypatch.setattr(consumers_module, "_event_exists_db_sync", fake_db)

    assert consumers_module._event_exists_cached_sync(789) is None
    assert delete_calls["count"] == 1
