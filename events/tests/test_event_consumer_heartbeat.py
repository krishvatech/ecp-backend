import asyncio
from types import SimpleNamespace

import pytest
from asgiref.sync import async_to_sync
from channels.generic.websocket import AsyncJsonWebsocketConsumer

import events.consumers as consumers_module
from events.consumers import EventConsumer


def make_consumer():
    consumer = EventConsumer()
    consumer.event_id = 123
    consumer.channel_name = "test-channel"
    consumer.user = SimpleNamespace(id=456, is_anonymous=False, username="tester")
    consumer._ws_closed = False
    consumer._ws_close_sent = False
    consumer._disconnect_cleanup_started = False
    consumer._disconnect_cleanup_enqueued = False
    consumer._live_session_tracked = False
    consumer.heartbeat_task = None
    return consumer


def test_heartbeat_stops_after_disconnect(monkeypatch):
    consumer = make_consumer()

    monkeypatch.setattr(consumers_module, "HEARTBEAT_INTERVAL", 60)

    async def run():
        consumer.heartbeat_task = asyncio.create_task(consumer._heartbeat_loop())
        await asyncio.sleep(0)

        await consumer.disconnect(1000)

        assert consumer._ws_closed is True
        assert consumer.heartbeat_task is None

    async_to_sync(run)()


def test_no_send_occurs_after_close(monkeypatch):
    consumer = make_consumer()
    calls = {"close": 0, "send": 0}

    async def fake_close(self, code=None, reason=None):
        calls["close"] += 1

    async def fake_send_json(self, content, close=False):
        calls["send"] += 1

    monkeypatch.setattr(AsyncJsonWebsocketConsumer, "close", fake_close)
    monkeypatch.setattr(AsyncJsonWebsocketConsumer, "send_json", fake_send_json)

    async def run():
        await consumer.close(code=4000)
        await consumer.send_json({"type": "ping"})

    async_to_sync(run)()

    assert calls == {"close": 1, "send": 0}


def test_close_is_sent_only_once(monkeypatch):
    consumer = make_consumer()
    close_calls = []

    async def fake_close(self, code=None, reason=None):
        close_calls.append(code)

    monkeypatch.setattr(AsyncJsonWebsocketConsumer, "close", fake_close)

    async def run():
        await consumer.close(code=4000)
        await consumer.close(code=4001)

    async_to_sync(run)()

    assert close_calls == [4000]
    assert consumer._ws_closed is True


def test_closed_socket_errors_do_not_flood_logs(monkeypatch, caplog):
    consumer = make_consumer()

    async def fake_send_json(self, content, close=False):
        raise RuntimeError("Unexpected ASGI message 'websocket.send', after sending 'websocket.close'")

    monkeypatch.setattr(AsyncJsonWebsocketConsumer, "send_json", fake_send_json)

    async def run():
        await consumer.send_json({"type": "ping"})
        await consumer.send_json({"type": "ping"})

    async_to_sync(run)()

    assert consumer._ws_closed is True
    assert not [record for record in caplog.records if record.levelname in {"WARNING", "ERROR"}]


def test_heartbeat_closed_send_error_exits_without_looping(monkeypatch):
    consumer = make_consumer()
    send_calls = {"count": 0}

    monkeypatch.setattr(consumers_module, "HEARTBEAT_INTERVAL", 0)
    monkeypatch.setattr(consumers_module, "HEARTBEAT_TIMEOUT", 60)

    async def fake_send_json(content, close=False):
        send_calls["count"] += 1
        raise RuntimeError("response already completed")

    consumer.send_json = fake_send_json

    async_to_sync(consumer._heartbeat_loop)()

    assert send_calls["count"] == 1
    assert consumer._ws_closed is True


def test_heartbeat_timeout_does_not_double_close(monkeypatch):
    consumer = make_consumer()
    close_calls = []

    monkeypatch.setattr(consumers_module, "HEARTBEAT_INTERVAL", 0)
    monkeypatch.setattr(consumers_module, "HEARTBEAT_TIMEOUT", -1)

    async def fake_close(self, code=None, reason=None):
        close_calls.append(code)

    monkeypatch.setattr(AsyncJsonWebsocketConsumer, "close", fake_close)

    async def run():
        await consumer._heartbeat_loop()
        await consumer.close(code=4001)

    async_to_sync(run)()

    assert close_calls == [4000]


def test_reconnect_leaves_only_one_active_heartbeat_task(monkeypatch):
    first = make_consumer()
    second = make_consumer()

    monkeypatch.setattr(consumers_module, "HEARTBEAT_INTERVAL", 60)

    async def run():
        first.heartbeat_task = asyncio.create_task(first._heartbeat_loop())
        await asyncio.sleep(0)
        await first.disconnect(1006)

        second.heartbeat_task = asyncio.create_task(second._heartbeat_loop())
        await asyncio.sleep(0)

        assert first.heartbeat_task is None
        assert second.heartbeat_task is not None
        assert not second.heartbeat_task.done()

        second.heartbeat_task.cancel()
        try:
            await second.heartbeat_task
        except asyncio.CancelledError:
            pass

    async_to_sync(run)()
