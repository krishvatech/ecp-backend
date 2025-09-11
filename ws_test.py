import asyncio, os, websockets

ACCESS = os.getenv("ACCESS")

async def try_url(u):
    try:
        async with websockets.connect(u) as ws:
            print("OK:", u)
            return True
    except Exception as e:
        print("FAIL:", u, "|", e)
        return False

async def main():
    base = "ws://localhost:8000"
    paths = [
        f"/ws/events/1/?token={ACCESS}",
        f"/ws/events/1?token={ACCESS}",
        f"/ws/event/1/?token={ACCESS}",
        f"/ws/event/1?token={ACCESS}",
        f"/ws/events/?token={ACCESS}",
        f"/ws/event/?token={ACCESS}",
    ]
    for p in paths:
        await try_url(base+p)

asyncio.run(main())
