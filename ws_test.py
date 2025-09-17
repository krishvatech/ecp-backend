import websockets
import asyncio
import json

TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzU4MDg1MzY5LCJpYXQiOjE3NTgwODM1NjksImp0aSI6IjkzNTNmNmZmOGMwYTQwN2ZiZTAzMGY0MzFhYmE5NzMzIiwidXNlcl9pZCI6Mzh9.RZ_xDzZ63mvg55MwO_d-_-tlJE5S87s-IyJm111_O4Y"
URL = f"ws://127.0.0.1:8000/ws/events/27/chat/?token={TOKEN}"

async def main():
    async with websockets.connect(URL) as ws:
        await ws.send(json.dumps({"message": "hello from Python client"}))
        async for msg in ws:
            print("Received:", msg)

asyncio.run(main())
