import pytest
from channels.testing import WebsocketCommunicator
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from ecp_backend.asgi import application
from events.models import Event
from users.models import User
from community.models import Community
from interactions.models import ChatMessage, Question

@pytest.mark.django_db
@pytest.mark.asyncio
async def test_chat_message_persists_and_broadcasts(settings):
    """
    An authenticated member joining chat should broadcast and persist messages.
    """
    org = Community.objects.create(name="ChatOrg", owner_id=1, description="")
    creator = User.objects.create_user(username="c1", password="pass123")
    org.members.add(creator)
    event = Event.objects.create(title="ChatEvent", community=org, created_by=creator)

    # token (use plain string; JWT middleware not executed in test)
    headers = [(b'authorization', f"Bearer dummy".encode())]

    communicator = WebsocketCommunicator(application, f"/ws/events/{event.id}/chat/")
    communicator.scope["headers"] = headers
    communicator.scope["user"] = creator
    connected, _ = await communicator.connect()
    assert connected

    # send a message
    await communicator.send_json_to({"message": "Hello"})
    response = await communicator.receive_json_from()
    assert response["type"] == "chat.message"
    assert response["message"] == "Hello"

    # ensure it persisted
    assert ChatMessage.objects.count() == 1
    msg = ChatMessage.objects.first()
    assert msg.content == "Hello"
    await communicator.disconnect()

@pytest.mark.django_db
@pytest.mark.asyncio
async def test_qna_flow(settings):
    """Test QnA consumer handles questions and answers."""
    org = Community.objects.create(name="QOrg", owner_id=1, description="")
    owner = User.objects.create_user(username="owner", password="pass123")
    org.members.add(owner)
    event = Event.objects.create(title="QEvent", community=org, created_by=owner)

    headers = [(b'authorization', f"Bearer dummy".encode())]
    communicator = WebsocketCommunicator(application, f"/ws/events/{event.id}/qna/")
    communicator.scope["headers"] = headers
    communicator.scope["user"] = owner
    connected, _ = await communicator.connect()
    assert connected

    # ask a question
    await communicator.send_json_to({"content": "What time is the event?"})
    resp = await communicator.receive_json_from()
    assert resp["type"] == "qna.question"
    question_id = resp["question_id"]
    assert Question.objects.count() == 1

    # answer the question
    await communicator.send_json_to({"question_id": question_id, "content": "It starts at 10."})
    ans = await communicator.receive_json_from()
    assert ans["type"] == "qna.answer"
    q = Question.objects.get(id=question_id)
    assert q.answer == "It starts at 10."
    await communicator.disconnect()
