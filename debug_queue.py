from events.models import SpeedNetworkingSession, SpeedNetworkingQueue, SpeedNetworkingMatch

def run():
    print("--- DEBUG QUEUE STATE ---")
    session = SpeedNetworkingSession.objects.filter(status='ACTIVE').first()
    if not session:
        print("No ACTIVE session found.")
        return

    print(f"Session ID: {session.id} ({session.name})")

    print("\n[QUEUE ENTRIES]")
    queues = SpeedNetworkingQueue.objects.filter(session=session)
    for q in queues:
        status = "FREE" if q.current_match is None else f"BUSY (Match {q.current_match.id})"
        print(f"User: {q.user.username} (ID: {q.user.id}) | Active: {q.is_active} | Status: {status}")

    print("\n[ACTIVE MATCHES]")
    matches = SpeedNetworkingMatch.objects.filter(session=session, status='ACTIVE')
    for m in matches:
        print(f"Match {m.id}: {m.participant_1.username} vs {m.participant_2.username}")
    print("-------------------------")

run()
