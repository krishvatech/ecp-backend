from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async
from .models import LoungeTable, LoungeParticipant, Event, EventRegistration
from django.contrib.auth.models import User
from django.db import transaction
import random

class EventConsumer(AsyncJsonWebsocketConsumer):
    """Consumer to handle real-time communication within an event, including Social Lounge state."""

    async def connect(self) -> None:
        self.user = self.scope.get("user")
        if not self.user or self.user.is_anonymous:
            await self.close(code=4401)
            return

        self.event_id = self.scope["url_route"]["kwargs"]["event_id"]
        self.group_name = f"event_{self.event_id}"

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        # Send welcome message with current lounge state
        lounge_state = await self.get_lounge_state()
        await self.update_online_status(True)
        await self.broadcast_lounge_update() # Sync everyone with new online count
        
        msg = {
            "type": "welcome",
            "event_id": self.event_id,
            "your_user_id": self.user.id,
            "lounge_state": lounge_state,
            "online_users": await self.get_online_participants_info()
        }
        print(f"[CONSUMER] Sending welcome to {self.user.username}: {msg.keys()}")
        await self.send_json(msg)

    async def disconnect(self, code: int) -> None:
        if hasattr(self, "group_name"):
            # Auto-leave table on disconnect
            await self.leave_current_table()
            await self.update_online_status(False)
            await self.broadcast_lounge_update() # Sync everyone
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive_json(self, content: dict, **kwargs) -> None:
        action = content.get("action")
        
        if action == "join_table":
            table_id = content.get("table_id")
            seat_index = content.get("seat_index")
            success, error = await self.join_table(table_id, seat_index)
            if success:
                await self.broadcast_lounge_update()
            else:
                await self.send_json({"type": "error", "message": error})

        elif action == "leave_table":
            print(f"[CONSUMER] User {self.user.username} requested to leave table")
            await self.leave_current_table()
            await self.broadcast_lounge_update()

        elif action == "random_assign":
            if not await self.is_host():
                print(f"[CONSUMER] DENIED random_assign: User {self.user.username} is not a host.")
                await self.send_json({"type": "error", "message": "Only hosts can perform random assignment."})
                return
            per_room = content.get("per_room", 4)
            await self.perform_random_assignment_and_notify(per_room)

        elif action == "start_timer":
            if not await self.is_host(): return
            duration = content.get("duration", 60)
            await self.channel_layer.group_send(
                self.group_name, 
                {"type": "breakout.timer", "duration": duration}
            )

        elif action == "broadcast_announcement":
            if not await self.is_host(): return
            message = content.get("message", "")
            await self.channel_layer.group_send(
                self.group_name, 
                {"type": "breakout.announcement", "message": message}
            )

        elif action == "end_all_breakouts":
            if not await self.is_host(): return
            await self.clear_all_tables()
            await self.channel_layer.group_send(
                self.group_name, 
                {"type": "breakout.end"}
            )
            await self.broadcast_lounge_update()

        else:
            # Traditional broadcast for other messages
            await self.channel_layer.group_send(
                self.group_name,
                {"type": "broadcast.message", "payload": content},
            )

    async def broadcast_message(self, event: dict) -> None:
        await self.send_json({"type": "message", "data": event["payload"]})

    async def lounge_update(self, event: dict) -> None:
        """Handler for 'lounge_update' group message."""
        await self.send_json({
            "type": "lounge_state",
            "lounge_state": event["state"],
            "online_users": event.get("online_users", [])
        })

    async def broadcast_lounge_update(self):
        state = await self.get_lounge_state()
        online_users = await self.get_online_participants_info()
        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "lounge_update",
                "state": state,
                "online_users": online_users
            }
        )

    @database_sync_to_async
    def get_online_participants_info(self):
        regs = EventRegistration.objects.filter(
            event_id=self.event_id, 
            is_online=True
        ).exclude(user_id=self.user.id).select_related('user')
        return [{
            "user_id": r.user.id,
            "username": r.user.username,
            "full_name": f"{r.user.first_name} {r.user.last_name}".strip() or r.user.username
        } for r in regs]

    async def breakout_timer(self, event: dict) -> None:
        await self.send_json({"type": "breakout_timer", "duration": event["duration"]})

    async def breakout_announcement(self, event: dict) -> None:
        await self.send_json({"type": "breakout_announcement", "message": event["message"]})

    async def breakout_end(self, event: dict) -> None:
        await self.send_json({"type": "breakout_end"})

    async def breakout_force_join(self, event: dict) -> None:
        """Targeted force join for specific user"""
        if str(self.user.id) == str(event["user_id"]):
            await self.send_json({
                "type": "force_join_breakout",
                "table_id": event["table_id"]
            })

    async def breakout_debug(self, event: dict) -> None:
        """Broadcast debug info to host"""
        if await self.is_host():
            await self.send_json({
                "type": "server_debug",
                "message": event["message"]
            })

    async def send_debug_to_host(self, message):
        await self.channel_layer.group_send(
            self.group_name,
            {
                "type": "breakout_debug",
                "message": message
            }
        )

    @database_sync_to_async
    def is_host(self):
        # A host is the creator OR any staff/superuser
        if self.user.is_superuser or self.user.is_staff:
            return True
        return Event.objects.filter(id=self.event_id, created_by=self.user).exists()

    @database_sync_to_async
    def update_online_status(self, increment):
        try:
            with transaction.atomic():
                reg, _ = EventRegistration.objects.select_for_update().get_or_create(
                    event_id=self.event_id, 
                    user=self.user,
                    defaults={'status': 'registered'}
                )
                if increment:
                    reg.online_count += 1
                else:
                    reg.online_count = max(0, reg.online_count - 1)
                
                reg.is_online = (reg.online_count > 0)
                reg.save(update_fields=['online_count', 'is_online'])
                print(f"[CONSUMER] User {self.user.username} (ID:{self.user.id}): count={reg.online_count}, online={reg.is_online}")
        except Exception as e:
            print(f"[CONSUMER] Error updating online status for {self.user.username}: {e}")

    @database_sync_to_async
    def clear_all_tables(self):
        LoungeParticipant.objects.filter(table__event_id=self.event_id).delete()

    @database_sync_to_async
    def perform_random_assignment(self, per_room):
        print(f"[RANDOM_ASSIGN] Starting: event={self.event_id}, per_room={per_room}")
        # 1. Get all online participants (excluding host)
        registrations = EventRegistration.objects.filter(
            event_id=self.event_id, 
            is_online=True
        ).exclude(user_id=self.user.id).select_related('user')
        
        users = [reg.user for reg in list(registrations)]
        print(f"[RANDOM_ASSIGN] Found {len(users)} online attendees: {[u.username for u in users]}")
        random.shuffle(users)

        # 2. Get tables
        tables = list(LoungeTable.objects.filter(event_id=self.event_id).order_by('id'))
        print(f"[RANDOM_ASSIGN] Found {len(tables)} tables")
        if not tables or not users:
            return []

        with transaction.atomic():
            # Clear old assignments
            LoungeParticipant.objects.filter(table__event_id=self.event_id).delete()
            
            assignments = []
            table_idx = 0
            # If per_room is 1, we try to put 1 person per table. 
            # If we run out of tables, we stop OR we could overflow. 
            # For "Airmeet" feel, usually people per room is a target.
            
            for user in users:
                if table_idx >= len(tables):
                    break 
                
                table = tables[table_idx]
                # Check if this table is already full based on 'per_room'
                table_current_count = len([a for a in assignments if a[1] == table.id])
                
                if table_current_count >= per_room or table_current_count >= table.max_seats:
                    table_idx += 1
                    if table_idx >= len(tables):
                        break
                    table = tables[table_idx]

                LoungeParticipant.objects.create(
                    table=table,
                    user=user,
                    seat_index=len([a for a in assignments if a[1] == table.id])
                )
                assignments.append((user.id, table.id))
            
            return assignments

    async def perform_random_assignment_and_notify(self, per_room):
        assignments = await self.perform_random_assignment(per_room)
        
        if not assignments:
            return
            
        await self.broadcast_lounge_update()
        
        # Notify each assigned user via the group
        for user_id, table_id in assignments:
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "breakout_force_join",
                    "user_id": user_id,
                    "table_id": table_id
                }
            )

    @database_sync_to_async
    def get_lounge_state(self):
        tables = LoungeTable.objects.filter(event_id=self.event_id).prefetch_related('participants__user')
        state = []
        for t in tables:
            participants = {}
            for p in t.participants.all():
                participants[p.seat_index] = {
                    "user_id": p.user.id,
                    "username": p.user.username,
                    "full_name": f"{p.user.first_name} {p.user.last_name}".strip() or p.user.username
                }
            state.append({
                "id": t.id,
                "name": t.name,
                "max_seats": t.max_seats,
                "dyte_meeting_id": t.dyte_meeting_id,
                "participants": participants
            })
        return state

    @database_sync_to_async
    def join_table(self, table_id, seat_index):
        try:
            with transaction.atomic():
                # 1. Clear user from any other table in this event
                LoungeParticipant.objects.filter(
                    table__event_id=self.event_id, 
                    user=self.user
                ).delete()

                # 2. Check if seat is occupied
                if LoungeParticipant.objects.filter(table_id=table_id, seat_index=seat_index).exists():
                    return False, "Seat already occupied"

                # 3. Create participant
                LoungeParticipant.objects.create(
                    table_id=table_id,
                    user=self.user,
                    seat_index=seat_index
                )
                return True, None
        except Exception as e:
            return False, str(e)

    @database_sync_to_async
    def leave_current_table(self):
        deleted_count, _ = LoungeParticipant.objects.filter(
            table__event_id=self.event_id, 
            user=self.user
        ).delete()
        print(f"[CONSUMER] User {self.user.username} (ID:{self.user.id}) left table. Deleted {deleted_count} participant record(s)")
        return deleted_count