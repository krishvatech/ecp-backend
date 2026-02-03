from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async
from .models import LoungeTable, LoungeParticipant, Event, EventRegistration
from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone
import random
from .utils import create_dyte_meeting

class EventConsumer(AsyncJsonWebsocketConsumer):
    """Consumer to handle real-time communication within an event, including Social Lounge state."""

    async def connect(self) -> None:
        self.user = self.scope.get("user")
        if not self.user or self.user.is_anonymous:
            await self.close(code=4401)
            return

        self.event_id = self.scope["url_route"]["kwargs"]["event_id"]
        self.group_name = f"event_{self.event_id}"

        # Join event group
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        
        # Join user-specific group for private messages
        # Check for Ban Status
        is_banned = await self.check_is_banned()
        if is_banned:
            print(f"[CONSUMER] User {self.user.username} is BANNED from event {self.event_id}. Closing connection.")
            await self.close(code=4003)
            return

        self.user_group_name = f"user_{self.user.id}"
        await self.channel_layer.group_add(self.user_group_name, self.channel_name)
        
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

            # Cleanup Dyte participants
            try:
                meeting_ids = await self.get_user_dyte_meetings()
                if meeting_ids:
                    import asyncio
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, self.cleanup_dyte_participants_sync, meeting_ids)
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"[CLEANUP] Failed: {e}")

            await self.broadcast_lounge_update() # Sync everyone
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

        if hasattr(self, "user_group_name"):
            await self.channel_layer.group_discard(self.user_group_name, self.channel_name)

    async def receive_json(self, content: dict, **kwargs) -> None:
        action = content.get("action")
        
        if action == "join_table":
            table_id = content.get("table_id")
            seat_index = content.get("seat_index")

            # ✅ DEFENSIVE: Verify meeting state is not corrupted
            # Lounge join should NOT reactivate the meeting
            try:
                event = await self.get_event()
                if event.status == "ended" and event.is_live:
                    # CRITICAL: Meeting state corrupted
                    print(f"[CRITICAL] Event {event.id} status='ended' but is_live=True during lounge join!")
                    await self.send_json({
                        "type": "error",
                        "message": "Meeting state error. Please refresh and try again.",
                        "error_code": "meeting_state_corrupted"
                    })
                    return
            except Exception as e:
                print(f"[CONSUMER] Failed to verify meeting state: {e}")
                # Continue anyway, don't block lounge join on verification failure

            success, error = await self.join_table(table_id, seat_index)
            if success:
                print(f"[CONSUMER] join_table successful for {self.user.username}, broadcasting update...")
                await self.broadcast_lounge_update()
            else:
                print(f"[CONSUMER] join_table failed for {self.user.username}: {error}")
                await self.send_json({"type": "error", "message": error})

        elif action == "leave_table":
            print(f"[CONSUMER] User {self.user.username} requested to leave table")
            await self.leave_current_table()
            await self.broadcast_lounge_update()

        elif action == "random_assign":
            try:
                per_room = int(content.get("per_room", 4))
                if not await self.is_host():
                    print(f"[CONSUMER] DENIED random_assign: User {self.user.username} is not a host.")
                    await self.send_debug_to_host("Action denied: Not a host")
                    return
                
                await self.perform_random_assignment_and_notify(per_room)
            except Exception as e:
                print(f"[CONSUMER] ERROR in random_assign: {str(e)}")
                await self.send_debug_to_host(f"Error during random assignment: {str(e)}")

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

    # --- Speed Networking Handlers ---
    async def speed_networking_session_started(self, event):
        """Broadcast session started to event group."""
        await self.send_json({
            "type": "speed_networking_session_started",
            "data": event["data"]
        })

    async def speed_networking_session_ended(self, event):
        """Broadcast session ended to event group."""
        await self.send_json({
            "type": "speed_networking_session_ended",
            "data": event["data"]
        })

    async def speed_networking_match_found(self, event):
        """Send match info to specific user."""
        # Since we are using user-specific groups now, this handler is triggered
        # only on the consumer instances for that user.
        await self.send_json({
            "type": "speed_networking_match_found",
            "data": event["data"]
        })

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
            is_online=True,
            is_banned=False  # Exclude banned users even if online flag is stuck
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

    async def meeting_ended(self, event: dict) -> None:
        """Broadcast notification that the host has ended the meeting.

        Participants should see PostEventLoungeScreen if lounge is available,
        otherwise they should be redirected away from the live meeting page.
        """
        await self.send_json({
            "type": "meeting_ended",
            "event_id": event.get("event_id"),
            "ended_at": event.get("ended_at"),
            "lounge_available": event.get("lounge_available", False),
            "lounge_closing_time": event.get("lounge_closing_time")
        })

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
    def get_user_dyte_meetings(self):
        """Get all Dyte meeting IDs where this user might be."""
        tables = LoungeTable.objects.filter(event_id=self.event_id).values_list('dyte_meeting_id', flat=True)
        meeting_ids = [mid for mid in tables if mid]

        try:
            event = Event.objects.get(id=self.event_id)
            if event.dyte_meeting_id:
                meeting_ids.append(event.dyte_meeting_id)
        except Event.DoesNotExist:
            pass

        return meeting_ids

    def cleanup_dyte_participants_sync(self, meeting_ids):
        """Remove user from all Dyte meetings."""
        import requests
        from .utils import DYTE_API_BASE, _dyte_headers
        import logging
        logger = logging.getLogger(__name__)

        removed = 0
        for mid in meeting_ids:
            try:
                logger.info(f"[CLEANUP] Checking meeting {mid} for user {self.user.id}")
                resp = requests.get(
                    f"{DYTE_API_BASE}/meetings/{mid}/participants",
                    headers=_dyte_headers(),
                    params={"limit": 100},
                    timeout=10,
                )

                if not resp.ok:
                    continue

                participants = resp.json().get("data", [])
                for p in participants:
                    cid = p.get("client_specific_id") or p.get("custom_participant_id")
                    if cid == str(self.user.id):
                        pid = p.get("id")
                        if pid:
                            logger.info(f"[CLEANUP] Removing participant {pid}")
                            del_resp = requests.delete(
                                f"{DYTE_API_BASE}/meetings/{mid}/participants/{pid}",
                                headers=_dyte_headers(),
                                timeout=10,
                            )
                            if del_resp.ok:
                                removed += 1
            except Exception as e:
                logger.error(f"[CLEANUP] Error: {e}")

        logger.info(f"[CLEANUP] Removed {removed} participants for user {self.user.id}")
        return removed

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

                online_total = EventRegistration.objects.filter(
                    event_id=self.event_id,
                    is_online=True,
                ).count()

                if online_total == 0:
                    Event.objects.filter(
                        id=self.event_id,
                        is_live=True,
                        idle_started_at__isnull=True,
                    ).update(idle_started_at=timezone.now())
                else:
                    Event.objects.filter(
                        id=self.event_id,
                        is_live=True,
                        idle_started_at__isnull=False,
                    ).update(idle_started_at=None)
        except Exception as e:
            print(f"[CONSUMER] Error updating online status for {self.user.username}: {e}")

    @database_sync_to_async
    def check_is_banned(self):
        return EventRegistration.objects.filter(
            event_id=self.event_id, 
            user=self.user, 
            is_banned=True
        ).exists()

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
        print(f"[RANDOM_ASSIGN] Found {len(users)} online attendees.")
        if not users:
            return []
        random.shuffle(users)

        # 2. Ensure we have enough BREAKOUT tables
        num_rooms_needed = (len(users) + per_room - 1) // per_room if per_room > 0 else 1
        tables = list(LoungeTable.objects.filter(event_id=self.event_id, category='BREAKOUT').order_by('id'))
        
        while len(tables) < num_rooms_needed:
            room_num = len(tables) + 1
            name = f"Breakout Room #{room_num}"
            print(f"[RANDOM_ASSIGN] Auto-creating {name}")
            mid = create_dyte_meeting(f"Breakout {self.event_id} - {room_num}")
            t = LoungeTable.objects.create(
                event_id=self.event_id,
                name=name,
                category='BREAKOUT',
                max_seats=max(per_room, 10),
                dyte_meeting_id=mid
            )
            tables.append(t)

        # 3. Perform assignments
        with transaction.atomic():
            # Clear all current assignments in the event
            LoungeParticipant.objects.filter(table__event_id=self.event_id).delete()
            
            assignments = []
            table_idx = 0
            for user in users:
                if table_idx >= len(tables): break
                table = tables[table_idx]
                
                # Check occupancy in current assignments list
                current_count = len([a for a in assignments if a[1] == table.id])
                if current_count >= per_room:
                    table_idx += 1
                    if table_idx >= len(tables): break
                    table = tables[table_idx]
                
                LoungeParticipant.objects.create(
                    table=table,
                    user=user,
                    seat_index=len([a for a in assignments if a[1] == table.id])
                )
                assignments.append((user.id, table.id))
            
            print(f"[RANDOM_ASSIGN] Completed: Created {len(assignments)} assignments.")
            return assignments

    async def perform_random_assignment_and_notify(self, per_room):
        assignments = await self.perform_random_assignment(per_room)
        
        if not assignments:
            msg = "No assignments created. Possibly no tables or no users online."
            print(f"[RANDOM_ASSIGN] {msg}")
            await self.send_debug_to_host(msg)
            return
        
        await self.send_debug_to_host(f"Created {len(assignments)} assignments across rooms.")
            
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
        debug_counts = []
        for t in tables:
            participants = {}
            for p in t.participants.all():
                profile = getattr(p.user, "profile", None)
                img = getattr(profile, "user_image", None) if profile else None
                if not img:
                    img = getattr(p.user, "avatar", None) or getattr(profile, "avatar", None) if profile else None
                avatar_url = ""
                if img:
                    try:
                        avatar_url = img.url
                    except Exception:
                        avatar_url = str(img) if img else ""
                participants[p.seat_index] = {
                    "user_id": p.user.id,
                    "username": p.user.username,
                    "full_name": f"{p.user.first_name} {p.user.last_name}".strip() or p.user.username,
                    "avatar_url": avatar_url,
                }
            icon_url = ""
            if getattr(t, "icon", None):
                try:
                    icon_url = t.icon.url
                except Exception:
                    icon_url = ""
            state.append({
                "id": t.id,
                "name": t.name,
                "category": t.category,
                "max_seats": t.max_seats,
                "dyte_meeting_id": t.dyte_meeting_id,
                "icon_url": icon_url,
                "participants": participants
            })
            if participants:
                debug_counts.append(f"Table {t.id}: {len(participants)} users")
        
        if debug_counts:
            print(f"[CONSUMER] get_lounge_state: Found participants: {', '.join(debug_counts)}")
        return state

    @database_sync_to_async
    def get_event(self):
        """Get the current event, used for state verification."""
        return Event.objects.get(id=self.event_id)

    @database_sync_to_async
    def join_table(self, table_id, seat_index):
        try:
            with transaction.atomic():
                # 1. Clear user from any other table in this event
                del_count, _ = LoungeParticipant.objects.filter(
                    table__event_id=self.event_id, 
                    user=self.user
                ).delete()
                print(f"[CONSUMER] join_table: Deleted {del_count} old records for user {self.user.id}")

                # 2. Check if seat is occupied
                if LoungeParticipant.objects.filter(table_id=table_id, seat_index=seat_index).exists():
                    print(f"[CONSUMER] join_table: Seat {seat_index} at table {table_id} already occupied")
                    return False, "Seat already occupied"

                # 3. Create participant
                LoungeParticipant.objects.create(
                    table_id=table_id,
                    user=self.user,
                    seat_index=seat_index
                )
                print(f"[CONSUMER] join_table: Created record for user {self.user.id} at table {table_id} seat {seat_index}")
                return True, None
        except Exception as e:
            print(f"[CONSUMER] join_table error: {e}")
            return False, str(e)

    @database_sync_to_async
    def leave_current_table(self):
        deleted_count, _ = LoungeParticipant.objects.filter(
            table__event_id=self.event_id, 
            user=self.user
        ).delete()
        print(f"[CONSUMER] User {self.user.username} (ID:{self.user.id}) left table. Deleted {deleted_count} participant record(s)")
        return deleted_count
