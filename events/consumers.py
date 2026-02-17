from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async
from .models import LoungeTable, LoungeParticipant, Event, EventRegistration
from django.contrib.auth.models import User
from django.db import transaction
from django.db.models import F
from django.utils import timezone
import random
import requests
import logging
from .utils import create_dyte_meeting, DYTE_API_BASE, _dyte_headers

logger = logging.getLogger(__name__)

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

        # Custom Logic: Auto-restore breakout room on reconnect
        try:
            er = await database_sync_to_async(EventRegistration.objects.select_related('last_breakout_table').get)(
                event_id=self.event_id, user=self.user
            )

            # Check if event is live and user had a previous breakout assignment
            event_is_live = await database_sync_to_async(lambda: Event.objects.filter(id=self.event_id, is_live=True).exists())()

            if event_is_live and er.last_breakout_table:
                table = er.last_breakout_table
                # Ensure the table still exists and is a Breakout Room
                if table and table.category == 'BREAKOUT':
                    print(f"[RECONNECT] Restoring user {self.user.id} to breakout room {table.id}")
                    ok, result = await self._restore_breakout_participant(table)
                    if ok:
                        print(f"[RECONNECT] ✅ Successfully restored to breakout room {table.id}, seat {result}")
                        
                        # Add to breakout group
                        await self.channel_layer.group_add(f"breakout_{table.id}", self.channel_name)

                        # Notify user to join Dyte meeting
                        # Include main room meeting ID so frontend can re-initialize the peek view
                        event = await database_sync_to_async(Event.objects.get)(id=self.event_id)
                        await self.send_json({
                            "type": "breakout_restored",
                            "table_id": table.id,
                            "table_name": table.name,
                            "dyte_meeting_id": table.dyte_meeting_id,
                            "main_room_meeting_id": event.dyte_meeting_id,
                        })
                        # 🔄 Broadcast lounge update so other participants see this user rejoined
                        # This ensures Christopher (and anyone else in the room) sees Ravikumar rejoin
                        await self.broadcast_lounge_update()
                    else:
                        print(f"[RECONNECT] ❌ Failed to restore breakout room: {result}")
                        await self.send_json({
                            "type": "breakout_restore_failed",
                            "message": f"Could not restore you to your previous Breakout Room: {result}",
                        })
        except EventRegistration.DoesNotExist:
            pass
        except Exception as e:
            print(f"[RECONNECT] Error auto-rejoining breakout: {e}")

        # Handle late joiners joining during active breakout sessions
        await self.handle_late_joiner_join()

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

            success, error, table = await self.join_table(table_id, seat_index)
            if success:
                print(f"[CONSUMER] join_table successful for {self.user.username}, broadcasting update...")
                
                # If breakout room, add to group
                if table and table.category == 'BREAKOUT':
                    await self.channel_layer.group_add(f"breakout_{table.id}", self.channel_name)

                await self.broadcast_lounge_update()
            else:
                print(f"[CONSUMER] join_table failed for {self.user.username}: {error}")
                await self.send_json({"type": "error", "message": error})

        elif action == "leave_table":
            print(f"[CONSUMER] User {self.user.username} requested to leave table")
            
            # Clear last_breakout_table assignment since user is manually leaving
            await database_sync_to_async(
                lambda: EventRegistration.objects.filter(event_id=self.event_id, user=self.user).update(last_breakout_table=None)
            )()

            success, table = await self.leave_current_table()
            if success and table and table.category == 'BREAKOUT':
                await self.channel_layer.group_discard(f"breakout_{table.id}", self.channel_name)
            
            await self.broadcast_lounge_update()

        elif action == "random_assign":
            try:
                per_room = int(content.get("per_room", 4))
                if not await self.is_host():
                    print(f"[CONSUMER] DENIED random_assign: User {self.user.username} is not a host.")
                    await self.send_debug_to_host("Action denied: Not a host")
                    return

                await self.perform_random_assignment_and_notify(per_room)
                await self._set_breakout_active_flag(True)
            except Exception as e:
                print(f"[CONSUMER] ERROR in random_assign: {str(e)}")
                await self.send_debug_to_host(f"Error during random assignment: {str(e)}")

        elif action == "manual_assign":
            try:
                if not await self.is_host():
                    print(f"[CONSUMER] DENIED manual_assign: User {self.user.username} is not a host.")
                    await self.send_debug_to_host("Action denied: Not a host")
                    return

                user_ids = content.get("user_ids", [])
                table_id = content.get("table_id")

                if not user_ids or not table_id:
                    await self.send_debug_to_host("Invalid manual assignment: missing user_ids or table_id")
                    return

                await self.perform_manual_assignment_and_notify(user_ids, table_id)
                # If we are manually assigning to a breakout room, we should consider breakouts active
                # We need to check if the table is a breakout room
                table = await database_sync_to_async(LoungeTable.objects.get)(id=table_id)
                if table.category == 'BREAKOUT':
                    await self._set_breakout_active_flag(True)
            except Exception as e:
                print(f"[CONSUMER] ERROR in manual_assign: {str(e)}")
                await self.send_debug_to_host(f"Error during manual assignment: {str(e)}")

        elif action == "assign_late_joiner":
            try:
                if not await self.is_host():
                    print(f"[CONSUMER] DENIED assign_late_joiner: User {self.user.username} is not a host.")
                    await self.send_debug_to_host("Action denied: Not a host")
                    return

                participant_id = content.get("participant_id")
                room_id = content.get("room_id")

                if not participant_id or not room_id:
                    await self.send_debug_to_host("assign_late_joiner: missing participant_id or room_id")
                    return

                print(f"[ASSIGN] Host assigning late joiner {participant_id} to room {room_id}")
                table, error = await self._assign_late_joiner_to_room_db(
                    participant_id, room_id, self.user.id, method='manual'
                )
                if error:
                    await self.send_debug_to_host(f"Failed to assign: {error}")
                    return

                print(f"[ASSIGN] ✅ Assigned user {participant_id} to room {table.id}")
                # Notify participant to join the room
                # We send BOTH notification (for toast) and force_join (for action)
                # to ensure the frontend actually moves the user.
                await self.channel_layer.group_send(
                    f"user_{participant_id}",
                    {
                        "type": "late_joiner_assigned",
                        "room_id": table.id,
                        "room_name": table.name,
                        "dyte_meeting_id": table.dyte_meeting_id,
                        "method": "manual",
                    }
                )
                await self.channel_layer.group_send(
                    f"user_{participant_id}",
                    {
                        "type": "breakout_force_join",
                        "user_id": participant_id,
                        "table_id": table.id
                    }
                )

                # NEW: Notify existing room members to refresh their list/view
                await self.channel_layer.group_send(
                    f"breakout_{table.id}",
                    {
                        "type": "refresh_breakout_participants",
                        "room_id": table.id,
                        "dyte_meeting_id": table.dyte_meeting_id
                    }
                )

                await self.broadcast_lounge_update()
            except Exception as e:
                print(f"[CONSUMER] ERROR in assign_late_joiner: {str(e)}")
                await self.send_debug_to_host(f"Error assigning late joiner: {str(e)}")

        elif action == "dismiss_late_joiner":
            try:
                if not await self.is_host():
                    print(f"[CONSUMER] DENIED dismiss_late_joiner: User {self.user.username} is not a host.")
                    await self.send_debug_to_host("Action denied: Not a host")
                    return

                participant_id = content.get("participant_id")
                if not participant_id:
                    await self.send_debug_to_host("dismiss_late_joiner: missing participant_id")
                    return

                print(f"[DISMISS] Host dismissing late joiner {participant_id} - stays in main room")
                await self._mark_late_joiner_main_room(participant_id)

                # Notify participant they stay in main room
                await self.channel_layer.group_send(
                    f"user_{participant_id}",
                    {"type": "late_joiner_dismissed", "message": "You will remain in the Main Room."}
                )
            except Exception as e:
                print(f"[CONSUMER] ERROR in dismiss_late_joiner: {str(e)}")
                await self.send_debug_to_host(f"Error dismissing late joiner: {str(e)}")

        elif action == "auto_assign_late_joiners":
            try:
                if not await self.is_host():
                    print(f"[CONSUMER] DENIED auto_assign_late_joiners: User {self.user.username} is not a host.")
                    await self.send_debug_to_host("Action denied: Not a host")
                    return

                enabled = content.get("enabled", False)
                strategy = content.get("strategy", "least")

                print(f"[AUTO_ASSIGN] Setting auto-assign: enabled={enabled}, strategy={strategy}")
                await database_sync_to_async(
                    lambda: Event.objects.filter(id=self.event_id).update(
                        auto_assign_late_joiners=enabled,
                        auto_assign_strategy=strategy
                    )
                )()

                await self.send_debug_to_host(
                    f"Auto-assign {'enabled' if enabled else 'disabled'} with strategy '{strategy}'"
                )
            except Exception as e:
                print(f"[CONSUMER] ERROR in auto_assign_late_joiners: {str(e)}")
                await self.send_debug_to_host(f"Error updating auto-assign: {str(e)}")

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
            await self._set_breakout_active_flag(False)
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

    # --- Admission Status Handlers ---
    async def admission_status_changed(self, event):
        """
        ✅ NEW: Notify user that their admission status has changed.
        Handles: "waiting" → "admitted" or "waiting" → "rejected"
        Frontend receives this and updates button state.
        """
        await self.send_json({
            "type": "admission_status_changed",
            "admission_status": event.get("data", {}).get("admission_status")
        })

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

    async def speed_networking_match_ended(self, event):
        """Notify user that their match has ended and they should return to queue."""
        await self.send_json({
            "type": "speed_networking_match_ended",
            "data": event["data"]
        })

    async def speed_networking_queue_update(self, event):
        """Broadcast queue stats update to all clients in the event (for host panel real-time refresh)."""
        await self.send_json({
            "type": "speed_networking_queue_update",
            "data": event["data"]
        })

    async def broadcast_message(self, event: dict) -> None:
        await self.send_json({"type": "message", "data": event["payload"]})

    async def server_debug(self, event: dict) -> None:
        """Handler for 'server_debug' group message."""
        await self.send_json({
            "type": "server_debug",
            "message": event["message"]
        })

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

    # ✅ NEW: Waiting room announcement handler
    async def waiting_room_announcement(self, event: dict) -> None:
        """Handler for announcements sent to waiting room participants."""
        await self.send_json({
            "type": "waiting_room_announcement",
            "event_id": event.get("event_id"),
            "message": event.get("message"),
            "sender_name": event.get("sender_name", "Host"),
            "timestamp": event.get("timestamp"),
        })

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

    async def meeting_started(self, event: dict) -> None:
        """Broadcast notification that the host has started the meeting.

        Participants should transition from waiting screen to live meeting view.
        """
        await self.send_json({
            "type": "meeting_started",
            "event_id": event.get("event_id"),
            "status": event.get("status"),
            "started_at": event.get("started_at"),
        })

    async def breakout_force_join(self, event: dict) -> None:
        """Targeted force join for specific user"""
        print(f"[HANDLER] breakout_force_join: self.user.id={self.user.id}, target={event['user_id']}")
        if str(self.user.id) == str(event["user_id"]):
            print(f"[HANDLER] ✅ Sending force_join_breakout to user {self.user.id}")
            await self.send_json({
                "type": "force_join_breakout",
                "table_id": event["table_id"]
            })
        else:
            print(f"[HANDLER] ⚠️ breakout_force_join mismatch: {self.user.id} != {event['user_id']}")

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
                "type": "server_debug",  # ✅ FIXED: Match frontend expectation
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
        # Clear assignments
        EventRegistration.objects.filter(event_id=self.event_id).update(last_breakout_table=None)
        # Remove participants
        LoungeParticipant.objects.filter(table__event_id=self.event_id).delete()

    @database_sync_to_async
    def perform_random_assignment(self, per_room):
        print(f"[RANDOM_ASSIGN] Starting: event={self.event_id}, per_room={per_room}")
        # 1. Get all online participants (excluding host)
        registrations = EventRegistration.objects.filter(
            event_id=self.event_id,
            is_online=True,
            admission_status="admitted",
            joined_live=True,
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

        # 3. Perform assignments with proper validation
        assignments = []

        try:
            with transaction.atomic():
                # Clear all current assignments in the event
                LoungeParticipant.objects.filter(table__event_id=self.event_id).delete()

                # ✅ FIX #2A: Proper round-robin assignment with validation
                for idx, user in enumerate(users):
                    table_idx = idx % len(tables)
                    table = tables[table_idx]
                    seat_index = idx // len(tables)  # ✅ FIXED: Proper seat calculation

                    # ✅ NEW: Verify user isn't already assigned
                    existing = LoungeParticipant.objects.filter(
                        user=user,
                        table__event_id=self.event_id
                    ).exists()
                    if existing:
                        print(f"[RANDOM_ASSIGN] ⚠️ User {user.id} already assigned, skipping duplicate")
                        continue

                    # Create assignment record
                    lounge_participant = LoungeParticipant.objects.create(
                        table=table,
                        user=user,
                        seat_index=seat_index
                    )

                    # Save assignment if breakout
                    if table.category == 'BREAKOUT':
                        EventRegistration.objects.filter(event_id=self.event_id, user=user).update(last_breakout_table=table)

                    assignments.append((user.id, table.id, table.dyte_meeting_id))

                    print(f"[RANDOM_ASSIGN] ✅ Assigned user {user.id} to table {table.id} "
                          f"(meeting {table.dyte_meeting_id}), seat_index={seat_index}")

                # ✅ NEW: Validate all assignments were created
                total_assigned = LoungeParticipant.objects.filter(
                    table__event_id=self.event_id
                ).count()
                print(f"[RANDOM_ASSIGN] Total assignments: {len(assignments)}, DB count: {total_assigned}")

                if len(assignments) != total_assigned:
                    print(f"[RANDOM_ASSIGN] ⚠️ Assignment count mismatch: "
                          f"expected {len(assignments)}, got {total_assigned}")

        except Exception as e:
            print(f"[RANDOM_ASSIGN] ❌ Failed to perform random assignment: {e}")
            return []

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

        # ✅ FIX: Notify each assigned user via the group
        # Assignments now include meeting_id for better debugging
        for assignment in assignments:
            user_id = assignment[0]
            table_id = assignment[1]
            await self.channel_layer.group_send(
                f"user_{user_id}",
                {
                    "type": "breakout_force_join",
                    "user_id": user_id,
                    "table_id": table_id
                }
            )

    async def perform_manual_assignment_and_notify(self, user_ids, table_id):
        """Perform manual assignment and notify assigned users."""
        assignments = await database_sync_to_async(self._perform_manual_assignment_sync_handler)(user_ids, table_id)

        if not assignments:
            msg = "❌ Manual assignment failed: No participants could be assigned. Possible reasons: user not found, table is full, or user doesn't meet criteria."
            print(f"[MANUAL_ASSIGN] {msg}")
            await self.send_debug_to_host(msg)
            return

        msg = f"✅ Successfully assigned {len(assignments)} participant(s) to the breakout room!"
        print(f"[MANUAL_ASSIGN] {msg}")
        await self.send_debug_to_host(msg)
        await self.broadcast_lounge_update()

        # Notify each assigned user to join the room
        for assignment in assignments:
            user_id = assignment[0]
            table_id = assignment[1]
            await self.channel_layer.group_send(
                f"user_{user_id}",
                {
                    "type": "breakout_force_join",
                    "user_id": user_id,
                    "table_id": table_id
                }
            )

    def _perform_manual_assignment_sync_handler(self, user_ids, table_id):
        """Assign specific users to a specific table. (Sync version for async wrapper)"""
        print(f"[MANUAL_ASSIGN] Starting: event={self.event_id}, table={table_id}, users={user_ids}")

        try:
            # Verify table exists
            try:
                table = LoungeTable.objects.get(id=table_id, event_id=self.event_id)
            except LoungeTable.DoesNotExist:
                print(f"[MANUAL_ASSIGN] ❌ Table {table_id} not found in event {self.event_id}")
                return []

            # Get valid users for assignment
            # Note: We use looser criteria since these are participants already in the meeting
            print(f"[MANUAL_ASSIGN] User IDs to assign: {user_ids}, Host ID: {self.user.id}")

            all_registered = EventRegistration.objects.filter(
                event_id=self.event_id,
                user_id__in=user_ids
            ).exclude(user_id=self.user.id)

            print(f"[MANUAL_ASSIGN] Found {all_registered.count()} registered users after filtering")
            for reg in all_registered:
                print(f"[MANUAL_ASSIGN]   User {reg.user.username} (ID:{reg.user_id}): online={reg.is_online}, admitted={reg.admission_status}, joined_live={reg.joined_live}")

            # Prefer users who are explicitly marked as online/admitted, but accept joined users
            valid_users = all_registered.filter(
                admission_status__in=["admitted", "registered"]
            ).exclude(user_id=self.user.id).values_list('user_id', flat=True)

            print(f"[MANUAL_ASSIGN] Valid users after admission status filter: {list(valid_users)}")

            if not valid_users:
                # If no strictly valid users, accept anyone registered for the event
                valid_users = all_registered.values_list('user_id', flat=True)
                print(f"[MANUAL_ASSIGN] Using looser criteria, found {len(list(valid_users))} users: {list(valid_users)}")

            if not valid_users:
                print(f"[MANUAL_ASSIGN] ❌ No valid users found in {user_ids}")
                print(f"[MANUAL_ASSIGN] All registered users count: {EventRegistration.objects.filter(event_id=self.event_id).count()}")
                return []

            # Clear any existing assignments for these users
            LoungeParticipant.objects.filter(user_id__in=valid_users).delete()

            # Assign each user to the table
            assignments = []
            for user_id in valid_users:
                # Find an available seat
                occupied_seats = set(
                    LoungeParticipant.objects.filter(table_id=table_id).values_list('seat_index', flat=True)
                )
                available_seats = [i for i in range(table.max_seats) if i not in occupied_seats]

                if not available_seats:
                    print(f"[MANUAL_ASSIGN] ⚠️ Table {table_id} is full, skipping user {user_id}")
                    continue

                seat_index = available_seats[0]

                participant = LoungeParticipant.objects.create(
                    table=table,
                    user_id=user_id,
                    seat_index=seat_index
                )

                # Check if it's a breakout room and save assignment
                if table.category == 'BREAKOUT':
                    EventRegistration.objects.filter(event_id=self.event_id, user_id=user_id).update(last_breakout_table=table)

                assignments.append((user_id, table_id))
                print(f"[MANUAL_ASSIGN] ✅ Assigned user {user_id} to table {table_id}, seat {seat_index}")

            print(f"[MANUAL_ASSIGN] Completed: Created {len(assignments)} assignments.")
            return assignments

        except Exception as e:
            print(f"[MANUAL_ASSIGN] ❌ Failed to perform manual assignment: {e}")
            return []

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
                participants[str(p.seat_index)] = {
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
    def _restore_breakout_participant(self, table):
        """Re-seat user in their previous breakout room after page reload.
        Clears stale participant records then creates a fresh entry.
        Returns (True, seat_index) or (False, reason_string).
        """
        try:
            with transaction.atomic():
                # Clear any stale lounge records for this user
                LoungeParticipant.objects.filter(
                    table__event_id=self.event_id,
                    user=self.user
                ).delete()

                # Find the first available seat
                occupied = set(
                    LoungeParticipant.objects.filter(table=table)
                    .values_list('seat_index', flat=True)
                )
                seat = next(
                    (i for i in range(max(table.max_seats, 1)) if i not in occupied),
                    None
                )
                if seat is None:
                    return False, "Breakout room is full"

                LoungeParticipant.objects.create(
                    table=table,
                    user=self.user,
                    seat_index=seat
                )
                # Keep last_breakout_table in EventRegistration (already set)
                return True, seat
        except Exception as e:
            print(f"[RECONNECT] Error in _restore_breakout_participant: {e}")
            return False, str(e)

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
                    return False, "Seat already occupied", None

                # 3. Create participant
                LoungeParticipant.objects.create(
                    table_id=table_id,
                    user=self.user,
                    seat_index=seat_index
                )
                
                # Check if it's a breakout room and save assignment
                table = LoungeTable.objects.get(id=table_id)
                if table.category == 'BREAKOUT':
                    EventRegistration.objects.filter(event_id=self.event_id, user=self.user).update(last_breakout_table=table)
                else:
                    # If joining a non-breakout table (e.g. lounge), clear the tracked breakout room
                    EventRegistration.objects.filter(event_id=self.event_id, user=self.user).update(last_breakout_table=None)

                print(f"[CONSUMER] join_table: Created record for user {self.user.id} at table {table_id} seat {seat_index}")
                return True, None, table
        except Exception as e:
            print(f"[CONSUMER] join_table error: {e}")
            return False, str(e), None

    @database_sync_to_async
    def leave_current_table(self):
        """
        Remove user from current lounge table.
        Deletes from both Django DB AND Dyte meeting to prevent 409 conflicts on rejoin.
        """
        try:
            # 1. Find the current table participant record
            lounge_record = LoungeParticipant.objects.filter(
                table__event_id=self.event_id,
                user=self.user
            ).first()

            if not lounge_record:
                logger.info(f"[CONSUMER] No lounge record found for user {self.user.id}")
                return 0, None

            table = lounge_record.table
            meeting_id = table.dyte_meeting_id
            dyte_participant_id = lounge_record.dyte_participant_id

            # 2. Remove from Dyte meeting FIRST (before deleting DB record)
            if meeting_id:
                try:
                    # If we have the Dyte participant ID, use it directly for faster removal
                    if dyte_participant_id:
                        delete_resp = requests.delete(
                            f"{DYTE_API_BASE}/meetings/{meeting_id}/participants/{dyte_participant_id}",
                            headers=_dyte_headers(),
                            timeout=10,
                        )
                        if delete_resp.ok:
                            logger.info(f"[CONSUMER] Removed user {self.user.id} from Dyte meeting {meeting_id} "
                                      f"(participant_id: {dyte_participant_id})")
                        else:
                            logger.warning(f"[CONSUMER] Failed to remove user from Dyte: {delete_resp.status_code}")
                    else:
                        # Fallback: Query Dyte to find the participant by client_specific_id
                        resp = requests.get(
                            f"{DYTE_API_BASE}/meetings/{meeting_id}/participants",
                            headers=_dyte_headers(),
                            params={"limit": 100},
                            timeout=10,
                        )
                        if resp.ok:
                            participants = resp.json().get("data", [])
                            for p in participants:
                                cid = p.get("client_specific_id") or p.get("custom_participant_id")
                                if cid == str(self.user.id):
                                    # Found the user in Dyte, now remove them
                                    participant_id = p.get("id")
                                    delete_resp = requests.delete(
                                        f"{DYTE_API_BASE}/meetings/{meeting_id}/participants/{participant_id}",
                                        headers=_dyte_headers(),
                                        timeout=10,
                                    )
                                    if delete_resp.ok:
                                        logger.info(f"[CONSUMER] Removed user {self.user.id} from Dyte meeting {meeting_id}")
                                    else:
                                        logger.warning(f"[CONSUMER] Failed to remove user from Dyte: {delete_resp.status_code}")
                                    break
                except Exception as e:
                    logger.warning(f"[CONSUMER] Error removing from Dyte: {e}")
                    # Don't fail the entire leave operation if Dyte removal fails

            # 3. Delete from Django DB
            lounge_record.delete()

            logger.info(f"[CONSUMER] User {self.user.username} (ID:{self.user.id}) left table. "
                       f"Removed from both Django and Dyte.")
            return 1, table

        except Exception as e:
            logger.error(f"[CONSUMER] leave_current_table error: {e}")
            return 0, None

    # ===== Late Joiner WebSocket Message Handlers =====

    async def late_joiner_notification(self, event):
        """
        Receive late joiner notification and send to WebSocket.
        This is sent to the HOST/ADMIN when a new participant joins during active breakout sessions.
        """
        print(f"[HANDLER] late_joiner_notification called with event: {event}")
        # Only send to hosts
        if not await self.is_host():
            print(f"[HANDLER] late_joiner_notification: User {self.user.id} is not a host - dropping message")
            return

        await self.send_json({
            "type": "late_joiner_notification",
            "notification": event.get("notification")
        })
        print(f"[HANDLER] ✅ Sent late_joiner_notification to host {self.user.id}")

    async def late_joiner_assigned(self, event):
        """
        Receive assignment notification and send to WebSocket.
        This is sent to the PARTICIPANT when host assigns them to a breakout room.
        """
        print(f"[HANDLER] late_joiner_assigned called with event: {event}")
        await self.send_json({
            "type": "late_joiner_assigned",
            "room_id": event.get("room_id"),
            "room_name": event.get("room_name"),
            "dyte_meeting_id": event.get("dyte_meeting_id"),
            "method": event.get("method", "manual")
        })
        print(f"[HANDLER] ✅ Sent late_joiner_assigned to participant")

    async def late_joiner_dismissed(self, event):
        """
        Receive dismissal notification and send to WebSocket.
        This is sent to the PARTICIPANT when host decides to keep them in main room.
        """
        print(f"[HANDLER] late_joiner_dismissed called with event: {event}")
        await self.send_json({
            "type": "late_joiner_dismissed",
            "message": event.get("message", "You will remain in the Main Room.")
        })
        print(f"[HANDLER] ✅ Sent late_joiner_dismissed to participant")

    async def refresh_breakout_participants(self, event):
        """
        Receive refresh notification and send to WebSocket.
        This is sent to all participants in a breakout room when a new participant is assigned.
        Tells them to refresh their participant list.
        """
        print(f"[HANDLER] refresh_breakout_participants called for room: {event.get('room_id')}")
        await self.send_json({
            "type": "refresh_breakout_participants",
            "room_id": event.get("room_id"),
            "dyte_meeting_id": event.get("dyte_meeting_id"),
            "message": "A new participant has been assigned to this room. Refreshing participant list..."
        })
        print(f"[HANDLER] ✅ Sent refresh_breakout_participants notification")

    # ===== LATE JOINER DETECTION & HANDLING =====

    async def handle_late_joiner_join(self):
        """Detect and handle late joiners during active breakout sessions."""
        try:
            print(f"[LATE_JOINER] Starting late joiner check for user {self.user.id}...")

            # 1. Check if breakout rooms are marked as active in the Event model
            # This is the primary source of truth.
            event_obj = await self.get_event()
            if not event_obj.breakout_rooms_active:
                # Double check with participant count just in case flag is out of sync (defensive)
                has_active = await self._check_active_breakout_rooms()
                if not has_active:
                    print(f"[LATE_JOINER] No active breakout rooms (flag=False, count=0) - skipping")
                    return
                else:
                    print(f"[LATE_JOINER] Flag is False but participants found - treating as active")
                    # Auto-correct the flag
                    await self._set_breakout_active_flag(True)

            # 2. Skip hosts
            is_host = await self.is_host()
            print(f"[LATE_JOINER] User is host: {is_host}")
            if is_host:
                return

            # 3. Skip reconnects (user already had a breakout assignment)
            try:
                er = await database_sync_to_async(
                    EventRegistration.objects.select_related('last_breakout_table').get
                )(event_id=self.event_id, user=self.user)
                if er.last_breakout_table:
                    print(f"[LATE_JOINER] User has previous breakout assignment - skipping")
                    return
            except EventRegistration.DoesNotExist:
                print(f"[LATE_JOINER] No EventRegistration found - skipping")
                return

            # 4. Create/get BreakoutJoiner record
            joiner = await self._create_or_get_late_joiner()
            if joiner is None:
                print(f"[LATE_JOINER] Late joiner already handled - skipping")
                return

            print(f"[LATE_JOINER] Created/got late joiner record: {joiner.id}")

            # 5. Get available rooms
            available_rooms = await self._get_available_breakout_rooms()
            print(f"[LATE_JOINER] Found {len(available_rooms)} available rooms")

            # 6. Check if auto-assign is enabled
            event = await self._get_event_with_breakout_settings()
            if event.auto_assign_late_joiners and available_rooms:
                print(f"[LATE_JOINER] Auto-assign enabled - assigning to room")
                await self._auto_assign_late_joiner(joiner, event, available_rooms)
                return

            # 7. Notify participant they are waiting
            print(f"[LATE_JOINER] Sending waiting message to participant")
            await self.send_json({
                "type": "waiting_for_breakout_assignment",
                "message": "Breakout sessions are in progress. The host will assign you shortly.",
                "joined_at": joiner.joined_at.isoformat() if joiner.joined_at else None,
            })

            # 8. Notify host
            print(f"[LATE_JOINER] Sending notification to host")
            participant_info = {
                'id': self.user.id,
                'full_name': self.user.get_full_name() or self.user.username,
                'email': self.user.email,
            }
            notification_data = {
                "late_joiner_id": joiner.id,
                "participant_id": self.user.id,
                "participant_name": participant_info['full_name'],
                "participant_email": participant_info['email'],
                "available_rooms": available_rooms,
                "can_auto_assign": bool(available_rooms),
            }
            print(f"[LATE_JOINER] Broadcasting notification: {notification_data}")
            await self.channel_layer.group_send(
                self.group_name,
                {"type": "late_joiner_notification", "notification": notification_data}
            )
            print(f"[LATE_JOINER] ✅ Notification sent to host")
            await self._notify_late_joiner_host_db(joiner.id)

        except Exception as e:
            print(f"[LATE_JOINER] ❌ Error in handle_late_joiner_join: {e}")
            import traceback
            traceback.print_exc()

    async def _auto_assign_late_joiner(self, joiner, event, available_rooms):
        """Auto-assign a late joiner based on the configured strategy."""
        try:
            strategy = event.auto_assign_strategy or 'least'
            target_room = None

            if strategy == 'least':
                print(f"[LATE_JOINER_AUTO] Using 'least' strategy")
                target_room = min(available_rooms, key=lambda r: r['current_participants'])
            elif strategy == 'round_robin':
                print(f"[LATE_JOINER_AUTO] Using 'round_robin' strategy")
                target_room = available_rooms[self.user.id % len(available_rooms)]
            else:  # sequential
                print(f"[LATE_JOINER_AUTO] Using 'sequential' strategy")
                target_room = available_rooms[0]

            if not target_room:
                print(f"[LATE_JOINER_AUTO] No target room found")
                return

            print(f"[LATE_JOINER_AUTO] Auto-assigning to room {target_room['id']}")
            table, error = await self._assign_late_joiner_to_room_db(
                self.user.id, target_room['id'], None, method='auto'
            )
            if table:
                print(f"[LATE_JOINER_AUTO] ✅ Auto-assigned to room {table.id}")
                await self.channel_layer.group_send(
                    f"user_{self.user.id}",
                    {
                        "type": "late_joiner_assigned",
                        "room_id": table.id,
                        "room_name": table.name,
                        "dyte_meeting_id": table.dyte_meeting_id,
                        "method": "auto",
                    }
                )
                await self.channel_layer.group_send(
                    f"user_{self.user.id}",
                    {
                        "type": "breakout_force_join",
                        "user_id": self.user.id,
                        "table_id": table.id
                    }
                )

                # Add to breakout group since we are on the user's connection
                await self.channel_layer.group_add(f"breakout_{table.id}", self.channel_name)

                # NEW: Notify existing room members to refresh their list/view
                await self.channel_layer.group_send(
                    f"breakout_{table.id}",
                    {
                        "type": "refresh_breakout_participants",
                        "room_id": table.id,
                        "dyte_meeting_id": table.dyte_meeting_id
                    }
                )

                await self.broadcast_lounge_update()
        except Exception as e:
            print(f"[LATE_JOINER_AUTO] ❌ Error auto-assigning: {e}")

    @database_sync_to_async
    def _check_active_breakout_rooms(self):
        """Returns True if any BREAKOUT table has participants."""
        from events.models import LoungeParticipant
        return LoungeParticipant.objects.filter(
            table__event_id=self.event_id,
            table__category='BREAKOUT'
        ).exists()

    @database_sync_to_async
    def _get_event_with_breakout_settings(self):
        """Get event with breakout settings."""
        return Event.objects.get(id=self.event_id)

    @database_sync_to_async
    def _create_or_get_late_joiner(self):
        """Create or retrieve BreakoutJoiner record for this user."""
        from events.models import BreakoutJoiner
        obj, created = BreakoutJoiner.objects.get_or_create(
            event_id=self.event_id,
            user=self.user,
            defaults={'status': 'waiting'}
        )
        if not created and obj.status in ('assigned', 'auto_assigned', 'main_room'):
            return None  # Already handled
        if not created:
            # Update to waiting if status was expired
            obj.status = 'waiting'
            obj.save(update_fields=['status'])
        return obj

    @database_sync_to_async
    def _get_available_breakout_rooms(self):
        """Return list of BREAKOUT tables with available seats."""
        from events.models import LoungeTable, LoungeParticipant
        tables = LoungeTable.objects.filter(
            event_id=self.event_id,
            category='BREAKOUT'
        ).prefetch_related('participants')
        available = []
        for t in tables:
            current = t.participants.count()
            if current < t.max_seats:
                available.append({
                    'id': t.id,
                    'name': t.name,
                    'current_participants': current,
                    'max_seats': t.max_seats,
                    'available_seats': t.max_seats - current,
                    'dyte_meeting_id': t.dyte_meeting_id,
                })
        return available

    @database_sync_to_async
    def _notify_late_joiner_host_db(self, joiner_id):
        """Update host_notified + notified_host_at in DB."""
        from django.utils import timezone
        from events.models import BreakoutJoiner
        BreakoutJoiner.objects.filter(id=joiner_id).update(
            host_notified=True,
            notified_host_at=timezone.now(),
            notification_sent_count=F('notification_sent_count') + 1
        )

    @database_sync_to_async
    def _assign_late_joiner_to_room_db(self, participant_id, room_id, assigned_by_id, method='manual'):
        """Assign the late joiner to a room, create LoungeParticipant record."""
        from django.utils import timezone
        from django.db import transaction
        from events.models import BreakoutJoiner, LoungeTable, LoungeParticipant

        with transaction.atomic():
            joiner = BreakoutJoiner.objects.select_for_update().get(
                event_id=self.event_id, user_id=participant_id
            )
            table = LoungeTable.objects.get(id=room_id, event_id=self.event_id)

            # Clear any existing seat
            LoungeParticipant.objects.filter(
                table__event_id=self.event_id, user_id=participant_id
            ).delete()

            # Find available seat
            occupied = set(LoungeParticipant.objects.filter(table=table).values_list('seat_index', flat=True))
            seat = next((i for i in range(table.max_seats) if i not in occupied), None)
            if seat is None:
                return None, "Room is full"

            LoungeParticipant.objects.create(table=table, user_id=participant_id, seat_index=seat)
            EventRegistration.objects.filter(event_id=self.event_id, user_id=participant_id).update(
                last_breakout_table=table
            )

            joiner.status = 'assigned' if method == 'manual' else 'auto_assigned'
            joiner.assigned_at = timezone.now()
            joiner.assigned_room = table
            joiner.assigned_by_id = assigned_by_id
            joiner.assignment_method = method
            joiner.save()
            return table, None

    @database_sync_to_async
    def _mark_late_joiner_main_room(self, participant_id):
        """Mark the late joiner as staying in main room."""
        from events.models import BreakoutJoiner
        BreakoutJoiner.objects.filter(event_id=self.event_id, user_id=participant_id).update(
            status='main_room', assignment_method='none'
        )

    @database_sync_to_async
    def _expire_all_late_joiners(self):
        """Called when breakout rooms end. Expire waiting joiners."""
        from events.models import BreakoutJoiner
        BreakoutJoiner.objects.filter(
            event_id=self.event_id, status='waiting'
        ).update(status='expired')

    @database_sync_to_async
    def _set_breakout_active_flag(self, active: bool):
        """Set the breakout_rooms_active flag on the event."""
        Event.objects.filter(id=self.event_id).update(breakout_rooms_active=active)
