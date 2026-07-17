"""
Admin views for managing promotional profiles.

Provides:
- List view with filtering and sorting
- Bulk actions (send reminders, export, mark complete)
- Progress summary by role
- Export endpoints
"""
import csv
import logging
from django.utils import timezone
from django.http import HttpResponse
from django.db.models import Q, Count, F, Case, When, CharField, Value
from django.db.models.functions import Concat
from rest_framework import viewsets, status, serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from events.models import (
    Event, PostAcceptanceFormAssignment,
    PostAcceptanceFormSubmission, EventParticipant, AdminAuditLog
)
from events.serializers import PostAcceptanceFormAssignmentSerializer
from events.permissions import IsEventStaff

logger = logging.getLogger('events')


class PromotionalProfileSerializer(serializers.ModelSerializer):
    """Serializer for promotional profile admin list."""
    attendee_name = serializers.CharField(read_only=True)
    attendee_email = serializers.CharField(read_only=True)
    display_consent = serializers.CharField(source='event_registration.display_consent', read_only=True)

    class Meta:
        model = PostAcceptanceFormAssignment
        fields = [
            'id', 'event', 'form_type', 'status', 'deadline',
            'started_at', 'completed_at', 'reminders_sent',
            'attendee_name', 'attendee_email', 'active_modules',
            'display_consent', 'last_reminder_sent_at'
        ]
        read_only_fields = fields


class PromotionalProfileAdminViewSet(viewsets.ModelViewSet):
    """
    Admin viewset for managing promotional profiles.

    Provides:
    - List all profiles with detailed metadata
    - Filter by role, status, module completion, consent
    - Bulk actions (reminders, exports, manual completion)
    - Progress summary by role
    """
    permission_classes = [IsAuthenticated, IsEventStaff]
    serializer_class = PromotionalProfileSerializer

    def get_queryset(self):
        """Get promotional profile assignments with related data."""
        event_id = self.kwargs.get('event_id')

        queryset = PostAcceptanceFormAssignment.objects.filter(
            event_id=event_id,
            form_type='promotional_profile',
            is_deleted=False,
        ).select_related(
            'event_registration__user',
            'form_template',
            'event'
        ).prefetch_related(
            'submission__answers'
        ).annotate(
            attendee_name=Concat(
                F('event_registration__user__first_name'),
                Value(' '),
                F('event_registration__user__last_name'),
                output_field=CharField()
            ),
            attendee_email=F('event_registration__user__email')
        )

        return queryset

    def filter_queryset(self, queryset):
        """Apply filters from query params."""
        # Filter by role
        role = self.request.query_params.get('role')
        if role:
            queryset = queryset.filter(active_modules__contains=[role])

        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        # Filter by display consent
        consent = self.request.query_params.get('display_consent')
        if consent:
            if consent == 'denied':
                queryset = queryset.filter(
                    event_registration__display_consent='no'
                )
            elif consent == 'granted':
                queryset = queryset.filter(
                    event_registration__display_consent='yes'
                )
            elif consent == 'pending':
                queryset = queryset.filter(
                    event_registration__display_consent__isnull=True
                )

        # Filter by module completion
        module = self.request.query_params.get('module')
        if module:
            # Check if module is in active_modules
            queryset = queryset.filter(active_modules__contains=[module])

        # Filter by missing assets
        missing = self.request.query_params.get('missing_assets')
        if missing:
            if missing == 'headshot':
                # Find speaker modules without headshot submission
                queryset = self._filter_missing_headshot(queryset)
            elif missing == 'logo':
                queryset = self._filter_missing_logo(queryset)
            elif missing == 'pitch_deck':
                queryset = self._filter_missing_pitch_deck(queryset)

        # Search by name or email
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(event_registration__user__first_name__icontains=search) |
                Q(event_registration__user__last_name__icontains=search) |
                Q(event_registration__user__email__icontains=search)
            )

        return queryset

    def _filter_missing_headshot(self, queryset):
        """Filter for speaker modules missing headshot."""
        from events.models import PostAcceptanceFormAnswer

        # Get assignments with speaker module
        speaker_assignments = queryset.filter(active_modules__contains=['speaker'])

        # Get those without headshot answer
        completed = PostAcceptanceFormAnswer.objects.filter(
            submission__assignment__in=speaker_assignments,
            question_key='headshot'
        ).values_list('submission__assignment_id', flat=True)

        return speaker_assignments.exclude(id__in=completed)

    def _filter_missing_logo(self, queryset):
        """Filter for sponsor modules missing logo."""
        from events.models import PostAcceptanceFormAnswer

        sponsor_assignments = queryset.filter(
            Q(active_modules__contains=['sponsor']) |
            Q(active_modules__contains=['startup'])
        )

        # Sponsor logo
        sponsor_logo = PostAcceptanceFormAnswer.objects.filter(
            submission__assignment__in=sponsor_assignments.filter(
                active_modules__contains=['sponsor']
            ),
            question_key='organisation_logo'
        ).values_list('submission__assignment_id', flat=True)

        # Startup logo
        startup_logo = PostAcceptanceFormAnswer.objects.filter(
            submission__assignment__in=sponsor_assignments.filter(
                active_modules__contains=['startup']
            ),
            question_key='company_logo'
        ).values_list('submission__assignment_id', flat=True)

        completed_ids = list(sponsor_logo) + list(startup_logo)
        return sponsor_assignments.exclude(id__in=completed_ids)

    def _filter_missing_pitch_deck(self, queryset):
        """Filter for startup modules missing pitch deck."""
        from events.models import PostAcceptanceFormAnswer

        startup_assignments = queryset.filter(active_modules__contains=['startup'])

        completed = PostAcceptanceFormAnswer.objects.filter(
            submission__assignment__in=startup_assignments,
            question_key='public_pitch_deck'
        ).values_list('submission__assignment_id', flat=True)

        return startup_assignments.exclude(id__in=completed)

    @action(detail=False, methods=['get'])
    def summary(self, request, event_id=None):
        """
        Get progress summary by role.

        Returns counts of complete/incomplete for each role.
        """
        queryset = self.get_queryset()
        event_id = self.kwargs.get('event_id')

        # Get all promotional profile assignments for this event
        all_assignments = queryset.count()

        # Count by role
        summary = {
            'total': all_assignments,
            'by_role': {}
        }

        # Get unique roles from active_modules
        roles = ['speaker', 'sponsor', 'sponsor_staff', 'startup', 'investor']

        for role in roles:
            role_assignments = queryset.filter(active_modules__contains=[role])
            role_count = role_assignments.count()
            completed_count = role_assignments.filter(
                status='completed'
            ).count()

            summary['by_role'][role] = {
                'total': role_count,
                'completed': completed_count,
                'pending': role_count - completed_count,
                'percentage': round((completed_count / role_count * 100) if role_count > 0 else 0)
            }

        return Response(summary)

    @action(detail=False, methods=['post'])
    def bulk_send_reminders(self, request, event_id=None):
        """
        Send reminders to multiple incomplete profiles.

        Body:
        {
            "assignment_ids": [1, 2, 3],
            "message": "Optional custom message"
        }
        """
        from events.services.post_acceptance_forms import send_form_assignment_email

        assignment_ids = request.data.get('assignment_ids', [])
        if not assignment_ids:
            return Response(
                {'error': 'No assignment IDs provided'},
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = self.get_queryset()
        assignments = queryset.filter(
            id__in=assignment_ids,
            status__in=['not_started', 'in_progress']
        )

        sent_count = 0
        failed = []

        for assignment in assignments:
            try:
                send_form_assignment_email(assignment)
                assignment.last_reminder_sent_at = timezone.now()
                assignment.reminders_sent = F('reminders_sent') + 1
                assignment.save(update_fields=['last_reminder_sent_at', 'reminders_sent'])
                sent_count += 1
                logger.info(
                    f"Sent reminder for assignment {assignment.id} "
                    f"to {assignment.event_registration.user.email}"
                )
            except Exception as e:
                failed.append({
                    'assignment_id': assignment.id,
                    'error': str(e)
                })
                logger.error(f"Failed to send reminder for assignment {assignment.id}: {e}")

        return Response({
            'sent': sent_count,
            'failed': failed,
            'total': len(assignment_ids)
        })

    @action(detail=False, methods=['post'])
    def bulk_mark_complete(self, request, event_id=None):
        """
        Manually mark modules as complete.

        Use when collateral collected outside platform.

        Body:
        {
            "assignment_ids": [1, 2, 3],
            "module": "speaker"  # or 'sponsor', 'startup', 'investor'
        }
        """
        assignment_ids = request.data.get('assignment_ids', [])
        module = request.data.get('module')

        if not assignment_ids or not module:
            return Response(
                {'error': 'assignment_ids and module required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = self.get_queryset()
        assignments = queryset.filter(
            id__in=assignment_ids,
            active_modules__contains=[module]
        )

        updated_count = 0
        for assignment in assignments:
            try:
                # If all active modules are complete, mark assignment as complete
                if assignment.status != 'completed':
                    assignment.status = 'completed'
                    assignment.completed_at = timezone.now()
                    assignment.save(update_fields=['status', 'completed_at'])
                    updated_count += 1
                    logger.info(
                        f"Manually marked assignment {assignment.id} as complete for module {module}"
                    )
            except Exception as e:
                logger.error(f"Error marking assignment {assignment.id} complete: {e}")

        return Response({
            'marked_complete': updated_count,
            'total': len(assignment_ids)
        })

    @action(detail=False, methods=['get'])
    def export_csv(self, request, event_id=None):
        """
        Export promotional profiles as CSV.

        Query params:
        - role: Filter by role
        - status: Filter by status
        - format: csv (default) or include others
        """
        queryset = self.filter_queryset(self.get_queryset())

        # Create CSV response
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="promotional_profiles.csv"'

        writer = csv.writer(response)

        # Header
        writer.writerow([
            'Name',
            'Email',
            'Roles/Modules',
            'Status',
            'Completed At',
            'Display Consent',
            'Reminders Sent',
            'Active Modules'
        ])

        # Data rows
        for assignment in queryset:
            user = assignment.event_registration.user
            writer.writerow([
                user.get_full_name(),
                user.email,
                ', '.join(assignment.active_modules),
                assignment.status,
                assignment.completed_at.isoformat() if assignment.completed_at else '',
                assignment.event_registration.display_consent or 'Pending',
                assignment.reminders_sent,
                ', '.join(assignment.active_modules)
            ])

        return response

    @action(detail=False, methods=['get'])
    def export_by_role(self, request, event_id=None):
        """
        Export profiles grouped by role.

        Query params:
        - role: Specific role to export (optional, all if not specified)
        """
        queryset = self.filter_queryset(self.get_queryset())
        role = request.query_params.get('role')

        response = HttpResponse(content_type='text/csv')
        filename = f"promotional_profiles_{role}.csv" if role else "promotional_profiles_all.csv"
        response['Content-Disposition'] = f'attachment; filename="{filename}"'

        writer = csv.writer(response)

        if role:
            # Single role export
            queryset = queryset.filter(active_modules__contains=[role])
            writer.writerow([
                'Name',
                'Email',
                'Status',
                'Completed At',
                'Display Consent',
                'Reminders Sent'
            ])

            for assignment in queryset:
                user = assignment.event_registration.user
                writer.writerow([
                    user.get_full_name(),
                    user.email,
                    assignment.status,
                    assignment.completed_at.isoformat() if assignment.completed_at else '',
                    assignment.event_registration.display_consent or 'Pending',
                    assignment.reminders_sent
                ])
        else:
            # All roles export with grouping
            roles = ['speaker', 'sponsor', 'sponsor_staff', 'startup', 'investor']
            for role in roles:
                role_queryset = queryset.filter(active_modules__contains=[role])
                if role_queryset.exists():
                    writer.writerow([f'\n{role.upper()}'.upper()])
                    writer.writerow(['Name', 'Email', 'Status', 'Completed At', 'Display Consent'])

                    for assignment in role_queryset:
                        user = assignment.event_registration.user
                        writer.writerow([
                            user.get_full_name(),
                            user.email,
                            assignment.status,
                            assignment.completed_at.isoformat() if assignment.completed_at else '',
                            assignment.event_registration.display_consent or 'Pending'
                        ])

        return response

    @action(detail=False, methods=['post'])
    def notify_production_lead(self, request, event_id=None):
        """
        Notify production lead about incomplete profiles.

        Body:
        {
            "production_lead_email": "lead@event.com",
            "missing_roles": ["speaker", "sponsor"],
            "include_summary": true
        }
        """
        from django.core.mail import send_mail

        production_lead_email = request.data.get('production_lead_email')
        missing_roles = request.data.get('missing_roles', [])
        include_summary = request.data.get('include_summary', True)

        if not production_lead_email:
            return Response(
                {'error': 'production_lead_email required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        event = self.get_queryset().first().event
        queryset = self.get_queryset()

        # Build email content
        content = f"Promotional Profile Status Report\n"
        content += f"Event: {event.title}\n"
        content += f"Date: {timezone.now().isoformat()}\n\n"

        if include_summary:
            summary_response = self.summary(request, event_id)
            summary_data = summary_response.data

            content += "SUMMARY BY ROLE:\n"
            for role, data in summary_data.get('by_role', {}).items():
                if missing_roles and role not in missing_roles:
                    continue
                percentage = data.get('percentage', 0)
                completed = data.get('completed', 0)
                total = data.get('total', 0)
                content += f"- {role.upper()}: {completed}/{total} complete ({percentage}%)\n"

        content += "\nIncomplete Profiles:\n"
        incomplete = queryset.filter(status__in=['not_started', 'in_progress'])
        for assignment in incomplete[:10]:  # Show first 10
            user = assignment.event_registration.user
            content += f"- {user.get_full_name()} ({user.email}) - {assignment.status}\n"

        if incomplete.count() > 10:
            content += f"... and {incomplete.count() - 10} more\n"

        try:
            send_mail(
                f'Promotional Profile Status - {event.title}',
                content,
                'noreply@event.com',
                [production_lead_email],
                fail_silently=False
            )
            logger.info(
                f"Sent promotional profile status to {production_lead_email} for event {event.id}"
            )
            return Response({
                'sent': True,
                'recipient': production_lead_email
            })
        except Exception as e:
            logger.error(f"Failed to send email to {production_lead_email}: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['get'])
    def missing_assets_report(self, request, event_id=None):
        """
        Get report of missing critical assets.

        Returns:
        {
            "missing_headshots": [{"id": 1, "name": "John Doe", "module": "speaker"}],
            "missing_logos": [...],
            "missing_pitch_decks": [...]
        }
        """
        queryset = self.get_queryset()

        missing_headshots = self._filter_missing_headshot(queryset)
        missing_logos = self._filter_missing_logo(queryset)
        missing_pitch_decks = self._filter_missing_pitch_deck(queryset)

        def format_assignments(assignments):
            return [
                {
                    'id': a.id,
                    'name': a.event_registration.user.get_full_name(),
                    'email': a.event_registration.user.email,
                    'modules': a.active_modules
                }
                for a in assignments
            ]

        return Response({
            'missing_headshots': format_assignments(missing_headshots),
            'missing_logos': format_assignments(missing_logos),
            'missing_pitch_decks': format_assignments(missing_pitch_decks),
            'total_missing': {
                'headshots': missing_headshots.count(),
                'logos': missing_logos.count(),
                'pitch_decks': missing_pitch_decks.count()
            }
        })

    @action(detail=False, methods=['post'])
    def export_production(self, request, event_id=None):
        """
        Export promotional profiles for production handoff.

        Request body:
        {
            "format": "csv" | "json" | "zip",
            "include_internal": false,
            "role": "speaker" (optional, for role-specific exports)
        }

        Returns file attachment.
        """
        from events.services.promotional_profile_export_service import (
            generate_csv_export, generate_json_export, generate_zip_export
        )
        from events.models import AdminAuditLog

        export_format = request.data.get('format', 'csv')
        include_internal = request.data.get('include_internal', False)
        role = request.data.get('role')

        # Check admin permission for internal exports
        if include_internal and not (request.user.is_superuser or request.user.groups.filter(name='view_restricted_attendee_data').exists()):
            return Response(
                {'error': 'Permission denied for internal export'},
                status=status.HTTP_403_FORBIDDEN
            )

        queryset = self.filter_queryset(self.get_queryset())

        # Filter by completion status (default: only completed)
        if not include_internal:
            queryset = queryset.filter(status='completed')

        if not queryset.exists():
            return Response(
                {'error': 'No profiles to export'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            event = queryset.first().event

            if export_format == 'csv':
                data = generate_csv_export(queryset, include_internal)
                content_type = 'text/csv'
                filename = f"promotional_profiles_{event.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.csv"

            elif export_format == 'json':
                data = generate_json_export(queryset, include_internal)
                content_type = 'application/json'
                filename = f"promotional_profiles_{event.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.json"

            elif export_format == 'zip':
                data = generate_zip_export(event, queryset, include_internal, role)
                if role:
                    filename = f"promotional_profiles_{role}_{event.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.zip"
                else:
                    filename = f"promotional_profiles_{event.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.zip"

                content_type = 'application/zip'
            else:
                return Response(
                    {'error': f'Invalid format: {export_format}'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Create audit log
            AdminAuditLog.objects.create(
                event=event,
                performed_by=request.user,
                action='export_production',
                details={
                    'format': export_format,
                    'include_internal': include_internal,
                    'role': role,
                    'row_count': queryset.count(),
                    'filename': filename
                }
            )

            logger.info(
                f"Production export: format={export_format}, internal={include_internal}, "
                f"role={role}, count={queryset.count()}, user={request.user.email}"
            )

            # Handle different data types
            from io import BytesIO
            if isinstance(data, BytesIO):
                response_data = data.getvalue()
            elif isinstance(data, bytes):
                response_data = data
            else:
                response_data = data.encode()

            response = HttpResponse(response_data, content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response

        except Exception as e:
            logger.error(f"Failed to generate production export: {e}")
            return Response(
                {'error': f'Export failed: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
