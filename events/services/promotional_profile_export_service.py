"""
Promotional Profile Export Service

Exports completed promotional profiles in multiple formats (CSV, JSON, ZIP)
for production team handoff. Supports role-based filtering, asset file inclusion,
consent enforcement, and audit logging.
"""
import csv
import json
import logging
import zipfile
from datetime import datetime
from io import BytesIO, StringIO
from pathlib import Path
from uuid import uuid4

from django.contrib.auth.models import User
from django.core.files.storage import default_storage
from django.db.models import Q
from django.utils.text import slugify
from django.utils.timezone import now

from events.models import PostAcceptanceFormAssignment, PostAcceptanceFormAnswer

logger = logging.getLogger(__name__)

# Module to file fields mapping (with prefixes to match schema)
MODULE_FILE_FIELDS = {
    'speaker': ['speaker_headshot', 'speaker_slide_deck'],
    'sponsor': ['sponsor_organisation_logo', 'sponsor_organisation_logo_dark', 'sponsor_deliverables'],
    'sponsor_staff': ['sponsor_staff_headshot'],
    'startup': ['startup_company_logo', 'startup_public_pitch_deck', 'startup_founder_photos'],
    'investor': ['investor_display_logo']
}

SAFE_FOLDER_NAMES = {
    'speaker': 'speakers',
    'sponsor': 'sponsors',
    'sponsor_staff': 'sponsor_staff',
    'startup': 'startups',
    'investor': 'investors'
}

# Module-specific fields for JSON export (with prefixes to match schema)
MODULE_QUESTION_KEYS = {
    'speaker': [
        'speaker_display_name', 'speaker_programme_title', 'speaker_programme_affiliation', 'speaker_headshot',
        'speaker_programme_bio', 'speaker_short_bio', 'speaker_talk_title', 'speaker_talk_abstract', 'speaker_session_format',
        'speaker_co_speakers', 'speaker_av_requirements', 'speaker_slide_deck', 'speaker_linkedin_url', 'speaker_twitter_handle',
        'speaker_personal_website', 'speaker_display_consent'
    ],
    'sponsor': [
        'sponsor_organisation_name_display', 'sponsor_organisation_logo', 'sponsor_organisation_logo_dark',
        'sponsor_tagline', 'sponsor_programme_description', 'sponsor_website_url', 'sponsor_sponsor_tier',
        'sponsor_booth_activation_details', 'sponsor_deliverables', 'sponsor_primary_contact_name',
        'sponsor_primary_contact_email', 'sponsor_display_consent'
    ],
    'sponsor_staff': [
        'sponsor_staff_display_name', 'sponsor_staff_role_at_sponsor', 'sponsor_staff_headshot', 'sponsor_staff_booth_presence',
        'sponsor_staff_areas_of_conversation', 'sponsor_staff_display_consent'
    ],
    'startup': [
        'startup_company_name_display', 'startup_company_logo', 'startup_one_line_pitch',
        'startup_programme_description', 'startup_stage', 'startup_sector_industry', 'startup_founded_year',
        'startup_website_url', 'startup_demo_url', 'startup_public_pitch_deck', 'startup_founder_names_roles',
        'startup_founder_photos', 'startup_display_consent'
    ],
    'investor': [
        'investor_display_name', 'investor_display_logo', 'investor_thesis_tagline', 'investor_stage_focus',
        'investor_sector_focus', 'investor_geographic_focus', 'investor_cheque_size_range', 'investor_open_to_inbound',
        'investor_display_consent'
    ]
}


def build_export_queryset(assignments, include_internal=False, include_incomplete=False, role=None):
    """Build queryset with appropriate filters for export.

    Args:
        assignments: QuerySet of PostAcceptanceFormAssignment
        include_internal: If False, exclude display_consent='no' profiles
        include_incomplete: If False, only include completed assignments
        role: If set, filter to assignments with this role in active_modules

    Returns:
        Filtered and optimized QuerySet
    """
    qs = assignments.filter(form_type='promotional_profile')

    # Status filter - completed by default
    if not include_incomplete:
        qs = qs.filter(status='completed')

    # Role filter
    if role:
        qs = qs.filter(active_modules__contains=[role])

    # Display consent filter
    if not include_internal:
        qs = qs.exclude(event_registration__display_consent='no')

    return qs.select_related(
        'event_registration__user',
        'event_registration',
        'submission'
    ).prefetch_related(
        'submission__answers'
    )


def _safe_filename(text, suffix=None):
    """Generate safe filename/folder name using slugify.

    Args:
        text: Original text (name, company, etc.)
        suffix: Optional suffix to append (e.g., UUID for collision prevention)

    Returns:
        Safe filename string
    """
    safe = slugify(text)
    if suffix:
        safe = f"{safe}-{suffix}"
    return safe


def _get_answer_value(answer):
    """Extract value from PostAcceptanceFormAnswer.

    Handles text, arrays (multi-select), and file fields.
    """
    if not answer:
        return ''
    if answer.answer_data and isinstance(answer.answer_data, list):
        return ', '.join(str(v) for v in answer.answer_data)
    return answer.answer_text or ''


def _get_module_answers(assignment):
    """Get all answers for an assignment, organized by question_key."""
    if not assignment.submission:
        return {}

    try:
        return {
            ans.question_key: ans
            for ans in assignment.submission.answers.all()
        }
    except Exception as e:
        logger.error(f"Error fetching answers for assignment {assignment.id}: {e}")
        return {}


def _serialize_profile_module(assignment, module_name):
    """Serialize a single module's profile data to dict format.

    Args:
        assignment: PostAcceptanceFormAssignment
        module_name: Module identifier (speaker, sponsor, etc.)

    Returns:
        Dict with status, data, and files
    """
    answers = _get_module_answers(assignment)

    # Extract relevant fields for this module
    module_data = {}
    question_keys = MODULE_QUESTION_KEYS.get(module_name, [])

    for key in question_keys:
        if key == 'display_consent':
            # Get from EventRegistration if not in answers
            module_data[key] = assignment.event_registration.display_consent
        elif key in answers:
            answer = answers[key]
            if key in MODULE_FILE_FIELDS.get(module_name, []):
                # File field - check both new and legacy file storage
                answer_files = list(answer.files.all())
                if answer_files:
                    # New multi-file model
                    if len(answer_files) == 1:
                        module_data[key] = {
                            'filename': Path(answer_files[0].file.name).name,
                            'exists': True
                        }
                    else:
                        module_data[key] = {
                            'filenames': [Path(f.file.name).name for f in answer_files],
                            'count': len(answer_files),
                            'exists': True
                        }
                elif answer.answer_file:
                    # Legacy single-file model
                    module_data[key] = {
                        'filename': Path(answer.answer_file.name).name,
                        'exists': True
                    }
                else:
                    module_data[key] = {'filename': None, 'exists': False}
            else:
                # Text/select field
                module_data[key] = _get_answer_value(answer)

    return {
        'status': 'completed' if assignment.status == 'completed' else 'incomplete',
        'data': module_data,
        'files': _get_module_files(assignment, module_name)
    }


def _get_module_files(assignment, module_name):
    """Get file references for a module.

    Returns dict of {question_key: file_path or file_paths_list}
    Supports both legacy answer.answer_file and new answer.files relation.
    """
    if not assignment.submission:
        return {}

    file_fields = MODULE_FILE_FIELDS.get(module_name, [])
    files = {}

    try:
        answers = assignment.submission.answers.filter(
            question_key__in=file_fields
        ).prefetch_related('files').all()

        for answer in answers:
            # Try new multi-file model first
            answer_files = list(answer.files.all())
            if answer_files:
                # If multiple files, return list; if single file, return path string
                if len(answer_files) == 1:
                    files[answer.question_key] = str(answer_files[0].file)
                else:
                    files[answer.question_key] = [str(f.file) for f in answer_files]
            # Fall back to legacy single-file model
            elif answer.answer_file:
                files[answer.question_key] = str(answer.answer_file)
    except Exception as e:
        logger.error(f"Error getting files for assignment {assignment.id}: {e}")

    return files


def generate_csv_export(assignments, include_internal=False, role=None):
    """Generate CSV export of promotional profiles.

    Args:
        assignments: QuerySet or list of PostAcceptanceFormAssignment
        include_internal: Include internal-only profiles (display_consent=no)
        role: Filter to specific role (speaker, sponsor, etc.)

    Returns:
        CSV string
    """
    if hasattr(assignments, 'filter'):
        assignments = build_export_queryset(
            assignments,
            include_internal=include_internal,
            role=role
        )

    output = StringIO()
    writer = csv.writer(output)

    # Headers
    headers = [
        'Attendee Name', 'Email', 'Role', 'Modules', 'Status',
        'Completed At', 'Display Consent', 'Reminders Sent'
    ]
    writer.writerow(headers)

    # Rows
    for assignment in assignments:
        row = [
            assignment.event_registration.user.get_full_name()
            or assignment.event_registration.user.username,
            assignment.event_registration.user.email,
            ', '.join(assignment.active_modules) if assignment.active_modules else '',
            ', '.join(assignment.active_modules) if assignment.active_modules else '',
            assignment.get_status_display(),
            (
                assignment.completed_at.isoformat()
                if assignment.completed_at else ''
            ),
            assignment.event_registration.display_consent,
            assignment.reminders_sent
        ]
        writer.writerow(row)

    return output.getvalue()


def generate_json_export(assignments, include_internal=False, role=None):
    """Generate JSON export of promotional profiles.

    Args:
        assignments: QuerySet or list of PostAcceptanceFormAssignment
        include_internal: Include internal-only profiles
        role: Filter to specific role

    Returns:
        JSON string
    """
    if hasattr(assignments, 'filter'):
        assignments = build_export_queryset(
            assignments,
            include_internal=include_internal,
            role=role
        )

    profiles = []
    for assignment in assignments:
        profile = {
            'assignment_id': assignment.id,
            'attendee': {
                'name': (
                    assignment.event_registration.user.get_full_name()
                    or assignment.event_registration.user.username
                ),
                'email': assignment.event_registration.user.email
            },
            'metadata': {
                'status': assignment.get_status_display(),
                'completed_at': (
                    assignment.completed_at.isoformat()
                    if assignment.completed_at else None
                ),
                'display_consent': assignment.event_registration.display_consent,
                'reminders_sent': assignment.reminders_sent
            },
            'modules': {}
        }

        # Add each active module's data
        for module_name in assignment.active_modules:
            try:
                profile['modules'][module_name] = _serialize_profile_module(
                    assignment, module_name
                )
            except Exception as e:
                logger.error(
                    f"Error serializing module {module_name} for assignment "
                    f"{assignment.id}: {e}"
                )

        profiles.append(profile)

    export_data = {
        'export_metadata': {
            'generated_at': now().isoformat(),
            'total_profiles': len(profiles),
            'include_internal': include_internal,
            'role': role
        },
        'profiles': profiles
    }

    return json.dumps(export_data, indent=2, default=str)


def generate_zip_export(event, assignments, include_internal=False, role=None):
    """Generate ZIP export with role-based folder structure and profile.json files.

    Structure:
        promotional_profiles/
            metadata.json
            speakers/
                maria-schenk/
                    profile.json
                    headshot.png
                    deck.pdf
            sponsors/
                bancor/
                    profile.json
                    logo.svg
                    ...

    Args:
        event: Event object (for metadata)
        assignments: QuerySet or list of PostAcceptanceFormAssignment
        include_internal: Include internal-only profiles
        role: Filter to specific role

    Returns:
        BytesIO ZIP file
    """
    if hasattr(assignments, 'filter'):
        assignments = build_export_queryset(
            assignments,
            include_internal=include_internal,
            role=role
        )

    zip_buffer = BytesIO()

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Initialize metadata structure
        metadata = {
            'event': {
                'id': event.id,
                'title': event.title,
                'format': event.format,
                'date': event.start_time.isoformat() if event.start_time else None,
                'location': event.location or None
            },
            'export': {
                'generated_at': now().isoformat(),
                'format': 'zip',
                'filters': {
                    'include_internal': include_internal,
                    'role': role,
                    'display_consent': 'all' if include_internal else 'yes_only'
                },
                'summary': {
                    'total_profiles': 0,
                    'by_role': {}
                }
            }
        }

        # Track which assignments we've added to prevent duplicates
        added_assignments = set()

        # Process each assignment
        for assignment in assignments:
            for module_name in assignment.active_modules:
                # Skip if not matching requested role
                if role and module_name != role:
                    continue

                # Get display name for folder
                display_name = _get_display_name_for_module(assignment, module_name)
                safe_name = _safe_filename(display_name)
                folder_name = SAFE_FOLDER_NAMES.get(module_name, module_name)
                base_path = f'promotional_profiles/{folder_name}/{safe_name}'

                try:
                    # Create profile.json
                    profile_data = _serialize_profile_module(assignment, module_name)
                    profile_json = {
                        'type': module_name,
                        'display_name': display_name,
                        'metadata': {
                            'assignment_id': assignment.id,
                            'event_id': assignment.event.id,
                            'attendee_email': assignment.event_registration.user.email,
                            'status': profile_data.get('status', 'incomplete'),
                            'completed_at': assignment.completed_at.isoformat() if assignment.completed_at else None,
                            'display_consent': assignment.event_registration.display_consent,
                        },
                        'data': profile_data['data']
                    }

                    zf.writestr(
                        f'{base_path}/profile.json',
                        json.dumps(profile_json, indent=2, default=str)
                    )

                    # Add files for this module
                    _add_module_files_to_zip(
                        zf, assignment, module_name, base_path
                    )

                    added_assignments.add(assignment.id)

                except Exception as e:
                    logger.error(
                        f"Error adding assignment {assignment.id} module "
                        f"{module_name} to ZIP: {e}"
                    )
                    continue

        # Write metadata.json with final counts
        assignments_list = list(assignments)
        by_role = {}
        for m in ['speaker', 'sponsor', 'startup', 'investor', 'sponsor_staff']:
            count = sum(
                1 for a in assignments_list
                if m in a.active_modules
            )
            if count > 0:
                by_role[m] = count

        metadata['export']['summary']['by_role'] = by_role
        metadata['export']['summary']['total_profiles'] = len(added_assignments)

        zf.writestr(
            'promotional_profiles/metadata.json',
            json.dumps(metadata, indent=2, default=str)
        )

    zip_buffer.seek(0)
    return zip_buffer


def _get_display_name_for_module(assignment, module_name):
    """Extract the display name for a specific module."""
    answers = _get_module_answers(assignment)

    # Map module to display_name question key (prefixed)
    display_keys = {
        'speaker': 'speaker_display_name',
        'sponsor': 'sponsor_organisation_name_display',
        'sponsor_staff': 'sponsor_staff_display_name',
        'startup': 'startup_company_name_display',
        'investor': 'investor_display_name'
    }

    key = display_keys.get(module_name)
    if key and key in answers:
        return _get_answer_value(answers[key]) or 'Unknown'

    # Fallback to attendee name
    return (
        assignment.event_registration.user.get_full_name()
        or assignment.event_registration.user.username
    )


def _add_module_files_to_zip(zf, assignment, module_name, base_path):
    """Add all files for a module to the ZIP archive.

    Args:
        zf: ZipFile object
        assignment: PostAcceptanceFormAssignment
        module_name: Module name (speaker, sponsor, etc.)
        base_path: Base folder path in ZIP
    """
    if not assignment.submission:
        return

    file_fields = MODULE_FILE_FIELDS.get(module_name, [])

    try:
        answers = assignment.submission.answers.filter(
            question_key__in=file_fields
        ).prefetch_related('files').all()

        for answer in answers:
            # Try new multi-file model first
            answer_files = list(answer.files.all())

            # If no files in new model, try legacy answer.answer_file
            if not answer_files and answer.answer_file:
                answer_files = [answer]  # Wrap legacy in list-like interface

            for idx, file_obj_or_answer in enumerate(answer_files):
                try:
                    # Determine file path based on whether it's new or legacy model
                    if hasattr(file_obj_or_answer, 'file'):
                        # New multi-file model
                        file_path = str(file_obj_or_answer.file)
                        file_name = Path(file_obj_or_answer.file.name).name
                    else:
                        # Legacy single-file model
                        if not file_obj_or_answer.answer_file:
                            continue
                        file_path = str(file_obj_or_answer.answer_file)
                        file_name = Path(file_obj_or_answer.answer_file.name).name

                    if not default_storage.exists(file_path):
                        logger.warning(
                            f"File not found in storage: {file_path} "
                            f"for assignment {assignment.id}"
                        )
                        continue

                    # Read file content
                    file_obj = default_storage.open(file_path, 'rb')
                    file_content = file_obj.read()
                    file_obj.close()

                    # Handle multiple deliverables/founder_photos (check for prefixed versions)
                    if answer.question_key in ['sponsor_deliverables', 'startup_founder_photos']:
                        subfolder = (
                            'deliverables' if answer.question_key == 'sponsor_deliverables'
                            else 'founder-photos'
                        )
                        zip_file_path = f'{base_path}/{subfolder}/{file_name}'
                    else:
                        zip_file_path = f'{base_path}/{file_name}'

                    # Add file to ZIP
                    zf.writestr(zip_file_path, file_content)

                except Exception as e:
                    logger.error(
                        f"Error adding file to ZIP "
                        f"for assignment {assignment.id}: {e}"
                    )
                    continue

    except Exception as e:
        logger.error(
            f"Error processing files for assignment {assignment.id} "
            f"module {module_name}: {e}"
        )
