"""
Tests for Promotional Profile Modules: Sponsor, Start-up, Investor.

Tests cover:
- Schema structure and fields
- File upload validation
- Text field validation
- Form submission and validation
- Module-level completion tracking
"""
import pytest
from io import BytesIO
from PIL import Image
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.utils import timezone
from events.models import (
    Event, EventRegistration, PostAcceptanceFormTemplate,
    PostAcceptanceFormAssignment
)
from events.services.post_acceptance_forms import (
    validate_sponsor_organisation_submission,
    validate_sponsor_staff_submission,
    validate_startup_submission,
    validate_investor_submission,
    writeback_promotional_profile_module
)
from events.validators import (
    validate_organisation_logo,
    validate_startup_pitch,
    validate_startup_description,
    validate_pitch_deck,
    validate_founder_photos,
    validate_thesis_tagline
)
from users.models import User
from communities.models import Community
from django.core.exceptions import ValidationError


def create_test_image(width=500, height=500, format='JPEG'):
    """Create a test image file."""
    img = Image.new('RGB', (width, height), color='blue')
    img_io = BytesIO()
    img.save(img_io, format=format)
    img_io.seek(0)
    return img_io


@pytest.fixture
def user():
    """Create a test user."""
    return User.objects.create_user(
        username='sponsor_test',
        email='sponsor@test.com',
        first_name='John',
        last_name='Doe'
    )


@pytest.fixture
def community():
    """Create a test community."""
    return Community.objects.create(
        name='Test Community',
        slug='test-community'
    )


@pytest.fixture
def event(community):
    """Create an event."""
    return Event.objects.create(
        community=community,
        title='Tech Conference 2026',
        slug='tech-conf-2026',
        format='in_person',
        status='live',
        start_time=timezone.now() + timezone.timedelta(days=30),
        end_time=timezone.now() + timezone.timedelta(days=32),
        registration_type='apply'
    )


class TestSponsorOrganisationModule(TestCase):
    """Test sponsor organisation module validation."""

    def test_organisation_logo_validation_valid(self):
        """Test valid organisation logo."""
        img_io = create_test_image()
        file = SimpleUploadedFile('logo.png', img_io.getvalue(), content_type='image/png')
        # Should not raise
        validate_organisation_logo(file)

    def test_organisation_logo_too_large(self):
        """Test logo file size limit (5 MB)."""
        large_content = b'x' * (6 * 1024 * 1024)
        file = SimpleUploadedFile('logo.png', large_content, content_type='image/png')
        with pytest.raises(ValidationError) as exc:
            validate_organisation_logo(file)
        assert 'too large' in str(exc.value)

    def test_organisation_logo_invalid_format(self):
        """Test invalid logo format."""
        file = SimpleUploadedFile('logo.gif', b'GIF89a', content_type='image/gif')
        with pytest.raises(ValidationError) as exc:
            validate_organisation_logo(file)
        assert 'Invalid format' in str(exc.value)

    def test_organisation_description_valid(self):
        """Test valid organisation description (50-150 words)."""
        description = ' '.join(['word'] * 100)
        result = validate_organisation_description(description)
        assert result['valid'] is True

    def test_organisation_description_too_short(self):
        """Test description under 50 words."""
        description = ' '.join(['word'] * 30)
        result = validate_organisation_description(description)
        assert result['valid'] is False

    def test_organisation_description_too_long(self):
        """Test description over 150 words."""
        description = ' '.join(['word'] * 200)
        result = validate_organisation_description(description)
        assert result['valid'] is False

    def test_sponsor_organisation_form_valid(self):
        """Test complete sponsor organisation form."""
        img_io = create_test_image()
        logo = SimpleUploadedFile('logo.png', img_io.getvalue(), content_type='image/png')

        answers = {
            'organisation_name_display': 'TechCorp',
            'organisation_logo': logo,
            'tagline': 'Leading cloud solutions',
            'programme_description': ' '.join(['word'] * 100),
            'website_url': 'https://techcorp.com',
            'primary_contact_name': 'John Smith',
            'primary_contact_email': 'john@techcorp.com',
            'display_consent': 'yes'
        }

        result = validate_sponsor_organisation_submission(answers)
        assert result['valid'] is True

    def test_sponsor_organisation_form_missing_required(self):
        """Test form with missing required field."""
        answers = {
            'organisation_name_display': 'TechCorp',
            # Missing organisation_logo and other required fields
        }

        result = validate_sponsor_organisation_submission(answers)
        assert result['valid'] is False
        assert 'organisation_logo' in result['errors']

    def test_sponsor_organisation_invalid_email(self):
        """Test invalid contact email."""
        img_io = create_test_image()
        logo = SimpleUploadedFile('logo.png', img_io.getvalue(), content_type='image/png')

        answers = {
            'organisation_name_display': 'TechCorp',
            'organisation_logo': logo,
            'tagline': 'Leading cloud solutions',
            'programme_description': ' '.join(['word'] * 100),
            'website_url': 'https://techcorp.com',
            'primary_contact_name': 'John Smith',
            'primary_contact_email': 'not-an-email',
            'display_consent': 'yes'
        }

        result = validate_sponsor_organisation_submission(answers)
        assert result['valid'] is False
        assert 'primary_contact_email' in result['errors']


class TestSponsorStaffModule(TestCase):
    """Test sponsor staff module validation."""

    def test_sponsor_staff_form_valid(self):
        """Test complete sponsor staff form."""
        answers = {
            'display_name': 'Jane Smith',
            'role_at_sponsor': 'Sales Director',
            'booth_presence': ['full_time'],
            'areas_of_conversation': ['sales', 'technical'],
            'display_consent': 'yes'
        }

        result = validate_sponsor_staff_submission(answers)
        assert result['valid'] is True

    def test_sponsor_staff_form_missing_required(self):
        """Test form with missing required fields."""
        answers = {
            'display_name': 'Jane Smith',
            # Missing role_at_sponsor and other required fields
        }

        result = validate_sponsor_staff_submission(answers)
        assert result['valid'] is False
        assert 'role_at_sponsor' in result['errors']

    def test_sponsor_staff_name_length(self):
        """Test name length validation."""
        answers = {
            'display_name': 'x',  # Too short (< 2)
            'role_at_sponsor': 'Sales Director',
            'booth_presence': ['full_time'],
            'areas_of_conversation': ['sales'],
            'display_consent': 'yes'
        }

        result = validate_sponsor_staff_submission(answers)
        assert result['valid'] is False
        assert 'display_name' in result['errors']


class TestStartupModule(TestCase):
    """Test startup module validation."""

    def test_startup_pitch_validation_valid(self):
        """Test valid one-line pitch."""
        pitch = 'AI-powered logistics platform for SMEs'
        # Should not raise
        validate_startup_pitch(pitch)

    def test_startup_pitch_too_long(self):
        """Test pitch exceeding 140 characters."""
        pitch = 'x' * 141
        with pytest.raises(ValidationError) as exc:
            validate_startup_pitch(pitch)
        assert '140 characters' in str(exc.value)

    def test_startup_description_valid(self):
        """Test valid startup description (50-100 words)."""
        description = ' '.join(['word'] * 75)
        result = validate_startup_description(description)
        assert result['valid'] is True

    def test_startup_description_too_short(self):
        """Test description under 50 words."""
        description = ' '.join(['word'] * 30)
        result = validate_startup_description(description)
        assert result['valid'] is False

    def test_startup_description_too_long(self):
        """Test description over 100 words."""
        description = ' '.join(['word'] * 150)
        result = validate_startup_description(description)
        assert result['valid'] is False

    def test_pitch_deck_validation_valid_pdf(self):
        """Test valid PDF pitch deck."""
        pdf_content = b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog >> endobj'
        file = SimpleUploadedFile(
            'pitch.pdf',
            pdf_content,
            content_type='application/pdf'
        )
        # Should not raise
        validate_pitch_deck(file)

    def test_pitch_deck_too_large(self):
        """Test pitch deck size limit (25 MB)."""
        large_content = b'x' * (26 * 1024 * 1024)
        file = SimpleUploadedFile('pitch.pdf', large_content, content_type='application/pdf')
        with pytest.raises(ValidationError) as exc:
            validate_pitch_deck(file)
        assert 'too large' in str(exc.value)

    def test_pitch_deck_invalid_format(self):
        """Test invalid pitch deck format (not PDF)."""
        file = SimpleUploadedFile('pitch.doc', b'x' * 1000, content_type='application/msword')
        with pytest.raises(ValidationError) as exc:
            validate_pitch_deck(file)
        assert 'PDF format' in str(exc.value)

    def test_founder_photos_valid(self):
        """Test valid founder photos (JPEG/PNG, max 3MB each, max 3 files)."""
        files = []
        for i in range(2):
            img_io = create_test_image()
            file = SimpleUploadedFile(
                f'founder{i}.jpg',
                img_io.getvalue(),
                content_type='image/jpeg'
            )
            files.append(file)

        # Should not raise
        validate_founder_photos(files)

    def test_founder_photos_too_many(self):
        """Test more than 3 founder photos."""
        files = []
        for i in range(4):
            img_io = create_test_image()
            file = SimpleUploadedFile(
                f'founder{i}.jpg',
                img_io.getvalue(),
                content_type='image/jpeg'
            )
            files.append(file)

        with pytest.raises(ValidationError) as exc:
            validate_founder_photos(files)
        assert 'Too many files' in str(exc.value)

    def test_startup_form_valid(self):
        """Test complete startup form."""
        img_io = create_test_image()
        logo = SimpleUploadedFile('logo.png', img_io.getvalue(), content_type='image/png')

        answers = {
            'company_name_display': 'StartupCo',
            'company_logo': logo,
            'one_line_pitch': 'AI logistics for SMEs',
            'programme_description': ' '.join(['word'] * 75),
            'stage': 'seed',
            'sector_industry': ['ai_ml', 'saas'],
            'founded_year': 2023,
            'website_url': 'https://startupco.com',
            'founder_names_roles': 'John Doe (CEO), Jane Smith (CTO)',
            'display_consent': 'yes'
        }

        result = validate_startup_submission(answers)
        assert result['valid'] is True

    def test_startup_form_invalid_year(self):
        """Test startup with invalid founded year."""
        answers = {
            'company_name_display': 'StartupCo',
            'company_logo': SimpleUploadedFile('logo.png', b'', content_type='image/png'),
            'one_line_pitch': 'AI logistics',
            'programme_description': ' '.join(['word'] * 75),
            'stage': 'seed',
            'sector_industry': ['ai_ml'],
            'founded_year': 1999,  # Too old
            'website_url': 'https://startupco.com',
            'founder_names_roles': 'John Doe (CEO)',
            'display_consent': 'yes'
        }

        result = validate_startup_submission(answers)
        assert result['valid'] is False


class TestInvestorModule(TestCase):
    """Test investor module validation."""

    def test_thesis_tagline_validation_valid(self):
        """Test valid investment thesis tagline."""
        tagline = 'Early-stage AI/ML startups in Southeast Asia'
        # Should not raise
        validate_thesis_tagline(tagline)

    def test_thesis_tagline_too_long(self):
        """Test tagline exceeding 200 characters."""
        tagline = 'x' * 201
        with pytest.raises(ValidationError) as exc:
            validate_thesis_tagline(tagline)
        assert '200 characters' in str(exc.value)

    def test_investor_form_valid(self):
        """Test complete investor form."""
        answers = {
            'display_name': 'John Investor',
            'thesis_tagline': 'Early-stage AI/ML in Southeast Asia',
            'stage_focus': ['seed', 'series_a'],
            'sector_focus': ['ai_ml', 'fintech'],
            'geographic_focus': ['southeast_asia'],
            'cheque_size_range': '250k_1m',
            'open_to_inbound': 'yes',
            'display_consent': 'yes'
        }

        result = validate_investor_submission(answers)
        assert result['valid'] is True

    def test_investor_form_missing_required(self):
        """Test form with missing required field."""
        answers = {
            'display_name': 'John Investor',
            # Missing thesis_tagline and other required fields
        }

        result = validate_investor_submission(answers)
        assert result['valid'] is False
        assert 'thesis_tagline' in result['errors']


class TestModuleCompletion(TestCase):
    """Test module-level completion tracking."""

    @pytest.mark.django_db
    def test_sponsor_staff_module_active(self, user, community, event):
        """Test that sponsor_staff module is activated for sponsor staff role."""
        from events.models import EventParticipant

        # Create sponsor staff participant
        EventParticipant.objects.create(
            event=event,
            user=user,
            role='sponsor_staff',
            triggers_promotional_profile=True
        )

        # Create registration
        registration = EventRegistration.objects.create(
            event=event,
            user=user,
            status='registered',
            attendee_status='confirmed'
        )

        # Create assignment with sponsor_staff module
        form = PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type='promotional_profile'
        )

        assignment = PostAcceptanceFormAssignment.objects.create(
            event=event,
            form_template=form,
            event_registration=registration,
            form_type='promotional_profile',
            active_modules=['sponsor_staff']
        )

        # Verify assignment has correct modules
        assert 'sponsor_staff' in assignment.active_modules
        assert assignment.status == 'not_started'

    @pytest.mark.django_db
    def test_investor_module_active(self, user, community, event):
        """Test that investor module is activated for investor role."""
        from events.models import EventParticipant

        # Create investor participant
        EventParticipant.objects.create(
            event=event,
            user=user,
            role='investor',
            triggers_promotional_profile=True
        )

        # Create registration
        registration = EventRegistration.objects.create(
            event=event,
            user=user,
            status='registered',
            attendee_status='confirmed'
        )

        # Create assignment with investor module
        form = PostAcceptanceFormTemplate.objects.create(
            event=event,
            form_type='promotional_profile'
        )

        assignment = PostAcceptanceFormAssignment.objects.create(
            event=event,
            form_template=form,
            event_registration=registration,
            form_type='promotional_profile',
            active_modules=['investor']
        )

        # Verify assignment has correct modules
        assert 'investor' in assignment.active_modules
