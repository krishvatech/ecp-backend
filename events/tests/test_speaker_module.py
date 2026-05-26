"""
Tests for Speaker Module of Promotional Profile Form.

Tests cover:
- Schema structure and fields
- File upload validation (headshot, slide deck)
- Text field validation (bio length, character limits)
- URL validation (LinkedIn, Twitter, website)
- Form submission and validation
- Prefill logic
- Admin display consent handling
"""
import pytest
from io import BytesIO
from PIL import Image
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.utils import timezone
from events.models import (
    Event, EventRegistration, PostAcceptanceFormTemplate,
    PostAcceptanceFormAssignment, PostAcceptanceFormSubmission
)
from events.services.post_acceptance_forms import (
    validate_speaker_module_submission,
    writeback_speaker_profile_form
)
from events.validators import (
    validate_headshot, validate_slide_deck,
    validate_speaker_bio, validate_short_bio
)
from users.models import User
from communities.models import Community
from django.core.exceptions import ValidationError


@pytest.fixture
def user():
    """Create a test user."""
    return User.objects.create_user(
        username='speaker_test',
        email='speaker@test.com',
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
    """Create an in-person event with Promotional Profile form."""
    event = Event.objects.create(
        community=community,
        title='Tech Conference 2026',
        slug='tech-conf-2026',
        format='in_person',
        status='live',
        start_time=timezone.now() + timezone.timedelta(days=30),
        end_time=timezone.now() + timezone.timedelta(days=32),
        registration_type='apply'
    )

    # Create promotional profile form template
    form = PostAcceptanceFormTemplate.objects.create(
        event=event,
        form_type='promotional_profile',
        title='Speaker Profile Form',
        description='Please complete your speaker profile',
        is_enabled=True,
        deadline_days=14
    )
    return event


@pytest.fixture
def registration(event, user):
    """Create an event registration."""
    return EventRegistration.objects.create(
        event=event,
        user=user,
        status='registered',
        attendee_status='confirmed'
    )


@pytest.fixture
def form_assignment(event, registration):
    """Create a promotional profile form assignment."""
    form = PostAcceptanceFormTemplate.objects.get(
        event=event,
        form_type='promotional_profile'
    )
    assignment = PostAcceptanceFormAssignment.objects.create(
        event=event,
        form_template=form,
        event_registration=registration,
        form_type='promotional_profile',
        status='not_started',
        deadline=timezone.now() + timezone.timedelta(days=14),
        active_modules=['speaker']
    )
    return assignment


def create_test_image(width=1500, height=1500, format='JPEG'):
    """Create a test image file."""
    img = Image.new('RGB', (width, height), color='red')
    img_io = BytesIO()
    img.save(img_io, format=format)
    img_io.seek(0)
    return img_io


def create_test_pdf():
    """Create a mock PDF file."""
    pdf_content = b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog >> endobj\nxref\ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n0\n%%EOF'
    return BytesIO(pdf_content)


class TestSpeakerModuleValidation(TestCase):
    """Test speaker module field validation."""

    def test_headshot_validation_valid_jpeg(self):
        """Test valid JPEG headshot passes validation."""
        img_io = create_test_image(format='JPEG')
        file = SimpleUploadedFile(
            'headshot.jpg',
            img_io.getvalue(),
            content_type='image/jpeg'
        )
        # Should not raise
        validate_headshot(file)

    def test_headshot_validation_valid_png(self):
        """Test valid PNG headshot passes validation."""
        img_io = create_test_image(format='PNG')
        file = SimpleUploadedFile(
            'headshot.png',
            img_io.getvalue(),
            content_type='image/png'
        )
        # Should not raise
        validate_headshot(file)

    def test_headshot_validation_too_large(self):
        """Test file size limit (10 MB)."""
        # Create an oversized file (11 MB)
        large_content = b'x' * (11 * 1024 * 1024)
        file = SimpleUploadedFile(
            'headshot.jpg',
            large_content,
            content_type='image/jpeg'
        )
        with pytest.raises(ValidationError) as exc:
            validate_headshot(file)
        assert 'too large' in str(exc.value)

    def test_headshot_validation_invalid_format(self):
        """Test invalid image format."""
        file = SimpleUploadedFile(
            'headshot.gif',
            b'GIF89a\x01\x00\x01\x00',
            content_type='image/gif'
        )
        with pytest.raises(ValidationError) as exc:
            validate_headshot(file)
        assert 'Invalid image format' in str(exc.value)

    def test_headshot_validation_too_small_dimensions(self):
        """Test minimum dimension requirement (1500x1500)."""
        # Create image that's 1000x1000
        img_io = create_test_image(width=1000, height=1000)
        file = SimpleUploadedFile(
            'headshot.jpg',
            img_io.getvalue(),
            content_type='image/jpeg'
        )
        with pytest.raises(ValidationError) as exc:
            validate_headshot(file)
        assert '1500x1500' in str(exc.value)

    def test_slide_deck_validation_pdf(self):
        """Test valid PDF slide deck."""
        pdf_io = create_test_pdf()
        file = SimpleUploadedFile(
            'slides.pdf',
            pdf_io.getvalue(),
            content_type='application/pdf'
        )
        # Should not raise
        validate_slide_deck(file)

    def test_slide_deck_validation_pptx(self):
        """Test valid PPTX file (mock)."""
        # Mock PPTX content (ZIP format)
        pptx_content = b'PK\x03\x04'  # ZIP header
        file = SimpleUploadedFile(
            'slides.pptx',
            pptx_content,
            content_type='application/vnd.openxmlformats-officedocument.presentationml.presentation'
        )
        # Should not raise (basic validation)
        validate_slide_deck(file)

    def test_slide_deck_validation_too_large(self):
        """Test slide deck size limit (50 MB)."""
        large_content = b'x' * (51 * 1024 * 1024)
        file = SimpleUploadedFile(
            'slides.pdf',
            large_content,
            content_type='application/pdf'
        )
        with pytest.raises(ValidationError) as exc:
            validate_slide_deck(file)
        assert 'too large' in str(exc.value)

    def test_slide_deck_validation_invalid_format(self):
        """Test invalid slide deck format."""
        file = SimpleUploadedFile(
            'slides.docx',
            b'PK\x03\x04',
            content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        )
        with pytest.raises(ValidationError) as exc:
            validate_slide_deck(file)
        assert 'Invalid file extension' in str(exc.value)

    def test_speaker_bio_validation_valid(self):
        """Test valid bio with 150 words."""
        bio = ' '.join(['word'] * 150)
        result = validate_speaker_bio(bio)
        assert result['valid'] is True
        assert result['word_count'] == 150

    def test_speaker_bio_validation_too_short(self):
        """Test bio under 100 words."""
        bio = ' '.join(['word'] * 50)
        result = validate_speaker_bio(bio)
        assert result['valid'] is False
        assert any('short' in err.lower() for err in result['errors'])

    def test_speaker_bio_validation_too_long(self):
        """Test bio over 200 words."""
        bio = ' '.join(['word'] * 250)
        result = validate_speaker_bio(bio)
        assert result['valid'] is False
        assert any('long' in err.lower() for err in result['errors'])

    def test_short_bio_validation_valid(self):
        """Test valid short bio under 200 characters."""
        short_bio = 'A great speaker with expertise in technology.'
        # Should not raise
        validate_short_bio(short_bio)

    def test_short_bio_validation_too_long(self):
        """Test short bio exceeding 200 characters."""
        short_bio = 'x' * 201
        with pytest.raises(ValidationError) as exc:
            validate_short_bio(short_bio)
        assert '200 characters' in str(exc.value)


class TestSpeakerModuleFormValidation(TestCase):
    """Test complete speaker module form validation."""

    def test_form_submission_all_required_fields(self):
        """Test form validation with all required fields."""
        img_io = create_test_image()
        headshot = SimpleUploadedFile('headshot.jpg', img_io.getvalue(), content_type='image/jpeg')

        answers = {
            'display_name': 'John Doe',
            'programme_title': 'Senior Engineer',
            'programme_affiliation': 'Tech Corp',
            'headshot': headshot,
            'programme_bio': ' '.join(['word'] * 150),
            'short_bio': 'A great speaker',
            'talk_title': 'Building Scalable Systems',
            'talk_abstract': ' '.join(['word'] * 50),
            'session_format': 'presentation',
            'display_consent': 'yes'
        }

        result = validate_speaker_module_submission(answers)
        assert result['valid'] is True
        assert result['errors'] == {}

    def test_form_submission_missing_required_field(self):
        """Test form validation with missing required field."""
        answers = {
            'display_name': 'John Doe',
            # Missing programme_title
            'programme_affiliation': 'Tech Corp',
            # ... other fields missing
        }

        result = validate_speaker_module_submission(answers)
        assert result['valid'] is False
        assert 'programme_title' in result['errors']

    def test_form_submission_optional_fields(self):
        """Test form with optional fields omitted."""
        img_io = create_test_image()
        headshot = SimpleUploadedFile('headshot.jpg', img_io.getvalue(), content_type='image/jpeg')

        answers = {
            'display_name': 'John Doe',
            'programme_title': 'Senior Engineer',
            'programme_affiliation': 'Tech Corp',
            'headshot': headshot,
            'programme_bio': ' '.join(['word'] * 150),
            'short_bio': 'A great speaker',
            'talk_title': 'Building Scalable Systems',
            'talk_abstract': ' '.join(['word'] * 50),
            'session_format': 'presentation',
            'display_consent': 'yes'
            # linkedin_url, twitter_handle, personal_website, slide_deck all optional
        }

        result = validate_speaker_module_submission(answers)
        assert result['valid'] is True

    def test_form_submission_invalid_linkedin_url(self):
        """Test validation of LinkedIn URL."""
        answers = {
            'linkedin_url': 'not-a-url'
        }

        result = validate_speaker_module_submission(answers)
        assert result['valid'] is False
        assert 'linkedin_url' in result['errors']

    def test_form_submission_valid_linkedin_url(self):
        """Test validation of valid LinkedIn URL."""
        img_io = create_test_image()
        headshot = SimpleUploadedFile('headshot.jpg', img_io.getvalue(), content_type='image/jpeg')

        answers = {
            'display_name': 'John Doe',
            'programme_title': 'Senior Engineer',
            'programme_affiliation': 'Tech Corp',
            'headshot': headshot,
            'programme_bio': ' '.join(['word'] * 150),
            'short_bio': 'A great speaker',
            'talk_title': 'Building Scalable Systems',
            'talk_abstract': ' '.join(['word'] * 50),
            'session_format': 'presentation',
            'display_consent': 'yes',
            'linkedin_url': 'https://linkedin.com/in/johndoe'
        }

        result = validate_speaker_module_submission(answers)
        assert result['valid'] is True

    def test_form_submission_invalid_twitter_handle(self):
        """Test validation of Twitter handle."""
        answers = {
            'twitter_handle': 'this_handle_is_way_too_long_for_twitter'
        }

        result = validate_speaker_module_submission(answers)
        assert result['valid'] is False
        assert 'twitter_handle' in result['errors']

    def test_form_submission_valid_twitter_handle(self):
        """Test validation of valid Twitter handle."""
        img_io = create_test_image()
        headshot = SimpleUploadedFile('headshot.jpg', img_io.getvalue(), content_type='image/jpeg')

        answers = {
            'display_name': 'John Doe',
            'programme_title': 'Senior Engineer',
            'programme_affiliation': 'Tech Corp',
            'headshot': headshot,
            'programme_bio': ' '.join(['word'] * 150),
            'short_bio': 'A great speaker',
            'talk_title': 'Building Scalable Systems',
            'talk_abstract': ' '.join(['word'] * 50),
            'session_format': 'presentation',
            'display_consent': 'yes',
            'twitter_handle': '@johndoe'
        }

        result = validate_speaker_module_submission(answers)
        assert result['valid'] is True

    def test_form_submission_display_consent_no(self):
        """Test form with display_consent = 'no'."""
        img_io = create_test_image()
        headshot = SimpleUploadedFile('headshot.jpg', img_io.getvalue(), content_type='image/jpeg')

        answers = {
            'display_name': 'John Doe',
            'programme_title': 'Senior Engineer',
            'programme_affiliation': 'Tech Corp',
            'headshot': headshot,
            'programme_bio': ' '.join(['word'] * 150),
            'short_bio': 'A great speaker',
            'talk_title': 'Building Scalable Systems',
            'talk_abstract': ' '.join(['word'] * 50),
            'session_format': 'presentation',
            'display_consent': 'no'
        }

        result = validate_speaker_module_submission(answers)
        assert result['valid'] is True


class TestSpeakerModuleWriteback(TestCase):
    """Test speaker module form writeback to EventRegistration."""

    @pytest.mark.django_db
    def test_writeback_updates_display_consent(self, user, community, event, registration, form_assignment):
        """Test that writeback updates display_consent field."""
        # Create submission
        submission = PostAcceptanceFormSubmission.objects.create(
            assignment=form_assignment,
            submitted_at=timezone.now()
        )

        # Add answer
        from events.models import PostAcceptanceFormAnswer
        PostAcceptanceFormAnswer.objects.create(
            submission=submission,
            question_key='display_consent',
            answer_text='yes'
        )

        form_assignment.submission = submission
        form_assignment.save()

        # Run writeback
        result = writeback_speaker_profile_form(form_assignment)

        assert result is True
        registration.refresh_from_db()
        assert registration.display_consent == 'yes'
        assert registration.promotional_profile_completed_at is not None
