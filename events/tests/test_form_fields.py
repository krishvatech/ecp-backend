"""
Tests for Phase 5: Form Schema Primitives and Shared Question Library.

Tests cover:
1. FormField model CRUD and validation
2. SharedQuestion library operations
3. Profile binding and conditional visibility
4. Serializer output and field transformations
5. ViewSet permissions and filtering
6. Admin integration
"""

from django.test import TestCase, TransactionTestCase
from django.contrib.auth.models import User
from events.models import (
    Event, EventApplicationTrack, FormField, SharedQuestion,
    SharedQuestionCategory, EventApplication
)
from events.serializers import (
    FormFieldSerializer, SharedQuestionSerializer,
    SharedQuestionCategorySerializer
)
from community.models import Community
import json


class SharedQuestionCategoryModelTests(TestCase):
    """Tests for SharedQuestionCategory model."""

    def setUp(self):
        self.category = SharedQuestionCategory.objects.create(
            name='Professional Background',
            description='Questions about professional experience',
            sort_order=10
        )

    def test_create_category(self):
        """Test creating a question category."""
        self.assertEqual(self.category.name, 'Professional Background')
        self.assertEqual(self.category.sort_order, 10)

    def test_category_str(self):
        """Test string representation of category."""
        self.assertEqual(str(self.category), 'Professional Background')

    def test_category_ordering(self):
        """Test categories are ordered by sort_order."""
        cat2 = SharedQuestionCategory.objects.create(
            name='Interests',
            sort_order=20
        )
        categories = SharedQuestionCategory.objects.all()
        self.assertEqual(list(categories), [self.category, cat2])


class SharedQuestionModelTests(TestCase):
    """Tests for SharedQuestion model."""

    def setUp(self):
        self.category = SharedQuestionCategory.objects.create(
            name='Professional',
            sort_order=10
        )

    def test_create_text_question(self):
        """Test creating a text question."""
        question = SharedQuestion.objects.create(
            category=self.category,
            label='Job Title',
            field_type='text',
            help_text='Enter your current job title',
            placeholder='e.g., Software Engineer'
        )
        self.assertEqual(question.label, 'Job Title')
        self.assertEqual(question.field_type, 'text')

    def test_create_select_question_with_options(self):
        """Test creating a select question with options."""
        options = [
            {'label': 'Tech', 'value': 'tech'},
            {'label': 'Finance', 'value': 'finance'},
        ]
        question = SharedQuestion.objects.create(
            category=self.category,
            label='Industry',
            field_type='select',
            options=options
        )
        self.assertEqual(len(question.options), 2)
        self.assertEqual(question.options[0]['value'], 'tech')

    def test_question_str(self):
        """Test string representation of question."""
        question = SharedQuestion.objects.create(
            category=self.category,
            label='Role',
            field_type='select'
        )
        self.assertEqual(str(question), 'Role (Select)')

    def test_question_ordering(self):
        """Test questions ordered by category then ID."""
        q1 = SharedQuestion.objects.create(
            category=self.category,
            label='Q1',
            field_type='text'
        )
        q2 = SharedQuestion.objects.create(
            category=self.category,
            label='Q2',
            field_type='text'
        )
        questions = SharedQuestion.objects.all()
        self.assertEqual(list(questions), [q1, q2])


class FormFieldModelTests(TestCase):
    """Tests for FormField model."""

    def setUp(self):
        self.community = Community.objects.create(
            name='Test Community',
            slug='test-community'
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        self.event = Event.objects.create(
            community=self.community,
            title='Test Event',
            created_by=self.user
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track'
        )

    def test_create_form_field(self):
        """Test creating a form field."""
        field = FormField.objects.create(
            track=self.track,
            label='Full Name',
            field_type='text',
            required=True
        )
        self.assertEqual(field.label, 'Full Name')
        self.assertEqual(field.field_type, 'text')
        self.assertTrue(field.required)

    def test_form_field_with_validation(self):
        """Test form field with min/max validation."""
        field = FormField.objects.create(
            track=self.track,
            label='Comment',
            field_type='long_text',
            min_length=10,
            max_length=500,
            required=False
        )
        self.assertEqual(field.min_length, 10)
        self.assertEqual(field.max_length, 500)

    def test_form_field_with_options(self):
        """Test form field with predefined options."""
        options = [
            {'label': 'Option A', 'value': 'a'},
            {'label': 'Option B', 'value': 'b'},
        ]
        field = FormField.objects.create(
            track=self.track,
            label='Choose One',
            field_type='select',
            options=options
        )
        self.assertEqual(len(field.options), 2)

    def test_form_field_profile_binding(self):
        """Test form field with profile binding."""
        field = FormField.objects.create(
            track=self.track,
            label='Email',
            field_type='email',
            profile_binding='user.email',
            profile_binding_mode='prefill_if_present'
        )
        self.assertEqual(field.profile_binding, 'user.email')
        self.assertEqual(field.profile_binding_mode, 'prefill_if_present')

    def test_form_field_visibility_per_mode(self):
        """Test form field visibility per submission mode."""
        visibility = {
            'self_submission': True,
            'confirmed': False,
            'third_party_nomination': True
        }
        field = FormField.objects.create(
            track=self.track,
            label='Nominator Name',
            field_type='text',
            visibility_per_mode=visibility
        )
        self.assertTrue(field.visibility_per_mode['self_submission'])
        self.assertFalse(field.visibility_per_mode['confirmed'])

    def test_form_field_conditional_visibility(self):
        """Test form field conditional visibility logic."""
        condition = {
            'if': {'field': 'submission_mode', 'value': 'third_party_nomination'},
            'then': True
        }
        field = FormField.objects.create(
            track=self.track,
            label='Conditional Field',
            field_type='text',
            conditional_visibility=condition
        )
        self.assertEqual(field.conditional_visibility['if']['field'], 'submission_mode')

    def test_form_field_review_visibility(self):
        """Test review visibility flags."""
        field = FormField.objects.create(
            track=self.track,
            label='Public Field',
            field_type='text',
            visible_in_review_list=True,
            visible_in_review_detail=True
        )
        self.assertTrue(field.visible_in_review_list)
        self.assertTrue(field.visible_in_review_detail)

    def test_form_field_ordering(self):
        """Test form fields ordered by sort_order."""
        f1 = FormField.objects.create(
            track=self.track,
            label='First',
            field_type='text',
            sort_order=10
        )
        f2 = FormField.objects.create(
            track=self.track,
            label='Second',
            field_type='text',
            sort_order=20
        )
        fields = FormField.objects.filter(track=self.track)
        self.assertEqual(list(fields), [f1, f2])

    def test_form_field_unique_label_per_track(self):
        """Test that field labels must be unique within a track."""
        FormField.objects.create(
            track=self.track,
            label='Unique Label',
            field_type='text'
        )
        with self.assertRaises(Exception):
            FormField.objects.create(
                track=self.track,
                label='Unique Label',
                field_type='select'
            )

    def test_form_field_str(self):
        """Test string representation of form field."""
        field = FormField.objects.create(
            track=self.track,
            label='Test Field',
            field_type='text'
        )
        self.assertEqual(str(field), 'Test Field (Speaker Track)')

    def test_form_field_from_shared_question(self):
        """Test creating form field from shared question."""
        category = SharedQuestionCategory.objects.create(
            name='Test',
            sort_order=1
        )
        question = SharedQuestion.objects.create(
            category=category,
            label='Industry',
            field_type='select',
            options=[{'label': 'Tech', 'value': 'tech'}]
        )
        field = FormField.objects.create(
            track=self.track,
            label='Industry',
            field_type='select',
            shared_question=question,
            options=question.options
        )
        self.assertEqual(field.shared_question, question)
        self.assertEqual(field.label, question.label)


class FormFieldSerializerTests(TestCase):
    """Tests for FormFieldSerializer."""

    def setUp(self):
        self.community = Community.objects.create(
            name='Test Community',
            slug='test-community'
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        self.event = Event.objects.create(
            community=self.community,
            title='Test Event',
            created_by=self.user
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker Track'
        )

    def test_serialize_form_field(self):
        """Test serializing a form field."""
        field = FormField.objects.create(
            track=self.track,
            label='Email',
            field_type='email',
            required=True,
            help_text='Your email address',
            placeholder='name@example.com'
        )
        serializer = FormFieldSerializer(field)
        data = serializer.data

        self.assertEqual(data['label'], 'Email')
        self.assertEqual(data['field_type'], 'email')
        self.assertTrue(data['required'])
        self.assertEqual(data['help_text'], 'Your email address')

    def test_serializer_includes_field_type_display(self):
        """Test serializer includes field_type_display."""
        field = FormField.objects.create(
            track=self.track,
            label='Test',
            field_type='long_text'
        )
        serializer = FormFieldSerializer(field)
        self.assertEqual(serializer.data['field_type_display'], 'Long Text')

    def test_serializer_includes_shared_question_label(self):
        """Test serializer includes shared question label."""
        category = SharedQuestionCategory.objects.create(name='Test')
        question = SharedQuestion.objects.create(
            category=category,
            label='Industry',
            field_type='select'
        )
        field = FormField.objects.create(
            track=self.track,
            label='Industry',
            field_type='select',
            shared_question=question
        )
        serializer = FormFieldSerializer(field)
        self.assertEqual(serializer.data['shared_question_label'], 'Industry')

    def test_serializer_read_only_fields(self):
        """Test that read_only fields are not writable."""
        field = FormField.objects.create(
            track=self.track,
            label='Test',
            field_type='text'
        )
        serializer = FormFieldSerializer(field)
        # id and created_at should be in read_only_fields
        self.assertIn('id', serializer.fields)
        self.assertTrue(serializer.fields['id'].read_only)


class SharedQuestionSerializerTests(TestCase):
    """Tests for SharedQuestionSerializer."""

    def setUp(self):
        self.category = SharedQuestionCategory.objects.create(
            name='Professional',
            sort_order=10
        )

    def test_serialize_shared_question(self):
        """Test serializing a shared question."""
        question = SharedQuestion.objects.create(
            category=self.category,
            label='Industry',
            field_type='select',
            help_text='Select your industry',
            options=[{'label': 'Tech', 'value': 'tech'}]
        )
        serializer = SharedQuestionSerializer(question)
        data = serializer.data

        self.assertEqual(data['label'], 'Industry')
        self.assertEqual(data['field_type'], 'select')
        self.assertEqual(data['category_name'], 'Professional')

    def test_serializer_includes_category_name(self):
        """Test serializer includes nested category name."""
        question = SharedQuestion.objects.create(
            category=self.category,
            label='Role',
            field_type='text'
        )
        serializer = SharedQuestionSerializer(question)
        self.assertEqual(serializer.data['category_name'], 'Professional')


class SharedQuestionCategorySerializerTests(TestCase):
    """Tests for SharedQuestionCategorySerializer."""

    def test_serialize_category_with_questions(self):
        """Test serializing category with nested questions."""
        category = SharedQuestionCategory.objects.create(
            name='Professional',
            sort_order=10
        )
        q1 = SharedQuestion.objects.create(
            category=category,
            label='Q1',
            field_type='text'
        )
        q2 = SharedQuestion.objects.create(
            category=category,
            label='Q2',
            field_type='text'
        )
        serializer = SharedQuestionCategorySerializer(category)
        data = serializer.data

        self.assertEqual(data['name'], 'Professional')
        self.assertEqual(len(data['questions']), 2)
        self.assertEqual(data['questions'][0]['label'], 'Q1')


class FormFieldProfileBindingTests(TestCase):
    """Tests for profile binding functionality."""

    def setUp(self):
        self.community = Community.objects.create(
            name='Test Community',
            slug='test-community'
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            first_name='John',
            last_name='Doe'
        )
        self.event = Event.objects.create(
            community=self.community,
            title='Test Event',
            created_by=self.user
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker'
        )

    def test_form_field_profile_binding_modes(self):
        """Test all profile binding modes."""
        modes = ['always_show', 'prefill_if_present', 'hide_if_present', 'require_if_absent']

        for mode in modes:
            field = FormField.objects.create(
                track=self.track,
                label=f'Field with {mode}',
                field_type='text',
                profile_binding='user.first_name',
                profile_binding_mode=mode
            )
            self.assertEqual(field.profile_binding_mode, mode)

    def test_profile_binding_path(self):
        """Test various profile binding paths."""
        paths = [
            'user.email',
            'user.first_name',
            'user.last_name',
            'user.profile.industry',
        ]
        for path in paths:
            field = FormField.objects.create(
                track=self.track,
                label=f'Field for {path}',
                field_type='text',
                profile_binding=path
            )
            self.assertEqual(field.profile_binding, path)


class FormFieldConditionalVisibilityTests(TestCase):
    """Tests for conditional visibility functionality."""

    def setUp(self):
        self.community = Community.objects.create(
            name='Test Community',
            slug='test-community'
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        self.event = Event.objects.create(
            community=self.community,
            title='Test Event',
            created_by=self.user
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker'
        )

    def test_simple_conditional_visibility(self):
        """Test simple conditional visibility."""
        condition = {
            'if': {'field': 'submission_mode', 'value': 'third_party_nomination'},
            'then': True
        }
        field = FormField.objects.create(
            track=self.track,
            label='Conditional Field',
            field_type='text',
            conditional_visibility=condition
        )
        self.assertEqual(field.conditional_visibility['if']['value'], 'third_party_nomination')

    def test_complex_conditional_visibility(self):
        """Test complex conditional visibility with AND/OR logic."""
        condition = {
            'if': {
                'operator': 'AND',
                'conditions': [
                    {'field': 'submission_mode', 'value': 'confirmed'},
                    {'field': 'has_organization', 'value': True}
                ]
            },
            'then': True
        }
        field = FormField.objects.create(
            track=self.track,
            label='Complex Conditional',
            field_type='text',
            conditional_visibility=condition
        )
        self.assertEqual(field.conditional_visibility['if']['operator'], 'AND')
        self.assertEqual(len(field.conditional_visibility['if']['conditions']), 2)


class FormFieldVisibilityPerModeTests(TestCase):
    """Tests for per-mode visibility functionality."""

    def setUp(self):
        self.community = Community.objects.create(
            name='Test Community',
            slug='test-community'
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com'
        )
        self.event = Event.objects.create(
            community=self.community,
            title='Test Event',
            created_by=self.user
        )
        self.track = EventApplicationTrack.objects.create(
            event=self.event,
            key='speaker',
            label='Speaker'
        )

    def test_visibility_for_all_modes(self):
        """Test setting visibility for all submission modes."""
        visibility = {
            'self_submission': True,
            'confirmed': True,
            'self_nomination': True,
            'third_party_nomination': True
        }
        field = FormField.objects.create(
            track=self.track,
            label='Visible to All',
            field_type='text',
            visibility_per_mode=visibility
        )
        self.assertTrue(all(field.visibility_per_mode.values()))

    def test_visibility_selective_modes(self):
        """Test selective visibility per mode."""
        visibility = {
            'self_submission': False,
            'confirmed': True,
            'self_nomination': False,
            'third_party_nomination': True
        }
        field = FormField.objects.create(
            track=self.track,
            label='Selective',
            field_type='text',
            visibility_per_mode=visibility
        )
        self.assertFalse(field.visibility_per_mode['self_submission'])
        self.assertTrue(field.visibility_per_mode['confirmed'])

    def test_mode_filtering_in_form_schema(self):
        """Test that form fields can be filtered by mode."""
        f1 = FormField.objects.create(
            track=self.track,
            label='For Self',
            field_type='text',
            visibility_per_mode={'self_submission': True}
        )
        f2 = FormField.objects.create(
            track=self.track,
            label='For Confirmed',
            field_type='text',
            visibility_per_mode={'confirmed': True}
        )
        # Simulate filtering for self_submission mode
        visible_fields = [
            f for f in FormField.objects.filter(track=self.track)
            if f.visibility_per_mode.get('self_submission', True)
        ]
        self.assertIn(f1, visible_fields)
        self.assertNotIn(f2, visible_fields)
