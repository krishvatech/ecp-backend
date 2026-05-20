"""
Speaker Module Schema for Promotional Profile Form

Collects public speaker collateral for event website, printed programme,
signage, and event app.
"""

SPEAKER_MODULE_SCHEMA = {
    "id": "speaker_module",
    "title": "Speaker Information",
    "description": "Please provide your speaker profile information for publication",
    "showIfIncludes": {"field": "active_modules", "value": "speaker"},
    "fields": [
        {
            "id": "display_name",
            "type": "text",
            "label": "Display Name",
            "required": True,
            "placeholder": "How you'd like to be listed",
            "help_text": "Your name as it will appear in the programme"
        },
        {
            "id": "programme_title",
            "type": "text",
            "label": "Professional Title",
            "required": True,
            "placeholder": "e.g., Senior Software Engineer, Product Manager",
            "help_text": "Your job title or professional designation"
        },
        {
            "id": "programme_affiliation",
            "type": "text",
            "label": "Company/Organization",
            "required": True,
            "placeholder": "Your organization name",
            "help_text": "Company or organization you're affiliated with"
        },
        {
            "id": "headshot",
            "type": "file_upload",
            "label": "Headshot Photo",
            "required": True,
            "accept": "image/jpeg,image/png",
            "help_text": "JPG or PNG, max 10 MB, minimum 1500 x 1500 px. For speaker directory and event materials."
        },
        {
            "id": "programme_bio",
            "type": "textarea",
            "label": "Programme Bio (Long)",
            "required": True,
            "rows": 6,
            "placeholder": "Write in third person. e.g., 'Jane is a...'",
            "help_text": "100–200 words in third person for printed programme and website"
        },
        {
            "id": "short_bio",
            "type": "textarea",
            "label": "Short Bio",
            "required": True,
            "rows": 2,
            "placeholder": "A one-liner about you",
            "help_text": "Maximum 200 characters for event app and signage"
        },
        {
            "id": "talk_title",
            "type": "text",
            "label": "Talk/Session Title",
            "required": True,
            "placeholder": "e.g., 'Building Scalable Systems in 2026'",
            "help_text": "Main title of your talk or session"
        },
        {
            "id": "talk_abstract",
            "type": "textarea",
            "label": "Talk Abstract",
            "required": True,
            "rows": 5,
            "placeholder": "Describe your talk in 100-150 words",
            "help_text": "Brief description of your talk for the programme"
        },
        {
            "id": "session_format",
            "type": "select",
            "label": "Session Format",
            "required": True,
            "options": [
                {"value": "keynote", "label": "Keynote"},
                {"value": "presentation", "label": "Presentation"},
                {"value": "panel", "label": "Panel Discussion"},
                {"value": "workshop", "label": "Workshop"},
                {"value": "lightning_talk", "label": "Lightning Talk"},
                {"value": "fireside_chat", "label": "Fireside Chat"},
                {"value": "other", "label": "Other"}
            ],
            "help_text": "Type of session you'll be delivering"
        },
        {
            "id": "co_speakers",
            "type": "text",
            "label": "Co-Speakers (Optional)",
            "required": False,
            "placeholder": "e.g., Jane Doe, John Smith",
            "help_text": "Names of other speakers in your session, comma-separated"
        },
        {
            "id": "av_requirements",
            "type": "textarea",
            "label": "A/V & Technical Requirements",
            "required": False,
            "rows": 3,
            "placeholder": "e.g., 'Projector, microphone, video playback'",
            "help_text": "Any special equipment or technical setup needed"
        },
        {
            "id": "slide_deck",
            "type": "file_upload",
            "label": "Slide Deck (Optional)",
            "required": False,
            "accept": "application/pdf,application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "help_text": "PDF or PPTX file, max 50 MB. Upload if available."
        },
        {
            "id": "linkedin_url",
            "type": "text",
            "label": "LinkedIn URL (Optional)",
            "required": False,
            "placeholder": "https://linkedin.com/in/yourprofile",
            "help_text": "Your LinkedIn profile URL"
        },
        {
            "id": "twitter_handle",
            "type": "text",
            "label": "Twitter/X Handle (Optional)",
            "required": False,
            "placeholder": "@yourhandle",
            "help_text": "Your Twitter/X handle (include @)"
        },
        {
            "id": "personal_website",
            "type": "text",
            "label": "Personal Website (Optional)",
            "required": False,
            "placeholder": "https://yourwebsite.com",
            "help_text": "Link to your personal website or portfolio"
        },
        {
            "id": "display_consent",
            "type": "select",
            "label": "Display Consent",
            "required": True,
            "options": [
                {"value": "yes", "label": "Yes, display my information publicly"},
                {"value": "no", "label": "No, keep my information private"}
            ],
            "help_text": "Allow your speaker information to be published in the programme and on the event website"
        }
    ]
}


# Validation rules and constraints
SPEAKER_VALIDATION_RULES = {
    "display_name": {
        "min_length": 2,
        "max_length": 150
    },
    "programme_title": {
        "min_length": 2,
        "max_length": 100
    },
    "programme_affiliation": {
        "min_length": 2,
        "max_length": 150
    },
    "programme_bio": {
        "min_words": 100,
        "max_words": 200,
        "help_text": "Write in third person (e.g., 'Jane is a senior engineer...')"
    },
    "short_bio": {
        "max_characters": 200
    },
    "talk_title": {
        "min_length": 3,
        "max_length": 200
    },
    "talk_abstract": {
        "min_words": 20,
        "max_words": 200
    },
    "headshot": {
        "allowed_formats": ["image/jpeg", "image/png"],
        "max_size_mb": 10,
        "min_width": 1500,
        "min_height": 1500
    },
    "slide_deck": {
        "allowed_formats": ["application/pdf", "application/vnd.openxmlformats-officedocument.presentationml.presentation"],
        "max_size_mb": 50,
        "allowed_extensions": [".pdf", ".pptx"]
    },
    "linkedin_url": {
        "url_pattern": r"^https?:\/\/(www\.)?linkedin\.com",
        "max_length": 255
    },
    "twitter_handle": {
        "url_pattern": r"^@?[A-Za-z0-9_]{1,15}$",
        "max_length": 20
    },
    "personal_website": {
        "url_pattern": r"^https?:\/\/",
        "max_length": 255
    }
}
