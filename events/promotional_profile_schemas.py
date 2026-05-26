"""
Promotional Profile Form Schemas

Defines complete form schemas for each promotional profile module:
- Speaker
- Sponsor Organisation
- Sponsor Staff
- Startup
- Investor
"""

import copy


def add_module_prefix(schema, module_prefix):
    """
    FIX 6: Add module prefix to all field IDs in schema to prevent collisions.

    Example:
        add_module_prefix(SPEAKER_MODULE_SCHEMA, "speaker_")

    Result:
        "display_name" → "speaker_display_name"
        "headshot" → "speaker_headshot"
    """
    schema_copy = copy.deepcopy(schema)

    for section in schema_copy.get("sections", []):
        for field in section.get("fields", []):
            original_id = field.get("id")
            if original_id:
                field["id"] = f"{module_prefix}{original_id}"

    return schema_copy


SPEAKER_MODULE_SCHEMA = {
    "sections": [
        {
            "id": "speaker_profile",
            "title": "Speaker Profile",
            "description": "Tell us about yourself as a speaker",
            "showIfIncludes": {"field": "active_modules", "value": "speaker"},
            "fields": [
                {
                    "id": "display_name",
                    "label": "Full Name",
                    "type": "text",
                    "required": True,
                    "placeholder": "Your full name"
                },
                {
                    "id": "programme_title",
                    "label": "Title/Position",
                    "type": "text",
                    "required": True,
                    "placeholder": "Your professional title"
                },
                {
                    "id": "programme_affiliation",
                    "label": "Company/Organization",
                    "type": "text",
                    "required": True,
                    "placeholder": "Your organization"
                },
                {
                    "id": "headshot",
                    "label": "Headshot",
                    "type": "file_upload",
                    "required": True,
                    "accept": "image/png,image/jpeg",
                    "help_text": "JPG or PNG format. Minimum 1500×1500 pixels. Maximum 10 MB."
                }
            ]
        },
        {
            "id": "speaker_bio",
            "title": "Biography",
            "showIfIncludes": {"field": "active_modules", "value": "speaker"},
            "fields": [
                {
                    "id": "programme_bio",
                    "label": "Bio",
                    "type": "textarea",
                    "required": True,
                    "placeholder": "Write about yourself in third person",
                    "help_text": "100–200 words. Write in third person (e.g., 'John is a software engineer...' rather than 'I am a software engineer...')."
                },
                {
                    "id": "short_bio",
                    "label": "Short Bio",
                    "type": "textarea",
                    "required": True,
                    "placeholder": "One sentence describing yourself",
                    "help_text": "One sentence. Maximum 200 characters."
                }
            ]
        },
        {
            "id": "speaker_session",
            "title": "Session Details",
            "showIfIncludes": {"field": "active_modules", "value": "speaker"},
            "fields": [
                {
                    "id": "talk_title",
                    "label": "Talk/Session Title",
                    "type": "text",
                    "required": True
                },
                {
                    "id": "talk_abstract",
                    "label": "Talk Abstract",
                    "type": "textarea",
                    "required": True,
                    "placeholder": "Describe your talk",
                    "help_text": "3–5 sentences describing the key points and value of your talk."
                },
                {
                    "id": "session_format",
                    "label": "Session Format",
                    "type": "select",
                    "required": True,
                    "options": [
                        {"value": "keynote", "label": "Keynote"},
                        {"value": "panel", "label": "Panel"},
                        {"value": "workshop", "label": "Workshop"},
                        {"value": "lightning_talk", "label": "Lightning Talk"},
                        {"value": "demo", "label": "Demo"}
                    ]
                },
                {
                    "id": "co_speakers",
                    "label": "Co-Speakers (if any)",
                    "type": "text",
                    "required": False
                },
                {
                    "id": "av_requirements",
                    "label": "A/V Requirements",
                    "type": "textarea",
                    "required": False,
                    "placeholder": "Any special equipment or setup needed"
                },
                {
                    "id": "slide_deck",
                    "label": "Slide Deck",
                    "type": "file_upload",
                    "required": False,
                    "accept": "application/pdf,application/vnd.ms-powerpoint,application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    "help_text": "PDF or PowerPoint format. Maximum 50 MB."
                }
            ]
        },
        {
            "id": "speaker_social",
            "title": "Social & Web Presence",
            "showIfIncludes": {"field": "active_modules", "value": "speaker"},
            "fields": [
                {
                    "id": "linkedin_url",
                    "label": "LinkedIn URL",
                    "type": "url",
                    "required": False
                },
                {
                    "id": "twitter_handle",
                    "label": "Twitter Handle",
                    "type": "text",
                    "required": False,
                    "placeholder": "@yourhandle"
                },
                {
                    "id": "personal_website",
                    "label": "Personal Website",
                    "type": "url",
                    "required": False
                },
                {
                    "id": "display_consent",
                    "label": "Display Consent - May we publish your profile publicly?",
                    "type": "select",
                    "required": True,
                    "options": [
                        {"value": "yes", "label": "Yes"},
                        {"value": "no", "label": "No"}
                    ]
                }
            ]
        }
    ]
}

SPONSOR_ORGANISATION_MODULE_SCHEMA = {
    "sections": [
        {
            "id": "sponsor_org_info",
            "title": "Organization Information",
            "showIfIncludes": {"field": "active_modules", "value": "sponsor"},
            "fields": [
                {
                    "id": "organisation_name_display",
                    "label": "Organization Name",
                    "type": "text",
                    "required": True
                },
                {
                    "id": "organisation_logo",
                    "label": "Logo (PNG/SVG, 500x500px minimum)",
                    "type": "file_upload",
                    "required": True,
                    "accept": "image/png,image/svg+xml"
                },
                {
                    "id": "organisation_logo_dark",
                    "label": "Logo Dark Mode (optional)",
                    "type": "file_upload",
                    "required": False,
                    "accept": "image/png,image/svg+xml"
                }
            ]
        },
        {
            "id": "sponsor_description",
            "title": "About Your Organization",
            "showIfIncludes": {"field": "active_modules", "value": "sponsor"},
            "fields": [
                {
                    "id": "tagline",
                    "label": "Tagline",
                    "type": "text",
                    "required": True,
                    "placeholder": "One-line description"
                },
                {
                    "id": "programme_description",
                    "label": "Description",
                    "type": "textarea",
                    "required": True,
                    "placeholder": "Tell attendees about your organization"
                },
                {
                    "id": "website_url",
                    "label": "Website",
                    "type": "url",
                    "required": True
                }
            ]
        },
        {
            "id": "sponsor_tier",
            "title": "Sponsorship Details",
            "showIfIncludes": {"field": "active_modules", "value": "sponsor"},
            "fields": [
                {
                    "id": "sponsor_tier",
                    "label": "Sponsorship Tier",
                    "type": "select",
                    "required": True,
                    "options": [
                        {"value": "platinum", "label": "Platinum"},
                        {"value": "gold", "label": "Gold"},
                        {"value": "silver", "label": "Silver"},
                        {"value": "bronze", "label": "Bronze"},
                        {"value": "other", "label": "Other"}
                    ]
                },
                {
                    "id": "booth_activation_details",
                    "label": "Booth/Activation Details",
                    "type": "textarea",
                    "required": False
                },
                {
                    "id": "deliverables",
                    "label": "Deliverables (PDFs, images, etc.)",
                    "type": "file_upload_multiple",
                    "required": False,
                    "accept": "*/*"
                }
            ]
        },
        {
            "id": "sponsor_contact",
            "title": "Contact Information",
            "showIfIncludes": {"field": "active_modules", "value": "sponsor"},
            "fields": [
                {
                    "id": "primary_contact_name",
                    "label": "Primary Contact Name",
                    "type": "text",
                    "required": True
                },
                {
                    "id": "primary_contact_email",
                    "label": "Primary Contact Email",
                    "type": "email",
                    "required": True
                },
                {
                    "id": "display_consent",
                    "label": "Display Consent - May we publish your organization's profile publicly?",
                    "type": "select",
                    "required": True,
                    "options": [
                        {"value": "yes", "label": "Yes"},
                        {"value": "no", "label": "No"}
                    ]
                }
            ]
        }
    ]
}

SPONSOR_STAFF_MODULE_SCHEMA = {
    "sections": [
        {
            "id": "staff_profile",
            "title": "Staff Member Profile",
            "showIfIncludes": {"field": "active_modules", "value": "sponsor_staff"},
            "fields": [
                {
                    "id": "display_name",
                    "label": "Full Name",
                    "type": "text",
                    "required": True
                },
                {
                    "id": "role_at_sponsor",
                    "label": "Role at Organization",
                    "type": "text",
                    "required": True
                },
                {
                    "id": "headshot",
                    "label": "Headshot",
                    "type": "file_upload",
                    "required": True,
                    "accept": "image/png,image/jpeg"
                }
            ]
        },
        {
            "id": "staff_engagement",
            "title": "Event Engagement",
            "showIfIncludes": {"field": "active_modules", "value": "sponsor_staff"},
            "fields": [
                {
                    "id": "booth_presence",
                    "label": "Will you be at the booth?",
                    "type": "select",
                    "required": True,
                    "options": [
                        {"value": "yes", "label": "Yes"},
                        {"value": "no", "label": "No"},
                        {"value": "part_time", "label": "Part-time"}
                    ]
                },
                {
                    "id": "areas_of_conversation",
                    "label": "Areas of Conversation",
                    "type": "textarea",
                    "required": False
                },
                {
                    "id": "display_consent",
                    "label": "Display Consent - May we publish your profile publicly?",
                    "type": "select",
                    "required": True,
                    "options": [
                        {"value": "yes", "label": "Yes"},
                        {"value": "no", "label": "No"}
                    ]
                }
            ]
        }
    ]
}

STARTUP_MODULE_SCHEMA = {
    "sections": [
        {
            "id": "startup_info",
            "title": "Startup Information",
            "showIfIncludes": {"field": "active_modules", "value": "startup"},
            "fields": [
                {
                    "id": "company_name_display",
                    "label": "Company Name",
                    "type": "text",
                    "required": True
                },
                {
                    "id": "company_logo",
                    "label": "Company Logo",
                    "type": "file_upload",
                    "required": True,
                    "accept": "image/png,image/jpeg,image/svg+xml"
                },
                {
                    "id": "one_line_pitch",
                    "label": "One-Line Pitch",
                    "type": "text",
                    "required": True,
                    "placeholder": "How would you describe your startup in one sentence?"
                }
            ]
        },
        {
            "id": "startup_description",
            "title": "About Your Company",
            "showIfIncludes": {"field": "active_modules", "value": "startup"},
            "fields": [
                {
                    "id": "programme_description",
                    "label": "Company Description",
                    "type": "textarea",
                    "required": True
                },
                {
                    "id": "stage",
                    "label": "Stage",
                    "type": "select",
                    "required": True,
                    "options": [
                        {"value": "idea", "label": "Idea"},
                        {"value": "pre_seed", "label": "Pre-seed"},
                        {"value": "seed", "label": "Seed"},
                        {"value": "series_a", "label": "Series A"},
                        {"value": "series_b", "label": "Series B"},
                        {"value": "later", "label": "Later"}
                    ]
                },
                {
                    "id": "sector_industry",
                    "label": "Sector/Industry",
                    "type": "select",
                    "required": True,
                    "options": [
                        {"value": "aiml", "label": "AI/ML"},
                        {"value": "climate", "label": "Climate"},
                        {"value": "fintech", "label": "Fintech"},
                        {"value": "healthtech", "label": "Healthtech"},
                        {"value": "other", "label": "Other"}
                    ]
                },
                {
                    "id": "founded_year",
                    "label": "Founded Year",
                    "type": "number",
                    "required": True
                }
            ]
        },
        {
            "id": "startup_web",
            "title": "Web Presence",
            "showIfIncludes": {"field": "active_modules", "value": "startup"},
            "fields": [
                {
                    "id": "website_url",
                    "label": "Website",
                    "type": "url",
                    "required": True
                },
                {
                    "id": "demo_url",
                    "label": "Demo/Product URL",
                    "type": "url",
                    "required": False
                }
            ]
        },
        {
            "id": "startup_pitch",
            "title": "Pitch Materials",
            "showIfIncludes": {"field": "active_modules", "value": "startup"},
            "fields": [
                {
                    "id": "public_pitch_deck",
                    "label": "Pitch Deck (PDF)",
                    "type": "file_upload",
                    "required": False,
                    "accept": "application/pdf"
                },
                {
                    "id": "founder_names_roles",
                    "label": "Founder Names & Roles",
                    "type": "textarea",
                    "required": True
                },
                {
                    "id": "founder_photos",
                    "label": "Founder Photos",
                    "type": "file_upload_multiple",
                    "required": False,
                    "accept": "image/png,image/jpeg"
                },
                {
                    "id": "display_consent",
                    "label": "Display Consent - May we publish your startup's profile publicly?",
                    "type": "select",
                    "required": True,
                    "options": [
                        {"value": "yes", "label": "Yes"},
                        {"value": "no", "label": "No"}
                    ]
                }
            ]
        }
    ]
}

INVESTOR_MODULE_SCHEMA = {
    "sections": [
        {
            "id": "investor_info",
            "title": "Investor Profile",
            "showIfIncludes": {"field": "active_modules", "value": "investor"},
            "fields": [
                {
                    "id": "display_name",
                    "label": "Name/Firm Name",
                    "type": "text",
                    "required": True
                },
                {
                    "id": "display_logo",
                    "label": "Logo",
                    "type": "file_upload",
                    "required": True,
                    "accept": "image/png,image/jpeg,image/svg+xml"
                }
            ]
        },
        {
            "id": "investor_thesis",
            "title": "Investment Thesis",
            "showIfIncludes": {"field": "active_modules", "value": "investor"},
            "fields": [
                {
                    "id": "thesis_tagline",
                    "label": "Investment Thesis Tagline",
                    "type": "text",
                    "required": True
                },
                {
                    "id": "stage_focus",
                    "label": "Stage Focus",
                    "type": "select",
                    "required": True,
                    "options": [
                        {"value": "pre_seed", "label": "Pre-seed"},
                        {"value": "seed", "label": "Seed"},
                        {"value": "series_a", "label": "Series A"},
                        {"value": "series_b_plus", "label": "Series B+"},
                        {"value": "all_stages", "label": "All stages"}
                    ]
                },
                {
                    "id": "sector_focus",
                    "label": "Sector Focus",
                    "type": "select",
                    "required": True,
                    "options": [
                        {"value": "aiml", "label": "AI/ML"},
                        {"value": "climate", "label": "Climate"},
                        {"value": "fintech", "label": "Fintech"},
                        {"value": "healthtech", "label": "Healthtech"},
                        {"value": "other", "label": "Other"},
                        {"value": "multi_sector", "label": "Multi-sector"}
                    ]
                },
                {
                    "id": "geographic_focus",
                    "label": "Geographic Focus",
                    "type": "text",
                    "required": True
                },
                {
                    "id": "cheque_size_range",
                    "label": "Typical Check Size",
                    "type": "text",
                    "required": True,
                    "placeholder": "e.g., $250k - $1M"
                },
                {
                    "id": "open_to_inbound",
                    "label": "Open to Inbound?",
                    "type": "select",
                    "required": True,
                    "options": [
                        {"value": "yes", "label": "Yes"},
                        {"value": "no", "label": "No"},
                        {"value": "case_by_case", "label": "Case-by-case"}
                    ]
                },
                {
                    "id": "display_consent",
                    "label": "Display Consent - May we publish your investor profile publicly?",
                    "type": "select",
                    "required": True,
                    "options": [
                        {"value": "yes", "label": "Yes"},
                        {"value": "no", "label": "No"}
                    ]
                }
            ]
        }
    ]
}

# FIX 6: Prefixed schemas to prevent field ID collisions across modules
SPEAKER_SCHEMA_PREFIXED = add_module_prefix(SPEAKER_MODULE_SCHEMA, "speaker_")
SPONSOR_ORGANISATION_SCHEMA_PREFIXED = add_module_prefix(SPONSOR_ORGANISATION_MODULE_SCHEMA, "sponsor_org_")
SPONSOR_STAFF_SCHEMA_PREFIXED = add_module_prefix(SPONSOR_STAFF_MODULE_SCHEMA, "sponsor_staff_")
STARTUP_SCHEMA_PREFIXED = add_module_prefix(STARTUP_MODULE_SCHEMA, "startup_")
INVESTOR_SCHEMA_PREFIXED = add_module_prefix(INVESTOR_MODULE_SCHEMA, "investor_")

# FIX 3: Master schema combining all modules - use prefixed schemas to prevent field ID collisions
PROMOTIONAL_PROFILE_SCHEMA = {
    "sections": (
        SPEAKER_SCHEMA_PREFIXED.get("sections", []) +
        SPONSOR_ORGANISATION_SCHEMA_PREFIXED.get("sections", []) +
        SPONSOR_STAFF_SCHEMA_PREFIXED.get("sections", []) +
        STARTUP_SCHEMA_PREFIXED.get("sections", []) +
        INVESTOR_SCHEMA_PREFIXED.get("sections", [])
    )
}

# Mapping of module names to their prefixed schemas
MODULE_SCHEMAS_PREFIXED = {
    'speaker': SPEAKER_SCHEMA_PREFIXED,
    'sponsor_organisation': SPONSOR_ORGANISATION_SCHEMA_PREFIXED,
    'sponsor_staff': SPONSOR_STAFF_SCHEMA_PREFIXED,
    'startup': STARTUP_SCHEMA_PREFIXED,
    'investor': INVESTOR_SCHEMA_PREFIXED,
}
