"""
Promotional Profile Form Schemas

Defines complete form schemas for each promotional profile module:
- Speaker
- Sponsor Organisation
- Sponsor Staff
- Startup
- Investor
"""

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
                    "label": "Headshot (PNG/JPG, min 500x500px)",
                    "type": "file_upload",
                    "required": True,
                    "accept": "image/png,image/jpeg"
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
                    "label": "Extended Bio (for program materials)",
                    "type": "textarea",
                    "required": True,
                    "placeholder": "200-300 words about your background and expertise"
                },
                {
                    "id": "short_bio",
                    "label": "Short Bio (for website)",
                    "type": "textarea",
                    "required": True,
                    "placeholder": "50-100 words"
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
                    "placeholder": "200-300 words describing your talk"
                },
                {
                    "id": "session_format",
                    "label": "Session Format",
                    "type": "select",
                    "required": True,
                    "options": ["Keynote", "Panel", "Workshop", "Lightning Talk", "Demo"]
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
                    "label": "Slide Deck (PDF)",
                    "type": "file_upload",
                    "required": False,
                    "accept": "application/pdf"
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
                    "options": ["Yes", "No"]
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
                    "options": ["Platinum", "Gold", "Silver", "Bronze", "Other"]
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
                    "options": ["Yes", "No"]
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
                    "options": ["Yes", "No", "Part-time"]
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
                    "options": ["Yes", "No"]
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
                    "options": ["Idea", "Pre-seed", "Seed", "Series A", "Series B", "Later"]
                },
                {
                    "id": "sector_industry",
                    "label": "Sector/Industry",
                    "type": "select",
                    "required": True,
                    "options": ["AI/ML", "Climate", "Fintech", "Healthtech", "Other"]
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
                    "options": ["Yes", "No"]
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
                    "options": ["Pre-seed", "Seed", "Series A", "Series B+", "All stages"]
                },
                {
                    "id": "sector_focus",
                    "label": "Sector Focus",
                    "type": "select",
                    "required": True,
                    "options": ["AI/ML", "Climate", "Fintech", "Healthtech", "Other", "Multi-sector"]
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
                    "options": ["Yes", "No", "Case-by-case"]
                },
                {
                    "id": "display_consent",
                    "label": "Display Consent - May we publish your investor profile publicly?",
                    "type": "select",
                    "required": True,
                    "options": ["Yes", "No"]
                }
            ]
        }
    ]
}

# Master schema combining all modules
PROMOTIONAL_PROFILE_SCHEMA = {
    "sections": (
        SPEAKER_MODULE_SCHEMA.get("sections", []) +
        SPONSOR_ORGANISATION_MODULE_SCHEMA.get("sections", []) +
        SPONSOR_STAFF_MODULE_SCHEMA.get("sections", []) +
        STARTUP_MODULE_SCHEMA.get("sections", []) +
        INVESTOR_MODULE_SCHEMA.get("sections", [])
    )
}
