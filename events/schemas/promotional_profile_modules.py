"""
Promotional Profile Modules for Sponsor, Start-up, and Investor roles.

Includes schemas for:
1. Sponsor Organisation Module
2. Sponsor Staff Module
3. Start-up Module
4. Investor Module
"""

# ==================== SPONSOR ORGANISATION MODULE ====================

SPONSOR_ORGANISATION_MODULE_SCHEMA = {
    "id": "sponsor_organisation_module",
    "title": "Sponsor Organisation Details",
    "description": "Please provide your organisation's information for the event directory",
    "showIfIncludes": {"field": "active_modules", "value": "sponsor"},
    "fields": [
        {
            "id": "organisation_name_display",
            "type": "text",
            "label": "Organisation Name",
            "required": True,
            "placeholder": "Your organisation name",
            "help_text": "Official organization name for display"
        },
        {
            "id": "organisation_logo",
            "type": "file_upload",
            "label": "Logo (Light/Default)",
            "required": True,
            "accept": "image/jpeg,image/png,image/svg+xml",
            "help_text": "PNG, JPEG, or SVG. Max 5 MB. Square format recommended."
        },
        {
            "id": "organisation_logo_dark",
            "type": "file_upload",
            "label": "Logo (Dark Mode)",
            "required": False,
            "accept": "image/jpeg,image/png,image/svg+xml",
            "help_text": "Optional dark mode version. PNG, JPEG, or SVG. Max 5 MB."
        },
        {
            "id": "tagline",
            "type": "text",
            "label": "Organisation Tagline",
            "required": True,
            "placeholder": "e.g., 'Leading cloud solutions provider'",
            "help_text": "One-line tagline (max 100 characters)"
        },
        {
            "id": "programme_description",
            "type": "textarea",
            "label": "Organisation Description",
            "required": True,
            "rows": 5,
            "placeholder": "Tell us about your organisation...",
            "help_text": "50-150 words describing your organisation"
        },
        {
            "id": "website_url",
            "type": "text",
            "label": "Website URL",
            "required": True,
            "placeholder": "https://www.example.com",
            "help_text": "Full URL to your website"
        },
        {
            "id": "sponsor_tier",
            "type": "text",
            "label": "Sponsor Tier",
            "required": False,
            "placeholder": "Display only",
            "help_text": "Your sponsorship tier (auto-populated from event settings)"
        },
        {
            "id": "booth_activation_details",
            "type": "textarea",
            "label": "Booth Activation & Activities",
            "required": False,
            "rows": 4,
            "placeholder": "What will you have at your booth?",
            "help_text": "Activities, giveaways, demos, etc. at your event booth"
        },
        {
            "id": "deliverables",
            "type": "file_upload_multiple",
            "label": "Deliverables/Marketing Materials",
            "required": False,
            "accept": "image/*,application/pdf",
            "help_text": "Upload marketing materials, brochures, etc. (up to 5 files, 10 MB each)"
        },
        {
            "id": "primary_contact_name",
            "type": "text",
            "label": "Primary Contact Name",
            "required": True,
            "placeholder": "Name of primary contact for event",
            "help_text": "Who should we contact about logistics?"
        },
        {
            "id": "primary_contact_email",
            "type": "email",
            "label": "Primary Contact Email",
            "required": True,
            "placeholder": "contact@organization.com",
            "help_text": "Contact email for event coordination"
        },
        {
            "id": "display_consent",
            "type": "select",
            "label": "Display Consent",
            "required": True,
            "options": [
                {"value": "yes", "label": "Yes, display our organisation publicly"},
                {"value": "no", "label": "No, keep our information private"}
            ],
            "help_text": "Allow your organisation info to be published"
        }
    ]
}


# ==================== SPONSOR STAFF MODULE ====================

SPONSOR_STAFF_MODULE_SCHEMA = {
    "id": "sponsor_staff_module",
    "title": "Sponsor Staff Information",
    "description": "Please provide your staff member's information for networking",
    "showIfIncludes": {"field": "active_modules", "value": "sponsor_staff"},
    "fields": [
        {
            "id": "display_name",
            "type": "text",
            "label": "Display Name",
            "required": True,
            "placeholder": "Your full name",
            "help_text": "How you'd like to be identified at the event"
        },
        {
            "id": "role_at_sponsor",
            "type": "text",
            "label": "Role/Title at Sponsor",
            "required": True,
            "placeholder": "e.g., Sales Director, Developer Advocate",
            "help_text": "Your position or role"
        },
        {
            "id": "headshot",
            "type": "file_upload",
            "label": "Headshot (Optional)",
            "required": False,
            "accept": "image/jpeg,image/png",
            "help_text": "JPG or PNG, max 5 MB. For networking directory."
        },
        {
            "id": "booth_presence",
            "type": "multi_select",
            "label": "Will You Be At The Booth?",
            "required": True,
            "options": [
                {"value": "full_time", "label": "Full time (all days)"},
                {"value": "specific_days", "label": "Specific days only"},
                {"value": "select_times", "label": "Specific times"},
                {"value": "no_booth", "label": "Not at booth (virtual/remote)"}
            ],
            "help_text": "When will you be available at the sponsor booth?"
        },
        {
            "id": "areas_of_conversation",
            "type": "multi_select",
            "label": "Areas of Conversation",
            "required": True,
            "options": [
                {"value": "sales", "label": "Sales & Partnerships"},
                {"value": "technical", "label": "Technical & Product"},
                {"value": "careers", "label": "Careers & Hiring"},
                {"value": "case_studies", "label": "Case Studies & Results"},
                {"value": "product_demo", "label": "Product Demo"},
                {"value": "events", "label": "Events & Community"}
            ],
            "help_text": "What would you like to discuss with attendees?"
        },
        {
            "id": "display_consent",
            "type": "select",
            "label": "Display Consent",
            "required": True,
            "options": [
                {"value": "yes", "label": "Yes, display my information"},
                {"value": "no", "label": "No, keep private"}
            ],
            "help_text": "Allow your information in the event directory"
        }
    ]
}


# ==================== START-UP MODULE ====================

STARTUP_MODULE_SCHEMA = {
    "id": "startup_module",
    "title": "Start-up Information",
    "description": "Please provide your start-up's information for investor and partner discovery",
    "showIfIncludes": {"field": "active_modules", "value": "startup"},
    "fields": [
        {
            "id": "company_name_display",
            "type": "text",
            "label": "Company Name",
            "required": True,
            "placeholder": "Your company name",
            "help_text": "Official company name"
        },
        {
            "id": "company_logo",
            "type": "file_upload",
            "label": "Company Logo",
            "required": True,
            "accept": "image/jpeg,image/png,image/svg+xml",
            "help_text": "PNG, JPEG, or SVG. Max 5 MB. Square format recommended."
        },
        {
            "id": "one_line_pitch",
            "type": "text",
            "label": "One-Line Pitch",
            "required": True,
            "placeholder": "The elevator pitch for your company",
            "help_text": "Maximum 140 characters. Example: 'AI-powered logistics platform for SMEs'"
        },
        {
            "id": "programme_description",
            "type": "textarea",
            "label": "Company Description",
            "required": True,
            "rows": 4,
            "placeholder": "Tell us about your start-up...",
            "help_text": "50-100 words describing your company, problem solved, and vision"
        },
        {
            "id": "stage",
            "type": "select",
            "label": "Funding Stage",
            "required": True,
            "options": [
                {"value": "pre_seed", "label": "Pre-Seed"},
                {"value": "seed", "label": "Seed"},
                {"value": "series_a", "label": "Series A"},
                {"value": "series_b", "label": "Series B"},
                {"value": "series_c", "label": "Series C+"},
                {"value": "growth", "label": "Growth/Late Stage"},
                {"value": "profitable", "label": "Profitable/Bootstrap"}
            ],
            "help_text": "Your current funding stage"
        },
        {
            "id": "sector_industry",
            "type": "multi_select",
            "label": "Sector/Industry",
            "required": True,
            "options": [
                {"value": "ai_ml", "label": "AI/Machine Learning"},
                {"value": "fintech", "label": "FinTech"},
                {"value": "healthtech", "label": "HealthTech"},
                {"value": "edtech", "label": "EdTech"},
                {"value": "climate", "label": "Climate Tech"},
                {"value": "cybersecurity", "label": "Cybersecurity"},
                {"value": "saas", "label": "SaaS"},
                {"value": "devtools", "label": "Developer Tools"},
                {"value": "web3", "label": "Web3/Crypto"},
                {"value": "other", "label": "Other"}
            ],
            "help_text": "Select primary sectors/industries"
        },
        {
            "id": "founded_year",
            "type": "number",
            "label": "Founded Year",
            "required": True,
            "placeholder": "2024",
            "help_text": "Year your company was founded"
        },
        {
            "id": "website_url",
            "type": "text",
            "label": "Website URL",
            "required": True,
            "placeholder": "https://www.example.com",
            "help_text": "Your website URL"
        },
        {
            "id": "demo_url",
            "type": "text",
            "label": "Product Demo URL (Optional)",
            "required": False,
            "placeholder": "https://demo.example.com",
            "help_text": "Link to live demo or product"
        },
        {
            "id": "public_pitch_deck",
            "type": "file_upload",
            "label": "Public Pitch Deck (Optional)",
            "required": False,
            "accept": "application/pdf",
            "help_text": "PDF only, max 25 MB. Share your investor pitch deck."
        },
        {
            "id": "founder_names_roles",
            "type": "textarea",
            "label": "Founder Names & Roles",
            "required": True,
            "rows": 3,
            "placeholder": "e.g., John Doe (CEO), Jane Smith (CTO), Bob Johnson (CFO)",
            "help_text": "List founders with their roles, comma-separated"
        },
        {
            "id": "founder_photos",
            "type": "file_upload_multiple",
            "label": "Founder Photos (Optional)",
            "required": False,
            "accept": "image/jpeg,image/png",
            "help_text": "Headshots of founders. JPG/PNG, max 3 MB each (up to 3 files)"
        },
        {
            "id": "display_consent",
            "type": "select",
            "label": "Display Consent",
            "required": True,
            "options": [
                {"value": "yes", "label": "Yes, display our company publicly"},
                {"value": "no", "label": "No, keep our information private"}
            ],
            "help_text": "Allow your company info to be published"
        }
    ]
}


# ==================== INVESTOR MODULE ====================

INVESTOR_MODULE_SCHEMA = {
    "id": "investor_module",
    "title": "Investor Profile",
    "description": "Please provide your investment focus and details for start-up discovery",
    "showIfIncludes": {"field": "active_modules", "value": "investor"},
    "fields": [
        {
            "id": "display_name",
            "type": "text",
            "label": "Display Name",
            "required": True,
            "placeholder": "Your name or firm name",
            "help_text": "How you'd like to be identified"
        },
        {
            "id": "display_logo",
            "type": "file_upload",
            "label": "Logo/Avatar (Optional)",
            "required": False,
            "accept": "image/jpeg,image/png,image/svg+xml",
            "help_text": "PNG, JPEG, or SVG. Max 5 MB. For investor directory."
        },
        {
            "id": "thesis_tagline",
            "type": "text",
            "label": "Investment Thesis Tagline",
            "required": True,
            "placeholder": "Your investment focus, max 200 characters",
            "help_text": "Max 200 characters. e.g., 'Early-stage AI/ML startups in Southeast Asia'"
        },
        {
            "id": "stage_focus",
            "type": "multi_select",
            "label": "Stage Focus",
            "required": True,
            "options": [
                {"value": "pre_seed", "label": "Pre-Seed"},
                {"value": "seed", "label": "Seed"},
                {"value": "series_a", "label": "Series A"},
                {"value": "series_b", "label": "Series B"},
                {"value": "series_c", "label": "Series C+"},
                {"value": "growth", "label": "Growth/Late Stage"}
            ],
            "help_text": "Which funding stages do you focus on?"
        },
        {
            "id": "sector_focus",
            "type": "multi_select",
            "label": "Sector Focus",
            "required": True,
            "options": [
                {"value": "ai_ml", "label": "AI/Machine Learning"},
                {"value": "fintech", "label": "FinTech"},
                {"value": "healthtech", "label": "HealthTech"},
                {"value": "edtech", "label": "EdTech"},
                {"value": "climate", "label": "Climate Tech"},
                {"value": "cybersecurity", "label": "Cybersecurity"},
                {"value": "saas", "label": "SaaS"},
                {"value": "devtools", "label": "Developer Tools"},
                {"value": "web3", "label": "Web3/Crypto"},
                {"value": "other", "label": "Other"}
            ],
            "help_text": "What sectors interest you?"
        },
        {
            "id": "geographic_focus",
            "type": "multi_select",
            "label": "Geographic Focus",
            "required": True,
            "options": [
                {"value": "north_america", "label": "North America"},
                {"value": "europe", "label": "Europe"},
                {"value": "asia_pacific", "label": "Asia Pacific"},
                {"value": "southeast_asia", "label": "Southeast Asia"},
                {"value": "india", "label": "India"},
                {"value": "middle_east", "label": "Middle East"},
                {"value": "africa", "label": "Africa"},
                {"value": "latin_america", "label": "Latin America"},
                {"value": "global", "label": "Global/No Geographic Focus"}
            ],
            "help_text": "Which regions do you invest in?"
        },
        {
            "id": "cheque_size_range",
            "type": "select",
            "label": "Typical Cheque Size",
            "required": True,
            "options": [
                {"value": "under_50k", "label": "< $50K"},
                {"value": "50k_250k", "label": "$50K - $250K"},
                {"value": "250k_1m", "label": "$250K - $1M"},
                {"value": "1m_5m", "label": "$1M - $5M"},
                {"value": "5m_10m", "label": "$5M - $10M"},
                {"value": "10m_plus", "label": "$10M+"},
                {"value": "varies", "label": "Varies by round"}
            ],
            "help_text": "Your typical investment size"
        },
        {
            "id": "open_to_inbound",
            "type": "select",
            "label": "Open to Inbound Pitches?",
            "required": True,
            "options": [
                {"value": "yes", "label": "Yes, open to pitches"},
                {"value": "no", "label": "No, not accepting pitches"},
                {"value": "selective", "label": "Selective (ask for details)"}
            ],
            "help_text": "Are you open to start-up pitches?"
        },
        {
            "id": "display_consent",
            "type": "select",
            "label": "Display Consent",
            "required": True,
            "options": [
                {"value": "yes", "label": "Yes, display my profile publicly"},
                {"value": "no", "label": "No, keep my information private"}
            ],
            "help_text": "Allow your investor profile to be published"
        }
    ]
}


# Validation Rules for All Modules

SPONSOR_VALIDATION_RULES = {
    "organisation_name_display": {"min_length": 2, "max_length": 150},
    "tagline": {"min_length": 5, "max_length": 100},
    "programme_description": {"min_words": 50, "max_words": 150},
    "organisation_logo": {
        "allowed_formats": ["image/jpeg", "image/png", "image/svg+xml"],
        "max_size_mb": 5,
        "allowed_extensions": [".jpg", ".jpeg", ".png", ".svg"]
    },
    "organisation_logo_dark": {
        "allowed_formats": ["image/jpeg", "image/png", "image/svg+xml"],
        "max_size_mb": 5,
        "allowed_extensions": [".jpg", ".jpeg", ".png", ".svg"]
    },
    "primary_contact_email": {"email_required": True}
}

SPONSOR_STAFF_VALIDATION_RULES = {
    "display_name": {"min_length": 2, "max_length": 150},
    "role_at_sponsor": {"min_length": 2, "max_length": 100},
    "headshot": {
        "allowed_formats": ["image/jpeg", "image/png"],
        "max_size_mb": 5,
        "allowed_extensions": [".jpg", ".jpeg", ".png"]
    }
}

STARTUP_VALIDATION_RULES = {
    "company_name_display": {"min_length": 2, "max_length": 150},
    "one_line_pitch": {"max_characters": 140},
    "programme_description": {"min_words": 50, "max_words": 100},
    "founded_year": {"min_year": 2000, "max_year": 2026},
    "company_logo": {
        "allowed_formats": ["image/jpeg", "image/png", "image/svg+xml"],
        "max_size_mb": 5
    },
    "public_pitch_deck": {
        "allowed_formats": ["application/pdf"],
        "max_size_mb": 25
    },
    "founder_photos": {
        "allowed_formats": ["image/jpeg", "image/png"],
        "max_size_mb": 3,
        "max_files": 3
    }
}

INVESTOR_VALIDATION_RULES = {
    "display_name": {"min_length": 2, "max_length": 150},
    "thesis_tagline": {"max_characters": 200},
    "display_logo": {
        "allowed_formats": ["image/jpeg", "image/png", "image/svg+xml"],
        "max_size_mb": 5
    }
}
