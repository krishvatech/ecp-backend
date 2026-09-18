"""Named Mautic operations that an identity assertion can authorise.

An assertion is bound to exactly one of these, and the Mautic bridge accepts it
only on the route that performs that operation. Without this, an assertion
minted for one bridge route could be presented to another inside its short
validity window.

These strings are a contract with the Mautic plugin
(``EcpBridgeCampaignApiController``) and must match it exactly. This module
deliberately imports nothing, so both the client and the assertion signer can
depend on it.
"""

from __future__ import annotations

CAMPAIGN_CREATE = "campaign.create"
CAMPAIGN_UPDATE = "campaign.update"
CAMPAIGN_DELETE = "campaign.delete"
CAMPAIGN_EVENT_DELETE = "campaign.event.delete"
SEGMENT_CREATE = "segment.create"
SEGMENT_UPDATE = "segment.update"
SEGMENT_DELETE = "segment.delete"
SEGMENT_CONTACT_ADD = "segment.contact.add"
SEGMENT_CONTACT_REMOVE = "segment.contact.remove"
CONTACT_CREATE = "contact.create"
CONTACT_UPDATE = "contact.update"
CONTACT_TAG_ADD = "contact.tag.add"
CONTACT_TAG_REMOVE = "contact.tag.remove"
TAG_CREATE = "tag.create"
TAG_UPDATE = "tag.update"
TAG_DELETE = "tag.delete"
FIELD_CREATE = "field.create"
FIELD_UPDATE = "field.update"
FIELD_DELETE = "field.delete"
TEMPLATE_CREATE = "template.create"
TEMPLATE_UPDATE = "template.update"
TEMPLATE_DELETE = "template.delete"
TEMPLATE_DUPLICATE = "template.duplicate"

#: Every operation an assertion may be issued for. Anything else is refused at
#: signing time rather than relying on the bridge to reject it.
ASSERTABLE_OPERATIONS = frozenset(
    {
        CAMPAIGN_CREATE,
        CAMPAIGN_UPDATE,
        CAMPAIGN_DELETE,
        CAMPAIGN_EVENT_DELETE,
        SEGMENT_CREATE,
        SEGMENT_UPDATE,
        SEGMENT_DELETE,
        SEGMENT_CONTACT_ADD,
        SEGMENT_CONTACT_REMOVE,
        CONTACT_CREATE,
        CONTACT_UPDATE,
        CONTACT_TAG_ADD,
        CONTACT_TAG_REMOVE,
        TAG_CREATE,
        TAG_UPDATE,
        TAG_DELETE,
        FIELD_CREATE,
        FIELD_UPDATE,
        FIELD_DELETE,
        TEMPLATE_CREATE,
        TEMPLATE_UPDATE,
        TEMPLATE_DELETE,
        TEMPLATE_DUPLICATE,
    }
)
