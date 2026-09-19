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
COMPANY_CREATE = "company.create"
COMPANY_UPDATE = "company.update"
COMPANY_DELETE = "company.delete"
COMPANY_CONTACT_ADD = "company.contact.add"
COMPANY_CONTACT_REMOVE = "company.contact.remove"
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
NEWSLETTER_TEST_SEND = "newsletter.test_send"
POINT_ACTION_CREATE = "point.action.create"
POINT_ACTION_UPDATE = "point.action.update"
POINT_ACTION_DELETE = "point.action.delete"
POINT_GROUP_CREATE = "point.group.create"
POINT_GROUP_UPDATE = "point.group.update"
POINT_GROUP_DELETE = "point.group.delete"
POINT_CONTACT_ADJUST = "point.contact.adjust"
POINT_CONTACT_GROUP_ADJUST = "point.contact_group.adjust"
POINT_TRIGGER_CREATE = "point.trigger.create"
POINT_TRIGGER_UPDATE = "point.trigger.update"
POINT_TRIGGER_DELETE = "point.trigger.delete"
POINT_TRIGGER_EVENT_CREATE = "point.trigger.event.create"
POINT_TRIGGER_EVENT_UPDATE = "point.trigger.event.update"
POINT_TRIGGER_EVENT_DELETE = "point.trigger.event.delete"
CONTACT_NOTE_CREATE = "contact.note.create"
CONTACT_DNC_ADD = "contact.dnc.add"
CONTACT_DNC_REMOVE = "contact.dnc.remove"
STAGE_CREATE = "stage.create"
STAGE_UPDATE = "stage.update"
STAGE_DELETE = "stage.delete"
STAGE_CONTACT_ADD = "stage.contact.add"
STAGE_CONTACT_REMOVE = "stage.contact.remove"

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
        COMPANY_CREATE,
        COMPANY_UPDATE,
        COMPANY_DELETE,
        COMPANY_CONTACT_ADD,
        COMPANY_CONTACT_REMOVE,
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
        NEWSLETTER_TEST_SEND,
        POINT_ACTION_CREATE,
        POINT_ACTION_UPDATE,
        POINT_ACTION_DELETE,
        POINT_GROUP_CREATE,
        POINT_GROUP_UPDATE,
        POINT_GROUP_DELETE,
        POINT_CONTACT_ADJUST,
        POINT_CONTACT_GROUP_ADJUST,
        POINT_TRIGGER_CREATE,
        POINT_TRIGGER_UPDATE,
        POINT_TRIGGER_DELETE,
        POINT_TRIGGER_EVENT_CREATE,
        POINT_TRIGGER_EVENT_UPDATE,
        POINT_TRIGGER_EVENT_DELETE,
        CONTACT_NOTE_CREATE,
        CONTACT_DNC_ADD,
        CONTACT_DNC_REMOVE,
        STAGE_CREATE,
        STAGE_UPDATE,
        STAGE_DELETE,
        STAGE_CONTACT_ADD,
        STAGE_CONTACT_REMOVE,
    }
)
