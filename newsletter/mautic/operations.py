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

#: Every operation an assertion may be issued for. Anything else is refused at
#: signing time rather than relying on the bridge to reject it.
ASSERTABLE_OPERATIONS = frozenset(
    {
        CAMPAIGN_CREATE,
        CAMPAIGN_UPDATE,
        CAMPAIGN_DELETE,
        CAMPAIGN_EVENT_DELETE,
    }
)
