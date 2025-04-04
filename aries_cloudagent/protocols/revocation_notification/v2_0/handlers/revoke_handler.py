"""Handler for revoke message."""

from aries_cloudagent.protocols.didcomm_prefix import DIDCommPrefix
from .....messaging.base_handler import BaseHandler, HandlerException

from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder
from ..messages.revoke import Revoke
from ..messages.unrevoke import Unrevoke


class RevokeHandler(BaseHandler):
    """Handler for revoke message."""

    RECEIVED_TOPIC = "acapy::revocation-notification-v2::received"
    WEBHOOK_TOPIC = "acapy::webhook::revocation-notification-v2"

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle revoke message."""
        assert isinstance(context.message, (Revoke, Unrevoke))

        if not context.connection_ready:
            raise HandlerException("No connection established")

        self._logger.debug(
            "Received notification of revocation for %s cred %s with comment: %s",
            context.message.revocation_format,
            context.message.credential_id,
            context.message.comment,
        )

        message_type = DIDCommPrefix.NEW.qualify(context.message.Meta.message_type)

        # Emit a webhook
        if context.settings.get("revocation.monitor_notification"):
            await context.profile.notify(
                self.WEBHOOK_TOPIC,
                {
                    "@type": message_type,
                    "revocation_format": context.message.revocation_format,
                    "credential_id": context.message.credential_id,
                    "comment": context.message.comment,
                },
            )

        # Emit an event
        await context.profile.notify(
            self.RECEIVED_TOPIC,
            {
                "@type": message_type,
                "revocation_format": context.message.revocation_format,
                "credential_id": context.message.credential_id,
                "comment": context.message.comment,
            },
        )
