"""Handler for revoke message."""

from .....messaging.base_handler import BaseHandler, HandlerException
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder
from ..messages.revoke import Revoke


class RevokeHandler(BaseHandler):
    """Handler for revoke message."""

    RECEIVED_TOPIC = "acapy::revocation-notification::received"
    WEBHOOK_TOPIC = "acapy::webhook::revocation-notification"

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle revoke message."""
        assert isinstance(context.message, Revoke)

        if not context.connection_ready:
            raise HandlerException("No connection established")

        self._logger.debug(
            "Received notification of revocation (unrevoke: %s) "
            "for cred issued in thread %s "
            "with comment: %s",
            context.message.unrevoke,
            context.message.thread_id,
            context.message.comment,
        )

        notificationPayload = {
            "thread_id": context.message.thread_id,
            "comment": context.message.comment,
        }

        if context.message.unrevoke is not None:
            notificationPayload["unrevoke"] = context.message.unrevoke

        # Emit a webhook
        if context.settings.get("revocation.monitor_notification"):
            await context.profile.notify(
                self.WEBHOOK_TOPIC,
                notificationPayload,
            )

        # Emit an event
        await context.profile.notify(
            self.RECEIVED_TOPIC,
            notificationPayload,
        )
