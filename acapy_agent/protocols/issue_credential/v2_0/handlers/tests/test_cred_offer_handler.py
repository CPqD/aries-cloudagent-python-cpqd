from unittest import IsolatedAsyncioTestCase

from ......core.oob_processor import OobMessageProcessor
from ......messaging.request_context import RequestContext
from ......messaging.responder import MockResponder
from ......tests import mock
from ......transport.inbound.receipt import MessageReceipt
from ......utils.testing import create_test_profile
from ...messages.cred_offer import V20CredOffer
from .. import cred_offer_handler as test_module


class TestV20CredOfferHandler(IsolatedAsyncioTestCase):
    async def test_called(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.settings["debug.auto_respond_credential_offer"] = False
        request_context.connection_record = mock.MagicMock()

        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=mock.MagicMock()
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        with mock.patch.object(
            test_module, "V20CredManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_offer = mock.CoroutineMock()
            request_context.message = V20CredOffer()
            request_context.connection_ready = True
            handler_inst = test_module.V20CredOfferHandler()
            responder = MockResponder()
            await handler_inst.handle(request_context, responder)

        mock_cred_mgr.assert_called_once_with(request_context.profile)
        mock_cred_mgr.return_value.receive_offer.assert_called_once_with(
            request_context.message, request_context.connection_record.connection_id
        )
        mock_oob_processor.find_oob_record_for_inbound_message.assert_called_once_with(
            request_context
        )
        assert not responder.messages

    async def test_called_auto_request(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.settings["debug.auto_respond_credential_offer"] = True
        request_context.connection_record = mock.MagicMock()
        request_context.connection_record.my_did = "dummy"

        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=mock.MagicMock()
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        with mock.patch.object(
            test_module, "V20CredManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_offer = mock.CoroutineMock()
            mock_cred_mgr.return_value.create_request = mock.CoroutineMock(
                return_value=(None, "cred_request_message")
            )
            request_context.message = V20CredOffer()
            request_context.connection_ready = True
            handler_inst = test_module.V20CredOfferHandler()
            responder = MockResponder()
            await handler_inst.handle(request_context, responder)

        mock_cred_mgr.assert_called_once_with(request_context.profile)
        mock_cred_mgr.return_value.receive_offer.assert_called_once_with(
            request_context.message, request_context.connection_record.connection_id
        )
        mock_oob_processor.find_oob_record_for_inbound_message.assert_called_once_with(
            request_context
        )
        messages = responder.messages
        assert len(messages) == 1
        (result, target) = messages[0]
        assert result == "cred_request_message"
        assert target == {}

    async def test_called_auto_request_x_indy(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.settings["debug.auto_respond_credential_offer"] = True
        request_context.connection_record = mock.MagicMock()
        request_context.connection_record.my_did = "dummy"

        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=mock.MagicMock()
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        with mock.patch.object(
            test_module, "V20CredManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_offer = mock.CoroutineMock(
                return_value=mock.MagicMock(save_error_state=mock.CoroutineMock())
            )
            mock_cred_mgr.return_value.create_request = mock.CoroutineMock(
                side_effect=test_module.IndyHolderError()
            )

            request_context.message = V20CredOffer()
            request_context.connection_ready = True
            handler = test_module.V20CredOfferHandler()
            responder = MockResponder()

            with (
                mock.patch.object(
                    responder, "send_reply", mock.CoroutineMock()
                ) as mock_send_reply,
                mock.patch.object(
                    handler._logger, "exception", mock.MagicMock()
                ) as mock_log_exc,
            ):
                await handler.handle(request_context, responder)
                mock_log_exc.assert_called_once()

    async def test_called_auto_request_x_anoncreds(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.settings["debug.auto_respond_credential_offer"] = True
        request_context.connection_record = mock.MagicMock()
        request_context.connection_record.my_did = "dummy"

        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=mock.MagicMock()
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        with mock.patch.object(
            test_module, "V20CredManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_offer = mock.CoroutineMock(
                return_value=mock.MagicMock(save_error_state=mock.CoroutineMock())
            )
            mock_cred_mgr.return_value.create_request = mock.AsyncMock(
                side_effect=test_module.AnonCredsHolderError()
            )

            request_context.message = V20CredOffer()
            request_context.connection_ready = True
            handler = test_module.V20CredOfferHandler()
            responder = MockResponder()

            with (
                mock.patch.object(
                    responder, "send_reply", mock.CoroutineMock()
                ) as mock_send_reply,
                mock.patch.object(
                    handler._logger, "exception", mock.MagicMock()
                ) as mock_log_exc,
            ):
                await handler.handle(request_context, responder)
                mock_log_exc.assert_called_once()

    async def test_called_not_ready(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        with mock.patch.object(
            test_module, "V20CredManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_offer = mock.CoroutineMock()
            request_context.message = V20CredOffer()
            request_context.connection_ready = False
            handler_inst = test_module.V20CredOfferHandler()
            responder = MockResponder()
            with self.assertRaises(test_module.HandlerException) as err:
                await handler_inst.handle(request_context, responder)
            assert (
                err.exception.message == "Connection used for credential offer not ready"
            )

        assert not responder.messages

    async def test_no_conn_no_oob(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()

        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=None
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        request_context.message = V20CredOffer()
        request_context.connection_ready = False
        handler_inst = test_module.V20CredOfferHandler()
        responder = MockResponder()
        with self.assertRaises(test_module.HandlerException) as err:
            await handler_inst.handle(request_context, responder)
        assert (
            err.exception.message
            == "No connection or associated connectionless exchange found for credential offer"
        )

        assert not responder.messages
