"""Aries-Askar implementation of BaseWallet interface."""

import asyncio
import json
import logging
from ctypes import c_void_p, byref
from aries_cloudagent.wrappers import dinamo_wrapper
from typing import List, Optional, Sequence, Tuple, Union

from aries_askar import (
    AskarError,
    AskarErrorCode,
    Entry,
    Key,
    KeyAlg,
    SeedMethod,
)

from .did_parameters_validation import DIDParametersValidation
from ..askar.didcomm.v1 import pack_message, unpack_message
from ..askar.profile import AskarProfileSession
from ..ledger.base import BaseLedger
from ..ledger.endpoint_type import EndpointType
from ..ledger.error import LedgerConfigError
from ..storage.askar import AskarStorage
from ..storage.base import StorageRecord, StorageDuplicateError, StorageNotFoundError

from .base import BaseWallet, KeyInfo, DIDInfo
from .crypto import (
    sign_message,
    validate_seed,
    verify_signed_message,
)
from .did_info import INVITATION_REUSE_KEY
from .did_method import SOV, DIDMethod, DIDMethods
from .error import WalletError, WalletDuplicateError, WalletNotFoundError
from .key_type import BLS12381G2, ED25519, KeyType, KeyTypes
from .util import b58_to_bytes, bytes_to_b58

CATEGORY_DID = "did"
CATEGORY_CONFIG = "config"
RECORD_NAME_PUBLIC_DID = "default_public_did"

LOGGER = logging.getLogger(__name__)


class AskarWallet(BaseWallet):
    """Aries-Askar wallet implementation."""

    def __init__(self, session: AskarProfileSession):
        """Initialize a new `AskarWallet` instance.

        Args:
            session: The Askar profile session instance to use
        """
        self._session = session

    @property
    def session(self) -> AskarProfileSession:
        """Accessor for Askar profile session instance."""
        return self._session

    async def create_signing_key(
        self,
        key_type: KeyType,
        seed: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> KeyInfo:
        """Create a new public/private signing keypair.

        Args:
            key_type: Key type to create
            seed: Seed for key
            metadata: Optional metadata to store with the keypair

        Returns:
            A `KeyInfo` representing the new record

        Raises:
            WalletDuplicateError: If the resulting verkey already exists in the wallet
            WalletError: If there is another backend error

        """
        return await self.create_key(key_type, seed, metadata)

    async def create_key(
        self,
        key_type: KeyType,
        seed: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> KeyInfo:
        """Create a new public/private keypair.

        Args:
            key_type: Key type to create
            seed: Seed for key
            metadata: Optional metadata to store with the keypair

        Returns:
            A `KeyInfo` representing the new record

        Raises:
            WalletDuplicateError: If the resulting verkey already exists in the wallet
            WalletError: If there is another backend error
        """
        if metadata is None:
            metadata = {}
        try:
            keypair = _create_keypair(key_type, seed)
            verkey = bytes_to_b58(keypair.get_public_bytes())
            await self._session.handle.insert_key(
                verkey, keypair, metadata=json.dumps(metadata)
            )
        except AskarError as err:
            if err.code == AskarErrorCode.DUPLICATE:
                raise WalletDuplicateError(
                    "Verification key already present in wallet"
                ) from None
            raise WalletError("Error creating signing key") from err

        return KeyInfo(verkey=verkey, metadata=metadata, key_type=key_type)

    async def get_signing_key(self, verkey: str) -> KeyInfo:
        """Fetch info for a signing keypair.

        Args:
            verkey: The verification key of the keypair

        Returns:
            A `KeyInfo` representing the keypair

        Raises:
            WalletNotFoundError: If no keypair is associated with the verification key
            WalletError: If there is another backend error

        """

        if not verkey:
            raise WalletNotFoundError("No key identifier provided")
        key = await self._session.handle.fetch_key(verkey)
        if not key:
            raise WalletNotFoundError("Unknown key: {}".format(verkey))
        metadata = json.loads(key.metadata or "{}")
        # FIXME implement key types
        return KeyInfo(verkey=verkey, metadata=metadata, key_type=ED25519)

    async def replace_signing_key_metadata(self, verkey: str, metadata: dict):
        """Replace the metadata associated with a signing keypair.

        Args:
            verkey: The verification key of the keypair
            metadata: The new metadata to store

        Raises:
            WalletNotFoundError: if no keypair is associated with the verification key

        """

        # FIXME caller should always create a transaction first

        if not verkey:
            raise WalletNotFoundError("No key identifier provided")

        key = await self._session.handle.fetch_key(verkey, for_update=True)
        if not key:
            raise WalletNotFoundError("Keypair not found")
        await self._session.handle.update_key(
            verkey, metadata=json.dumps(metadata or {}), tags=key.tags
        )

    async def create_local_did(
        self,
        method: DIDMethod,
        key_type: KeyType,
        seed: Optional[str] = None,
        did: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> DIDInfo:
        """Create and store a new local DID.

        Args:
            method: The method to use for the DID
            key_type: The key type to use for the DID
            seed: Optional seed to use for DID
            did: The DID to use
            metadata: Metadata to store with DID

        Returns:
            A `DIDInfo` instance representing the created DID

        Raises:
            WalletDuplicateError: If the DID already exists in the wallet
            WalletError: If there is another backend error

        """
        did_validation = DIDParametersValidation(
            self._session.context.inject(DIDMethods)
        )
        did_validation.validate_key_type(method, key_type)

        if not metadata:
            metadata = {}

        try:
            # Inicializar a biblioteca Dinamo
            ret = dinamo_wrapper.initialize()
            if ret:
                raise WalletError(f"Dinamo initialization failed. Error code: {ret}")

            # Abrir uma sessão
            ret, hSession = dinamo_wrapper.open_session()
            if ret:
                raise WalletError(f"Failed to open session. Error code: {ret}")

            # Gerar uma chave usando DGenerateKey
            hKey = c_void_p()
            ret = dinamo_wrapper.libdinamo.DGenerateKey(hSession, dinamo_wrapper.KEY_ID.encode('utf-8'), dinamo_wrapper.KEY_TYPE, dinamo_wrapper.FLAGS, byref(hKey))
            if ret:
                raise WalletError(f"Failed to generate key. Error code: {ret}")

            # Pegar o valor da chave gerada
            keypair = dinamo_wrapper.get_key_value(hSession, hKey)
            verkey_bytes = keypair.get_public_bytes()
            verkey = bytes_to_b58(verkey_bytes)

            did = did_validation.validate_or_derive_did(
                method, key_type, verkey_bytes, did
            )

            try:
                await self._session.handle.insert_key(
                    verkey, keypair, metadata=json.dumps(metadata)
                )
            except AskarError as err:
                if err.code == AskarErrorCode.DUPLICATE:
                    # update metadata?
                    pass
                else:
                    raise WalletError("Error inserting key") from err

            item = await self._session.handle.fetch(CATEGORY_DID, did, for_update=True)
            if item:
                did_info = item.value_json
                if did_info.get("verkey") != verkey:
                    raise WalletDuplicateError("DID already present in wallet")
                if did_info.get("metadata") != metadata:
                    did_info["metadata"] = metadata
                    await self._session.handle.replace(
                        CATEGORY_DID, did, value_json=did_info, tags=item.tags
                    )
            else:
                value_json = {
                    "did": did,
                    "method": method.method_name,
                    "verkey": verkey,
                    "verkey_type": key_type.key_type,
                    "metadata": metadata,
                }
                tags = {
                    "method": method.method_name,
                    "verkey": verkey,
                    "verkey_type": key_type.key_type,
                }
                if INVITATION_REUSE_KEY in metadata:
                    tags[INVITATION_REUSE_KEY] = "true"
                await self._session.handle.insert(
                    CATEGORY_DID,
                    did,
                    value_json=value_json,
                    tags=tags,
                )

        except AskarError as err:
            raise WalletError("Error when creating local DID") from err

        return DIDInfo(
            did=did, verkey=verkey, metadata=metadata, method=method, key_type=key_type
        )

    async def store_did(self, did_info: DIDInfo):
        """Store a new DID in the wallet.

        Args:
            did_info: The `DIDInfo` instance representing the DID

        Raises:
            WalletDuplicateError: If the DID already exists in the wallet

        """

        keypair = await self.get_signing_key(did_info.verkey)
        did_validation = DIDParametersValidation(
            self._session.context.inject(DIDMethods)
        )
        did_validation.validate_or_derive_did(
            did_info.method, did_info.key_type, keypair.verkey.encode("ascii")
        )

        try:
            await self._session.handle.insert_key(
                did_info.verkey, keypair, metadata=json.dumps(did_info.metadata)
            )
        except AskarError as err:
            if err.code != AskarErrorCode.DUPLICATE:
                raise WalletError("Error storing signing key") from err

        item = await self._session.handle.fetch(CATEGORY_DID, did_info.did)
        if item:
            info = item.value_json
            if info.get("verkey") != did_info.verkey:
                raise WalletDuplicateError("DID already present in wallet")
            if info.get("metadata") != did_info.metadata:
                info["metadata"] = did_info.metadata
                await self._session.handle.replace(
                    CATEGORY_DID, did_info.did, value_json=info, tags=item.tags
                )
        else:
            value_json = {
                "did": did_info.did,
                "method": did_info.method.method_name,
                "verkey": did_info.verkey,
                "verkey_type": did_info.key_type.key_type,
                "metadata": did_info.metadata,
            }
            tags = {
                "method": did_info.method.method_name,
                "verkey": did_info.verkey,
                "verkey_type": did_info.key_type.key_type,
            }
            if INVITATION_REUSE_KEY in did_info.metadata:
                tags[INVITATION_REUSE_KEY] = "true"
            await self._session.handle.insert(
                CATEGORY_DID,
                did_info.did,
                value_json=value_json,
                tags=tags,
            )

    async def get_local_did(self, did: str) -> DIDInfo:
        """Retrieve a local DID by its ID.

        Args:
            did: The DID to retrieve

        Returns:
            A `DIDInfo` instance representing the retrieved DID

        Raises:
            WalletNotFoundError: If the DID is not found in the wallet

        """
        item = await self._session.handle.fetch(CATEGORY_DID, did)
        if not item:
            raise WalletNotFoundError("DID not found: {}".format(did))
        value_json = item.value_json
        return DIDInfo(
            did=did,
            verkey=value_json["verkey"],
            metadata=value_json["metadata"],
            method=DIDMethods().get_method(value_json["method"]),
            key_type=KeyTypes().get_key_type(value_json["verkey_type"]),
        )

    async def get_local_dids(self) -> Sequence[DIDInfo]:
        """List all local DIDs stored in the wallet.

        Returns:
            A list of `DIDInfo` instances representing all DIDs in the wallet

        """
        items = await self._session.handle.fetch_all(CATEGORY_DID)
        dids = []
        for item in items:
            value_json = item.value_json
            dids.append(
                DIDInfo(
                    did=value_json["did"],
                    verkey=value_json["verkey"],
                    metadata=value_json["metadata"],
                    method=DIDMethods().get_method(value_json["method"]),
                    key_type=KeyTypes().get_key_type(value_json["verkey_type"]),
                )
            )
        return dids

    async def get_public_did(self) -> Optional[DIDInfo]:
        """Retrieve the public DID from the wallet.

        Returns:
            A `DIDInfo` instance representing the public DID, or None if no public DID exists

        """
        item = await self._session.handle.fetch(CATEGORY_CONFIG, RECORD_NAME_PUBLIC_DID)
        if not item:
            return None
        return await self.get_local_did(item.value_json["did"])

    async def set_public_did(self, did: str) -> Optional[DIDInfo]:
        """Set the public DID for the wallet.

        Args:
            did: The DID to set as the public DID

        Returns:
            A `DIDInfo` instance representing the set public DID

        """
        if not did:
            await self._session.handle.delete(CATEGORY_CONFIG, RECORD_NAME_PUBLIC_DID)
            return None

        did_info = await self.get_local_did(did)
        await self._session.handle.replace(
            CATEGORY_CONFIG, RECORD_NAME_PUBLIC_DID, value_json={"did": did}
        )
        return did_info

    async def sign_message(self, message: Union[str, bytes], from_verkey: str) -> bytes:
        """Sign a message using the specified verkey.

        Args:
            message: The message to sign
            from_verkey: The verification key to sign the message with

        Returns:
            The signed message

        """
        message_bytes = message.encode("utf-8") if isinstance(message, str) else message
        key_info = await self.get_signing_key(from_verkey)
        return sign_message(message_bytes, key_info)

    async def verify_message(
        self, message: Union[str, bytes], signature: bytes, from_verkey: str
    ) -> bool:
        """Verify a signed message using the specified verkey.

        Args:
            message: The signed message to verify
            signature: The signature to verify against
            from_verkey: The verification key to verify the message with

        Returns:
            True if the signature is valid, False otherwise

        """
        message_bytes = message.encode("utf-8") if isinstance(message, str) else message
        return verify_signed_message(message_bytes, signature, from_verkey)

    async def pack_message(
        self, message: Union[str, bytes], to_verkeys: Sequence[str], from_verkey: str = None
    ) -> bytes:
        """Pack an encrypted message for the specified recipients.

        Args:
            message: The message to pack
            to_verkeys: A list of verification keys for the recipients
            from_verkey: The verification key of the sender

        Returns:
            The packed message

        """
        message_bytes = message.encode("utf-8") if isinstance(message, str) else message
        return await pack_message(message_bytes, to_verkeys, from_verkey)

    async def unpack_message(self, enc_message: Union[str, bytes]) -> dict:
        """Unpack an encrypted message.

        Args:
            enc_message: The encrypted message to unpack

        Returns:
            The unpacked message

        """
        enc_message_bytes = (
            enc_message.encode("utf-8") if isinstance(enc_message, str) else enc_message
        )
        return await unpack_message(enc_message_bytes)

    async def rotate_did_keypair(self, did: str, next_seed: str = None) -> DIDInfo:
        """Rotate the keypair for a local DID.

        Args:
            did: The DID to rotate the keypair for
            next_seed: Optional seed for the new keypair

        Returns:
            A `DIDInfo` instance representing the updated DID

        Raises:
            WalletNotFoundError: If the DID is not found in the wallet
            WalletError: If there is another backend error

        """
        did_info = await self.get_local_did(did)
        next_key_info = await self.create_key(did_info.key_type, next_seed)
        did_info = await self.get_local_did(did_info.did)
        await self.replace_signing_key_metadata(
            did_info.verkey, {**did_info.metadata, "previous_key": did_info.verkey}
        )
        did_info.verkey = next_key_info.verkey
        await self._session.handle.replace(
            CATEGORY_DID,
            did_info.did,
            value_json=did_info,
            tags={
                "method": did_info.method.method_name,
                "verkey": did_info.verkey,
                "verkey_type": did_info.key_type.key_type,
            },
        )
        return did_info
