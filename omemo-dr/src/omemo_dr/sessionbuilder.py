from __future__ import annotations

from typing import Optional

import logging

from .const import PQ_PREKEY_SIGNATURE_CONTEXT
from .ecc.curve import Curve
from .exceptions import InvalidKeyException
from .exceptions import UntrustedIdentityException
from .protocol.prekeywhispermessage import PreKeyWhisperMessage
from .ratchet.aliceparameters import AliceParameters
from .ratchet.bobparameters import BobParameters
from .ratchet.ratchetingsession import RatchetingSession
from .state.prekeybundle import PreKeyBundle
from .state.sessionrecord import SessionRecord
from .state.store import Store

log = logging.getLogger(__name__)


class SessionBuilder:
    def __init__(
        self,
        store: Store,
        recipient_id: str,
        device_id: int,
    ) -> None:
        self._store = store
        self._recipient_id = recipient_id
        self._device_id = device_id

    def process(
        self, session_record: SessionRecord, message: PreKeyWhisperMessage
    ) -> Optional[int]:
        message_version = message.get_message_version()
        their_identity_key = message.get_identity_key()

        unsigned_pre_key_id = None

        if not self._store.is_trusted_identity(self._recipient_id, their_identity_key):
            raise UntrustedIdentityException(self._recipient_id, their_identity_key)

        if message_version in (3, 4):
            unsigned_pre_key_id = self.process_message(session_record, message)
        else:
            raise AssertionError("Unknown version %s" % message_version)

        self._store.save_identity(self._recipient_id, their_identity_key)

        return unsigned_pre_key_id

    def process_message(
        self, session_record: SessionRecord, message: PreKeyWhisperMessage
    ) -> Optional[int]:
        if session_record.has_session_state(
            message.get_message_version(), message.get_base_key().serialize()
        ):
            log.warning(
                "We've already setupgetMessageVersion a "
                "session for this V3 message, letting bundled "
                "message fall through..."
            )
            return None

        our_signed_pre_key = self._store.load_signed_pre_key(
            message.get_signed_pre_key_id()
        )
        our_signed_pre_key_pair = our_signed_pre_key.get_key_pair()
        our_one_time_prekey = self._store.load_pre_key(
            message.get_pre_key_id()
        ).get_key_pair()

        our_pq_signed_pre_key = self._store.load_pq_signed_pre_key(
            message.get_pq_signed_pre_key_id()
        ).get_key_pair()

        parameters = BobParameters(
            self._store.get_identity_key_pair(),
            our_signed_pre_key_pair,
            our_signed_pre_key_pair,
            our_one_time_prekey,
            message.get_identity_key(),
            message.get_base_key(),
            our_pq_signed_pre_key,
            message.get_kem_ciphertext(),
        )

        if not session_record.is_fresh():
            session_record.archive_current_state()

        RatchetingSession.initialize_session_as_bob(
            session_record.get_session_state(),
            message.get_message_version(),
            parameters,
        )
        session_record.get_session_state().set_our_device_id(
            self._store.get_our_device_id()
        )
        session_record.get_session_state().set_remote_device_id(message.get_device_id())
        session_record.get_session_state().set_alice_base_key(
            message.get_base_key().serialize()
        )

        return message.get_pre_key_id()

    def process_pre_key_bundle(self, bundle: PreKeyBundle) -> None:
        if not self._store.is_trusted_identity(
            self._recipient_id, bundle.get_identity_key()
        ):
            raise UntrustedIdentityException(
                self._recipient_id, bundle.get_identity_key()
            )

        if not Curve.verify_signature(
            bundle.get_identity_key().get_public_key(),
            bundle.get_signed_pre_key().serialize(),
            bundle.get_signed_pre_key_signature(),
        ):
            raise InvalidKeyException("Invalid signature on device key!")

        their_pq_signed_pre_key = bundle.get_pq_signed_pre_key()
        if their_pq_signed_pre_key is None:
            raise InvalidKeyException("Bundle carries no PQ device key!")

        if not Curve.verify_signature(
            bundle.get_identity_key().get_public_key(),
            PQ_PREKEY_SIGNATURE_CONTEXT + their_pq_signed_pre_key.serialize(),
            bundle.get_pq_signed_pre_key_signature(),
        ):
            raise InvalidKeyException("Invalid signature on PQ device key!")

        session_record = self._store.load_session(self._recipient_id, self._device_id)
        our_base_key = Curve.generate_key_pair()
        their_signed_pre_key = bundle.get_signed_pre_key()
        their_one_time_pre_key = bundle.get_pre_key()
        their_one_time_pre_key_id = bundle.get_pre_key_id()

        parameters = AliceParameters(
            self._store.get_identity_key_pair(),
            our_base_key,
            bundle.get_identity_key(),
            their_signed_pre_key,
            their_signed_pre_key,
            their_one_time_pre_key,
            their_pq_signed_pre_key,
            bundle.get_pq_signed_pre_key_id(),
        )

        if not session_record.is_fresh():
            session_record.archive_current_state()

        kem_ciphertext = RatchetingSession.initialize_session_as_alice(
            session_record.get_session_state(),
            bundle.get_session_version(),
            parameters,
        )

        session_record.get_session_state().set_unacknowledged_pre_key_message(
            their_one_time_pre_key_id,
            bundle.get_signed_pre_key_id(),
            our_base_key.get_public_key(),
            bundle.get_pq_signed_pre_key_id(),
            kem_ciphertext,
        )
        session_record.get_session_state().set_our_device_id(
            self._store.get_our_device_id()
        )
        session_record.get_session_state().set_remote_device_id(
            bundle.get_remote_device_id()
        )
        session_record.get_session_state().set_alice_base_key(
            our_base_key.get_public_key().serialize()
        )
        self._store.store_session(self._recipient_id, self._device_id, session_record)
        self._store.save_identity(self._recipient_id, bundle.get_identity_key())
