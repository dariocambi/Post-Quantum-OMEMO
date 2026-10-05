from __future__ import annotations

from typing import Union

from .aes import aes_cbc_decrypt
from .aes import aes_cbc_encrypt
from .ecc.curve import Curve
from .ecc.djbec import CurvePublicKey
from .exceptions import DuplicateMessageException
from .exceptions import InvalidMessageException
from .exceptions import NoSessionException
from .kdf.messagekeys import MessageKeys
from .protocol.prekeywhispermessage import PreKeyWhisperMessage
from .protocol.whispermessage import WhisperMessage
from .ratchet.chainkey import ChainKey
from .sessionbuilder import SessionBuilder
from .state.sessionrecord import SessionRecord
from .state.sessionstate import SessionState
from .state.store import Store


class SessionCipher:
    def __init__(self, store: Store, recipient_id: str, device_id: int) -> None:
        self._store = store
        self._recipient_id = recipient_id
        self._device_id = device_id
        self._session_builder = SessionBuilder(
            store,
            recipient_id,
            device_id,
        )

    def encrypt(
        self, padded_message: Union[bytes, str]
    ) -> Union[WhisperMessage, PreKeyWhisperMessage]:
        if isinstance(padded_message, str):
            padded_message = padded_message.encode()

        session_record = self._store.load_session(self._recipient_id, self._device_id)
        session_state = session_record.get_session_state()
        chain_key = session_state.get_sender_chain_key()
        message_keys = chain_key.get_message_keys()
        sender_ephemeral = session_state.get_sender_ratchet_key()
        previous_counter = session_state.get_previous_counter()
        session_version = session_state.get_session_version()

        ciphertext_body = self.get_ciphertext(
            session_version, message_keys, padded_message
        )

        ciphertext_message = WhisperMessage.new(
            session_version,
            message_keys.get_mac_key(),
            sender_ephemeral,
            chain_key.get_index(),
            previous_counter,
            ciphertext_body,
            session_state.get_local_identity_key(),
            session_state.get_remote_identity_key(),
        )

        if session_state.has_unacknowledged_pre_key_message():
            items = session_state.get_unacknowledged_pre_key_message_items()
            our_device_id = session_state.get_our_device_id()

            ciphertext_message = PreKeyWhisperMessage.new(
                session_version,
                our_device_id,
                items.get_pre_key_id(),
                items.get_signed_pre_key_id(),
                items.get_base_key(),
                session_state.get_local_identity_key(),
                ciphertext_message,
                items.get_pq_signed_pre_key_id(),   # PQ signed prekey id
                items.get_kem_ciphertext(),         # KEM ciphertext
            )

        session_state.set_sender_chain_key(chain_key.get_next_chain_key())
        self._store.store_session(self._recipient_id, self._device_id, session_record)

        return ciphertext_message

    def decrypt_msg(self, ciphertext: WhisperMessage) -> bytes:
        if not self._store.contains_session(self._recipient_id, self._device_id):
            raise NoSessionException(
                "No session for: %s, %s" % (self._recipient_id, self._device_id)
            )

        session_record = self._store.load_session(self._recipient_id, self._device_id)
        plaintext = self.decrypt_with_session_record(session_record, ciphertext)

        self._store.store_session(self._recipient_id, self._device_id, session_record)

        return plaintext

    def decrypt_pkmsg(self, ciphertext: PreKeyWhisperMessage) -> bytes:
        session_record = self._store.load_session(self._recipient_id, self._device_id)
        unsigned_pre_key_id = self._session_builder.process(session_record, ciphertext)
        plaintext = self.decrypt_with_session_record(
            session_record, ciphertext.get_whisper_message()
        )

        self._store.store_session(self._recipient_id, self._device_id, session_record)

        if unsigned_pre_key_id is not None:
            self._store.remove_pre_key(unsigned_pre_key_id)

        return plaintext

    def decrypt_with_session_record(
        self, session_record: SessionRecord, cipher_text: WhisperMessage
    ) -> bytes:
        previous_states = session_record.get_previous_session_states()
        exceptions: list[Exception] = []
        try:
            session_state = SessionState(session_record.get_session_state())
            plaintext = self.decrypt_with_session_state(session_state, cipher_text)
            session_record.set_state(session_state)
            return plaintext
        except InvalidMessageException as e:
            exceptions.append(e)

        for i in range(0, len(previous_states)):
            previous_state = previous_states[i]
            try:
                promotedState = SessionState(previous_state)
                plaintext = self.decrypt_with_session_state(promotedState, cipher_text)
                previous_states.pop(i)
                session_record.promote_state(promotedState)
                return plaintext
            except InvalidMessageException as e:
                exceptions.append(e)

        raise InvalidMessageException("No valid sessions", exceptions)

    def decrypt_with_session_state(
        self, session_state: SessionState, ciphertext_message: WhisperMessage
    ) -> bytes:
        if not session_state.has_sender_chain():
            raise InvalidMessageException("Uninitialized session!")

        message_version = ciphertext_message.get_message_version()
        if message_version != session_state.get_session_version():
            raise InvalidMessageException(
                "Message version %s, but session version %s"
                % (
                    ciphertext_message.get_message_version,
                    session_state.get_session_version(),
                )
            )

        their_ephemeral = ciphertext_message.get_sender_ratchet_key()
        counter = ciphertext_message.get_counter()
        chain_key = self.get_or_create_chain_key(session_state, their_ephemeral)
        message_keys = self.get_or_create_message_keys(
            session_state, their_ephemeral, chain_key, counter
        )

        ciphertext_message.verify_mac(
            session_state.get_remote_identity_key(),
            session_state.get_local_identity_key(),
            message_keys.get_mac_key(),
        )

        plaintext = self.get_plaintext(
            message_version, message_keys, ciphertext_message.get_body()
        )
        session_state.clear_unacknowledged_pre_key_message()

        return plaintext

    def get_or_create_chain_key(
        self,
        session_state: SessionState,
        ec_publick_key_their_ephemeral: CurvePublicKey,
    ) -> ChainKey:
        their_ephemeral = ec_publick_key_their_ephemeral
        if session_state.has_receiver_chain(their_ephemeral):
            return session_state.get_receiver_chain_key(their_ephemeral)
        else:
            root_key = session_state.get_root_key()
            our_ephemeral = session_state.get_sender_ratchet_key_pair()
            receiver_chain = root_key.create_chain(their_ephemeral, our_ephemeral)
            our_new_ephemeral = Curve.generate_key_pair()
            sender_chain = receiver_chain[0].create_chain(
                their_ephemeral, our_new_ephemeral
            )

            session_state.set_root_key(sender_chain[0])
            session_state.add_receiver_chain(their_ephemeral, receiver_chain[1])
            session_state.set_previous_counter(
                max(session_state.get_sender_chain_key().get_index() - 1, 0)
            )
            session_state.set_sender_chain(our_new_ephemeral, sender_chain[1])
            return receiver_chain[1]

    def get_or_create_message_keys(
        self,
        session_state: SessionState,
        ec_public_key_their_ephemeral: CurvePublicKey,
        chain_key: ChainKey,
        counter: int,
    ) -> MessageKeys:
        their_ephemeral = ec_public_key_their_ephemeral
        if chain_key.get_index() > counter:
            if session_state.has_message_keys(their_ephemeral, counter):
                return session_state.remove_message_keys(their_ephemeral, counter)
            else:
                raise DuplicateMessageException(
                    "Received message with old counter: %s, %s"
                    % (chain_key.get_index(), counter)
                )

        if counter - chain_key.get_index() > 2000:
            raise InvalidMessageException("Over 2000 messages into the future!")

        while chain_key.get_index() < counter:
            message_keys = chain_key.get_message_keys()
            session_state.set_message_keys(their_ephemeral, message_keys)
            chain_key = chain_key.get_next_chain_key()

        session_state.set_receiver_chain_key(
            their_ephemeral, chain_key.get_next_chain_key()
        )
        return chain_key.get_message_keys()

    def get_ciphertext(
        self, version: int, message_keys: MessageKeys, plaintext: bytes
    ) -> bytes:
        return aes_cbc_encrypt(
            message_keys.get_cipher_key(), message_keys.get_iv(), plaintext
        )

    def get_plaintext(
        self, version: int, message_keys: MessageKeys, ciphertext: bytes
    ) -> bytes:
        return aes_cbc_decrypt(
            message_keys.get_cipher_key(), message_keys.get_iv(), ciphertext
        )
