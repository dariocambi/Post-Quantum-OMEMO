import unittest

from omemo_dr.const import NS_OMEMO_TMP
from omemo_dr.exceptions import DuplicateMessage
from omemo_dr.session_manager import OMEMOSessionManager
from omemo_dr.structs import OMEMOConfig
from omemo_dr.structs import OMEMOMessage

from .inmemorystore import InMemoryStore


class SessionBuilderTest(unittest.TestCase):
    def test_omemo_tmp_session(self):
        bob_store = InMemoryStore()
        alice_store = InMemoryStore()

        config = OMEMOConfig(
            default_prekey_amount=100,
            min_prekey_amount=80,
            spk_archive_seconds=86400 * 15,
            spk_cycle_seconds=86400,
            unacknowledged_count=2000,
        )

        bob_session_manager = OMEMOSessionManager(
            "bob",
            bob_store,
            config,
        )

        alice_session_manager = OMEMOSessionManager(
            "alice",
            alice_store,
            config,
        )

        # Bob gets alice`s bundle and build session
        alice_bundle = alice_session_manager.get_bundle(NS_OMEMO_TMP)
        bob_session_manager.update_devicelist("alice", [alice_bundle.device_id])
        bob_session_manager.build_session("alice", alice_bundle)

        alice_device_id = alice_session_manager.get_our_device()
        bob_device_id = bob_session_manager.get_our_device()

        # Bob sends message
        sent_plaintext = "some test message"

        omemo_message = bob_session_manager.encrypt(
            "alice", sent_plaintext, groupchat=False
        )
        assert omemo_message is not None

        # Check if first message is a pre key message
        self.assertTrue(omemo_message.keys[alice_device_id][1])

        # Alice receives message
        received_plaintext, _, _ = alice_session_manager.decrypt_message(
            omemo_message, "bob"
        )

        self.assertEqual(sent_plaintext, received_plaintext)

        sent_plaintext = "message reply"

        # Alice sends reply
        omemo_message = alice_session_manager.encrypt(
            "bob", sent_plaintext, groupchat=False
        )
        assert omemo_message is not None

        # Reply must not be a pre key message
        self.assertFalse(omemo_message.keys[bob_device_id][1])

        # Bob receives reply
        received_plaintext, _, _ = bob_session_manager.decrypt_message(
            omemo_message, "alice"
        )
        self.assertEqual(sent_plaintext, received_plaintext)

        # Bob sends 10 messages
        messages: list[OMEMOMessage] = []
        for n in range(10):
            omemo_message = bob_session_manager.encrypt(
                "alice", f"message reply {n}", groupchat=False
            )
            assert omemo_message is not None
            messages.append(omemo_message)

        # Alice receives 10 messages
        for n, omemo_message in enumerate(messages):
            received_plaintext, _, _ = alice_session_manager.decrypt_message(
                omemo_message, "bob"
            )
            self.assertEqual(f"message reply {n}", received_plaintext)

        # Alice sends 10 messages
        messages: list[OMEMOMessage] = []
        for n in range(10):
            omemo_message = alice_session_manager.encrypt(
                "bob", f"message reply {n}", groupchat=False
            )
            assert omemo_message is not None
            messages.append(omemo_message)

        # Bob receives messages out of order
        for n, omemo_message in enumerate(reversed(messages)):
            received_plaintext, _, _ = bob_session_manager.decrypt_message(
                omemo_message, "alice"
            )
            self.assertEqual(f"message reply {9 - n}", received_plaintext)

        # Bob sends 10 messages
        messages: list[OMEMOMessage] = []
        for n in range(10):
            omemo_message = bob_session_manager.encrypt(
                "alice", f"message reply {n}", groupchat=False
            )
            assert omemo_message is not None
            messages.append(omemo_message)

        # Alice receives only the last message (9 messages before are lost)
        omemo_message = messages[-1]
        received_plaintext, _, _ = alice_session_manager.decrypt_message(
            omemo_message, "bob"
        )
        self.assertEqual("message reply 9", received_plaintext)

        # Alice receives a message a second time
        with self.assertRaises(DuplicateMessage):
            received_plaintext, _, _ = alice_session_manager.decrypt_message(
                omemo_message, "bob"
            )
