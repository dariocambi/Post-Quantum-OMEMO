"""tests for the hybrid handshake: kem facade, master secret, downgrade guard, bundle attacks, wire format."""

import copy
import os
import time
import unittest
from contextlib import contextmanager
from unittest import mock

from omemo_dr.const import NS_PQOMEMO, PQ_PREKEY_SIGNATURE_CONTEXT, PQ_KEM_CIPHERTEXT_LENGTH, PQ_KEM_PUBLIC_KEY_LENGTH, PQ_KEM_SHARED_SECRET_LENGTH
from omemo_dr.ecc.curve import Curve
from omemo_dr.exceptions import DecryptionFailed, HybridKeyAgreementError, InvalidKeyException, InvalidMessageException
from omemo_dr.identitykey import IdentityKey
from omemo_dr.pqkem.kem import KEM
from omemo_dr.pqkem.keys import KemPrivateKey, KemPublicKey
from omemo_dr.protocol import whisper_pb2
from omemo_dr.protocol.prekeywhispermessage import PreKeyWhisperMessage
from omemo_dr.protocol.whispermessage import WhisperMessage
from omemo_dr.ratchet import ratchetingsession
from omemo_dr.ratchet.ratchetingsession import HYBRID_MASTER_SECRET_LENGTH, RatchetingSession
from omemo_dr.session_manager import OMEMOSessionManager
from omemo_dr.state.pqsignedprekeyrecord import PqSignedPreKeyRecord
from omemo_dr.structs import OMEMOConfig, OMEMOMessage
from omemo_dr.util.byteutil import ByteUtil

from .inmemorystore import InMemoryStore

# 32 discontinuity bytes + 4 dh agreements, i.e. what plain x3dh would give us
CLASSICAL_MASTER_SECRET_LENGTH = 160



# ----------[ helpers ]---------- #

def make_managers() -> tuple[OMEMOSessionManager, OMEMOSessionManager]:
    '''makes two session managers with in-memory stores and a config that doesn't expire the signed prekey too quickly'''
    config = OMEMOConfig(default_prekey_amount=100, min_prekey_amount=80, spk_archive_seconds=86400 * 15, spk_cycle_seconds=86400, unacknowledged_count=2000)
    return OMEMOSessionManager("alice", InMemoryStore(), config), OMEMOSessionManager("bob", InMemoryStore(), config)


def build_session(alice: OMEMOSessionManager, bob: OMEMOSessionManager):
    '''alice fetches bob's bundle and runs the handshake against it'''
    bundle = bob.get_bundle(NS_PQOMEMO)
    alice.update_devicelist("bob", [bundle.device_id])
    alice.build_session("bob", bundle)
    return bundle


def encrypt(sender: OMEMOSessionManager, to: str, plaintext: str) -> OMEMOMessage:
    '''1:1 encrypt without the Optional: None here would mean the session was never built'''
    message = sender.encrypt(to, plaintext, groupchat=False)
    assert message is not None
    return message


@contextmanager
def record_derivations():
    '''spies on the kdf: gives us the (master_secret, hybrid) pair each side feeds it'''
    original = RatchetingSession.calculate_derived_keys
    calls: list[tuple[bytes, bool]] = []

    def spy(session_version: int, master_secret: bytes, *, hybrid: bool = False) -> RatchetingSession.DerivedKeys:
        calls.append((master_secret, hybrid))
        return original(session_version, master_secret, hybrid=hybrid)

    with mock.patch.object(RatchetingSession, "calculate_derived_keys", staticmethod(spy)):
        yield calls


# -------------------- TESTS -------------------- #

class KemTest(unittest.TestCase):
    '''
    tests for the kem facade: key pair generation, encapsulation, decapsulation, and lengths
    '''

    def test_round_trip(self):
        '''
        a key pair can encapsulate and decapsulate a secret, and the lengths match the constants
        '''
        key_pair = KEM.generate_key_pair()
        ciphertext, shared_secret = KEM.encapsulate(key_pair.get_public_key())

        self.assertEqual(len(key_pair.get_public_key().serialize()), PQ_KEM_PUBLIC_KEY_LENGTH)
        self.assertEqual(len(ciphertext), PQ_KEM_CIPHERTEXT_LENGTH)
        self.assertEqual(len(shared_secret), PQ_KEM_SHARED_SECRET_LENGTH)
        self.assertEqual(KEM.decapsulate(key_pair.get_private_key(), ciphertext), shared_secret)

    def test_ciphertext_of_wrong_length_is_rejected(self):
        '''
        a ciphertext that is too short or too long cannot be decapsulated, and raises an exception
        '''
        key_pair = KEM.generate_key_pair()

        with self.assertRaises(InvalidKeyException):
            KEM.decapsulate(key_pair.get_private_key(), os.urandom(100))


    def test_foreign_ciphertext_decapsulates_to_a_pseudorandom_secret(self):
        '''
        a ciphertext that was not produced by the key pair decapsulates to a pseudorandom secret
        '''
        # fips 203 6.3, implicit rejection: a ciphertext meant for someone else yields a pseudorandom secret instead of an error, so a forgery surfaces later as a mac failure
        key_pair = KEM.generate_key_pair()
        ciphertext, _ = KEM.encapsulate(KEM.generate_key_pair().get_public_key())

        recovered = KEM.decapsulate(key_pair.get_private_key(), ciphertext)
        self.assertEqual(len(recovered), PQ_KEM_SHARED_SECRET_LENGTH)


class HybridMasterSecretTest(unittest.TestCase):
    '''
    tests for the hybrid handshake: the master secret, the kdf, and the anti-downgrade guard
    '''

    def test_both_sides_derive_the_same_keys(self):
        '''
        the hybrid handshake produces a master secret that is fed to the kdf on both sides, and
        the derived keys match. the spy gives us the master secret and hybrid flag each side used
        '''
        alice, bob = make_managers()

        with record_derivations() as calls:
            build_session(alice, bob)
            bob.decrypt_message(encrypt(alice, "bob", "hello"), "alice")

        (alice_secret, alice_hybrid), (bob_secret, bob_hybrid) = calls  # one derivation per side
        self.assertTrue(alice_hybrid and bob_hybrid)
        self.assertEqual(alice_secret, bob_secret)

        # the master secret is the classical x3dh secret plus the kem shared secret, discontinuity bytes still up front
        self.assertEqual(HYBRID_MASTER_SECRET_LENGTH, 192)  # 32 + 4*32 + 32
        self.assertEqual(HYBRID_MASTER_SECRET_LENGTH, CLASSICAL_MASTER_SECRET_LENGTH + PQ_KEM_SHARED_SECRET_LENGTH)
        self.assertEqual(len(alice_secret), HYBRID_MASTER_SECRET_LENGTH)
        self.assertEqual(alice_secret[:32], b"\xff" * 32)

        # outside the spy, so this is the real kdf
        alice_keys = RatchetingSession.calculate_derived_keys(3, alice_secret, hybrid=True)
        bob_keys = RatchetingSession.calculate_derived_keys(3, bob_secret, hybrid=True)

        self.assertEqual(alice_keys.get_root_key().get_key_bytes(), bob_keys.get_root_key().get_key_bytes())
        self.assertEqual(alice_keys.get_chain_key().get_key(), bob_keys.get_chain_key().get_key())


    def test_hybrid_label_changes_the_derived_keys(self):
        '''
        same ikm, different hkdf info: keeps hybrid and classical sessions from colliding
        '''
        master_secret = os.urandom(HYBRID_MASTER_SECRET_LENGTH)

        hybrid = RatchetingSession.calculate_derived_keys(3, master_secret, hybrid=True)
        classical = RatchetingSession.calculate_derived_keys(3, master_secret)

        self.assertNotEqual(hybrid.get_root_key().get_key_bytes(), classical.get_root_key().get_key_bytes())


    def test_master_secret_of_classical_length_is_refused(self):
        '''
        the anti-downgrade guard checks the length of the master secrrt and refuses to start a
        session if it is the same length as classical x3dh, which would mean the kem contributed
        nothing
        '''
        alice, bob = make_managers()

        class StrippedKEM:
            @staticmethod
            def encapsulate(public_key: KemPublicKey) -> tuple[bytes, bytes]:
                ciphertext, _ = KEM.encapsulate(public_key)
                return ciphertext, b""

            @staticmethod
            def decapsulate(private_key: KemPrivateKey, ciphertext: bytes) -> bytes:
                return b""

        with mock.patch.object(ratchetingsession, "KEM", StrippedKEM), self.assertRaises(HybridKeyAgreementError) as ctx:
            build_session(alice, bob)

        self.assertIn(str(CLASSICAL_MASTER_SECRET_LENGTH), str(ctx.exception))
        self.assertIn(str(HYBRID_MASTER_SECRET_LENGTH), str(ctx.exception))


class SessionTest(unittest.TestCase):
    '''
    tests for the hybrid handshake and the resulting session
    '''

    def test_messages_in_both_directions(self):
        '''
        a session can be built and messages can be sent in both directions
        '''
        alice, bob = make_managers()
        build_session(alice, bob)

        received, _, _ = bob.decrypt_message(encrypt(alice, "bob", "from alice"), "alice")
        self.assertEqual(received, "from alice")

        received, _, _ = alice.decrypt_message(encrypt(bob, "alice", "from bob"), "bob")
        self.assertEqual(received, "from bob")


    def test_kem_ciphertext_is_replayed_until_bob_answers(self):
        '''
        the kem ciphertext is replayed in every prekey message until bob answers, so that the handshake can complete even if the first prekey 
        message is lost. the ciphertext must be the same in all messages, because re-encapsulating would give a fresh secret each time
        '''
        alice, bob = make_managers()
        bundle = build_session(alice, bob)

        messages = [encrypt(alice, "bob", f"message {n}") for n in range(3)]
        self.assertTrue(all(message.keys[bundle.device_id][1] for message in messages))  # all prekey messages

        parsed = [PreKeyWhisperMessage.from_bytes(message.keys[bundle.device_id][0]) for message in messages]
        self.assertEqual(len({message.get_kem_ciphertext() for message in parsed}), 1)

        for n, message in enumerate(messages):
            received, _, _ = bob.decrypt_message(message, "alice")
            self.assertEqual(received, f"message {n}")


class BundleAttackTest(unittest.TestCase):
    '''
    tests for attacks on the bundle, where the attacker can swap keys and signatures
    '''

    def test_swapped_pq_prekey_under_the_real_identity_is_rejected(self):
        '''
        pqxdh 4.5 weak forward secrecy attack: the server swaps only the pq prekey and its signature, leaving bob's real identity key in place, so it can
        encapsulate to itself and strip the pq contribution. no signature under the genuine identity key, so we must abort
        '''
        alice, bob = make_managers()
        bundle = bob.get_bundle(NS_PQOMEMO)
        alice.update_devicelist("bob", [bundle.device_id])

        attacker_kem = KEM.generate_key_pair()
        attacker_identity = Curve.generate_key_pair()
        attacker_pq_key = attacker_kem.get_public_key().serialize()

        forged = copy.deepcopy(bundle)
        forged.pqspk = {"key": attacker_pq_key, "id": bundle.pqspk["id"]}
        forged.pqspk_signature = Curve.calculate_signature(attacker_identity.get_private_key(), attacker_pq_key)

        with mock.patch.object(KEM, "encapsulate") as encapsulate, self.assertRaises(InvalidKeyException):
            alice.build_session("bob", forged)

        encapsulate.assert_not_called()


    def test_swapped_identity_key_makes_the_session_diverge(self):
        '''
        swapping the identity key too forces the attacker to re-sign both prekeys under it, and since each signature is verified against the presented
        identity key the handshake now goes through. but dh1 and dh2 run against the attacker's identity instead of bob's, so the twosides derive 
        different secrets: a silent compromise turns into a visible failure.
        '''
        alice, bob = make_managers()
        bundle = bob.get_bundle(NS_PQOMEMO)
        alice.update_devicelist("bob", [bundle.device_id])

        attacker_kem = KEM.generate_key_pair()
        attacker_identity = Curve.generate_key_pair()
        attacker_pq_key = attacker_kem.get_public_key().serialize()

        forged = copy.deepcopy(bundle)
        forged.ik = attacker_identity.get_public_key().serialize()
        forged.spk_signature = Curve.calculate_signature(attacker_identity.get_private_key(), bundle.spk["key"])
        forged.pqspk = {"key": attacker_pq_key, "id": bundle.pqspk["id"]}
        forged.pqspk_signature = Curve.calculate_signature(attacker_identity.get_private_key(), PQ_PREKEY_SIGNATURE_CONTEXT + attacker_pq_key)

        with record_derivations() as calls:
            alice.build_session("bob", forged)
            with self.assertRaises(DecryptionFailed):
                bob.decrypt_message(encrypt(alice, "bob", "intercepted"), "alice")

        (alice_secret, _), (bob_secret, _) = calls
        self.assertNotEqual(alice_secret, bob_secret)


class WireFormatTest(unittest.TestCase):
    '''
    Tests for the wire format of prekey messages.
    '''

    def _make_prekey_message(self, kem_ciphertext: bytes) -> PreKeyWhisperMessage:
        '''
        helper function that makes a prekey message with a random base key and identity key, and the given kem ciphertext
        '''
        identity_key = IdentityKey(Curve.generate_key_pair().get_public_key())
        base_key = Curve.generate_key_pair().get_public_key()
        whisper_message = WhisperMessage.new(3, os.urandom(32), base_key, 1, 0, b"body", identity_key, identity_key)

        return PreKeyWhisperMessage.new(3, 111, 22, 33, base_key, identity_key, whisper_message, 44, kem_ciphertext)


    def test_round_trip_preserves_the_ciphertext(self):
        '''
        the kem ciphertext is preserved through the prekey message wire format, and the signed prekey id is preserved too
        '''
        ciphertext, _ = KEM.encapsulate(KEM.generate_key_pair().get_public_key())

        parsed = PreKeyWhisperMessage.from_bytes(self._make_prekey_message(ciphertext).serialize())

        self.assertEqual(parsed.get_kem_ciphertext(), ciphertext)
        self.assertEqual(parsed.get_pq_signed_pre_key_id(), 44)


    def test_prekey_message_without_ciphertext_is_rejected(self):
        '''
        a prekey message that has no kem ciphertext is rejected, because it would mean the kem contributed nothing
        '''
        ciphertext, _ = KEM.encapsulate(KEM.generate_key_pair().get_public_key())
        serialized = self._make_prekey_message(ciphertext).serialize()

        inner = whisper_pb2.PreKeyWhisperMessage()  # pyright: ignore
        inner.ParseFromString(serialized[1:])
        inner.ClearField("kemCiphertext")
        stripped = ByteUtil.combine(ByteUtil.ints_to_byte_high_and_low(3, 3), inner.SerializeToString())

        # fail closed: dropping the kem field must not quietly leave us with classical x3dh
        with self.assertRaises(InvalidMessageException):
            PreKeyWhisperMessage.from_bytes(stripped)


class PqSignedPreKeyRecordTest(unittest.TestCase):
    '''
    Tests for the wire format of signed prekey records.
    '''

    def test_serialisation_round_trip(self):
        '''
        a signed prekey record can be serialised and deserialised, and the fields match
        '''
        key_pair = KEM.generate_key_pair()
        signature, timestamp = os.urandom(64), int(time.time() * 1000)

        record = PqSignedPreKeyRecord.new(42, timestamp, key_pair, signature)
        restored = PqSignedPreKeyRecord.from_bytes(record.serialize())

        self.assertEqual(restored.serialize(), record.serialize())
        self.assertEqual(restored.get_id(), 42)
        self.assertEqual(restored.get_timestamp(), timestamp)
        self.assertEqual(restored.get_signature(), signature)
        self.assertEqual(restored.get_key_pair().get_public_key(), key_pair.get_public_key())
        self.assertEqual(restored.get_key_pair().get_private_key(), key_pair.get_private_key())




if __name__ == '__main__':
    unittest.main()
