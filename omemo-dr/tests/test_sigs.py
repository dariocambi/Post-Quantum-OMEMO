import unittest

from omemo_dr.ecc.curve import Curve
from omemo_dr.ecc.djbec import CurvePublicKey
from omemo_dr.util.keyhelper import KeyHelper


class Curve25519Test(unittest.TestCase):
    def test_agreement(self):
        alice_public = bytes(
            [
                0x05,
                0x1B,
                0xB7,
                0x59,
                0x66,
                0xF2,
                0xE9,
                0x3A,
                0x36,
                0x91,
                0xDF,
                0xFF,
                0x94,
                0x2B,
                0xB2,
                0xA4,
                0x66,
                0xA1,
                0xC0,
                0x8B,
                0x8D,
                0x78,
                0xCA,
                0x3F,
                0x4D,
                0x6D,
                0xF8,
                0xB8,
                0xBF,
                0xA2,
                0xE4,
                0xEE,
                0x28,
            ]
        )
        alice_private = bytes(
            [
                0xC8,
                0x06,
                0x43,
                0x9D,
                0xC9,
                0xD2,
                0xC4,
                0x76,
                0xFF,
                0xED,
                0x8F,
                0x25,
                0x80,
                0xC0,
                0x88,
                0x8D,
                0x58,
                0xAB,
                0x40,
                0x6B,
                0xF7,
                0xAE,
                0x36,
                0x98,
                0x87,
                0x90,
                0x21,
                0xB9,
                0x6B,
                0xB4,
                0xBF,
                0x59,
            ]
        )

        bob_public = bytes(
            [
                0x05,
                0x65,
                0x36,
                0x14,
                0x99,
                0x3D,
                0x2B,
                0x15,
                0xEE,
                0x9E,
                0x5F,
                0xD3,
                0xD8,
                0x6C,
                0xE7,
                0x19,
                0xEF,
                0x4E,
                0xC1,
                0xDA,
                0xAE,
                0x18,
                0x86,
                0xA8,
                0x7B,
                0x3F,
                0x5F,
                0xA9,
                0x56,
                0x5A,
                0x27,
                0xA2,
                0x2F,
            ]
        )

        bob_private = bytes(
            [
                0xB0,
                0x3B,
                0x34,
                0xC3,
                0x3A,
                0x1C,
                0x44,
                0xF2,
                0x25,
                0xB6,
                0x62,
                0xD2,
                0xBF,
                0x48,
                0x59,
                0xB8,
                0x13,
                0x54,
                0x11,
                0xFA,
                0x7B,
                0x03,
                0x86,
                0xD4,
                0x5F,
                0xB7,
                0x5D,
                0xC5,
                0xB9,
                0x1B,
                0x44,
                0x66,
            ]
        )

        shared = bytes(
            [
                0x32,
                0x5F,
                0x23,
                0x93,
                0x28,
                0x94,
                0x1C,
                0xED,
                0x6E,
                0x67,
                0x3B,
                0x86,
                0xBA,
                0x41,
                0x01,
                0x74,
                0x48,
                0xE9,
                0x9B,
                0x64,
                0x9A,
                0x9C,
                0x38,
                0x06,
                0xC1,
                0xDD,
                0x7C,
                0xA4,
                0xC4,
                0x77,
                0xE6,
                0x29,
            ]
        )

        alice_public_key = Curve.decode_point(alice_public)
        assert isinstance(alice_public_key, CurvePublicKey)

        alice_private_key = Curve.decode_private_point(alice_private)

        bob_public_key = Curve.decode_point(bob_public)
        assert isinstance(bob_public_key, CurvePublicKey)

        bob_private_key = Curve.decode_private_point(bob_private)

        shared_one = Curve.calculate_agreement(alice_public_key, bob_private_key)
        shared_two = Curve.calculate_agreement(bob_public_key, alice_private_key)

        self.assertEqual(shared_one, shared)
        self.assertEqual(shared_two, shared)

    def test_random_agreements(self):
        for _i in range(0, 50):
            alice = Curve.generate_key_pair()
            bob = Curve.generate_key_pair()
            shared_alice = Curve.calculate_agreement(
                bob.get_public_key(), alice.get_private_key()
            )
            shared_bob = Curve.calculate_agreement(
                alice.get_public_key(), bob.get_private_key()
            )
            self.assertEqual(shared_alice, shared_bob)

    def test_gensig(self):
        identity_key_pair = KeyHelper.generate_identity_key_pair()
        KeyHelper.generate_signed_pre_key(identity_key_pair, 0)

    def test_signature(self):
        # aliceIdentityPrivate = bytes([0xc0, 0x97, 0x24, 0x84, 0x12, 0xe5, 0x8b, 0xf0, 0x5d, 0xf4, 0x87, 0x96,
        #                                   0x82, 0x05, 0x13, 0x27, 0x94, 0x17, 0x8e, 0x36, 0x76, 0x37, 0xf5, 0x81,
        #                                   0x8f, 0x81, 0xe0, 0xe6, 0xce, 0x73, 0xe8, 0x65])

        alice_identity_public = bytes(
            [
                0x05,
                0xAB,
                0x7E,
                0x71,
                0x7D,
                0x4A,
                0x16,
                0x3B,
                0x7D,
                0x9A,
                0x1D,
                0x80,
                0x71,
                0xDF,
                0xE9,
                0xDC,
                0xF8,
                0xCD,
                0xCD,
                0x1C,
                0xEA,
                0x33,
                0x39,
                0xB6,
                0x35,
                0x6B,
                0xE8,
                0x4D,
                0x88,
                0x7E,
                0x32,
                0x2C,
                0x64,
            ]
        )

        alice_ephemeral_public = bytes(
            [
                0x05,
                0xED,
                0xCE,
                0x9D,
                0x9C,
                0x41,
                0x5C,
                0xA7,
                0x8C,
                0xB7,
                0x25,
                0x2E,
                0x72,
                0xC2,
                0xC4,
                0xA5,
                0x54,
                0xD3,
                0xEB,
                0x29,
                0x48,
                0x5A,
                0x0E,
                0x1D,
                0x50,
                0x31,
                0x18,
                0xD1,
                0xA8,
                0x2D,
                0x99,
                0xFB,
                0x4A,
            ]
        )

        alice_signature = bytes(
            [
                0x5D,
                0xE8,
                0x8C,
                0xA9,
                0xA8,
                0x9B,
                0x4A,
                0x11,
                0x5D,
                0xA7,
                0x91,
                0x09,
                0xC6,
                0x7C,
                0x9C,
                0x74,
                0x64,
                0xA3,
                0xE4,
                0x18,
                0x02,
                0x74,
                0xF1,
                0xCB,
                0x8C,
                0x63,
                0xC2,
                0x98,
                0x4E,
                0x28,
                0x6D,
                0xFB,
                0xED,
                0xE8,
                0x2D,
                0xEB,
                0x9D,
                0xCD,
                0x9F,
                0xAE,
                0x0B,
                0xFB,
                0xB8,
                0x21,
                0x56,
                0x9B,
                0x3D,
                0x90,
                0x01,
                0xBD,
                0x81,
                0x30,
                0xCD,
                0x11,
                0xD4,
                0x86,
                0xCE,
                0xF0,
                0x47,
                0xBD,
                0x60,
                0xB8,
                0x6E,
                0x88,
            ]
        )

        # alice_private_key = Curve.decode_private_point(alice_identity_private)
        alice_public_key = Curve.decode_point(alice_identity_public)
        assert isinstance(alice_public_key, CurvePublicKey)

        alice_ephemeral = Curve.decode_point(alice_ephemeral_public)
        assert isinstance(alice_ephemeral, CurvePublicKey)

        res = Curve.verify_signature(
            alice_public_key, alice_ephemeral.serialize(), alice_signature
        )
        self.assertTrue(res)
