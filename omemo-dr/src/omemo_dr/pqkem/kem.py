"""Post-quantum KEM facade, backed by liboqs.

Algorithm: ML-KEM-1024 (FIPS 203, formerly CRYSTALS-Kyber). ML-KEM is an
IND-CCA-secure key encapsulation mechanism obtained from an IND-CPA lattice
scheme via the Fujisaki-Okamoto transform. IND-CCA security is required here
because the encapsulation public key (the PQ signed prekey) is long-lived and
reused across many sessions, so an active adversary can submit arbitrary
ciphertexts against it; an IND-CPA-only scheme would be vulnerable to a
reaction attack recovering the private key over repeated queries.

This is the only module in the codebase that imports `oqs`. Every other
module reaches post-quantum key agreement through this facade, mirroring the
shape of the classical `Curve` facade in `ecc/curve.py`.
"""

from __future__ import annotations

import oqs

from .keys import KemKeyPair, KemPrivateKey, KemPublicKey
from ..exceptions import InvalidKeyException
from ..const import PQ_KEM_ALGORITHM, PQ_KEM_CIPHERTEXT_LENGTH, PQ_KEM_PRIVATE_KEY_LENGTH, PQ_KEM_PUBLIC_KEY_LENGTH, PQ_KEM_SHARED_SECRET_LENGTH



def _check_liboqs_matches_const() -> None:
    
    with oqs.KeyEncapsulation(PQ_KEM_ALGORITHM) as kem:
        details = kem.details

    # Lengths alone cannot identify the mechanism: Kyber1024 and ML-KEM-1024
    # agree on all four (1568/1568/32/3168), so a parameter block mixed up
    # between the NIST draft and the FIPS 203 standard passes every
    # length assertion. Only the reported name separates them.
    reported_name = details['name']
    if reported_name != PQ_KEM_ALGORITHM:
        raise RuntimeError(f'liboqs instantiated {PQ_KEM_ALGORITHM!r} but reports {reported_name!r} (version {details["version"]!r}); refusing to run on a mechanism other than the one const.py declares')

    expected = {
        'length_public_key': PQ_KEM_PUBLIC_KEY_LENGTH,
        'length_secret_key': PQ_KEM_PRIVATE_KEY_LENGTH,
        'length_ciphertext': PQ_KEM_CIPHERTEXT_LENGTH,
        'length_shared_secret': PQ_KEM_SHARED_SECRET_LENGTH,
    }
    for key, const_value in expected.items():
        actual_value = details[key]
        if actual_value != const_value:
            raise RuntimeError(f'liboqs {PQ_KEM_ALGORITHM} reports {key}={actual_value}, but const.py declares {const_value}; the two must be kept in sync')



_check_liboqs_matches_const()


class KEM:

    @staticmethod
    def generate_key_pair() -> KemKeyPair:

        with oqs.KeyEncapsulation(PQ_KEM_ALGORITHM) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()

        if len(public_key) != PQ_KEM_PUBLIC_KEY_LENGTH:
            raise RuntimeError(f'liboqs returned a {len(public_key)} byte public key, expected {PQ_KEM_PUBLIC_KEY_LENGTH}')

        return KemKeyPair(KemPublicKey(public_key), KemPrivateKey(private_key))


    @staticmethod
    def encapsulate(public_key: KemPublicKey) -> tuple[bytes, bytes]:

        with oqs.KeyEncapsulation(PQ_KEM_ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key.serialize())

        if len(ciphertext) != PQ_KEM_CIPHERTEXT_LENGTH:
            raise RuntimeError(f'liboqs returned a {len(ciphertext)} byte ciphertext, expected {PQ_KEM_CIPHERTEXT_LENGTH}')

        if len(shared_secret) != PQ_KEM_SHARED_SECRET_LENGTH:
            raise RuntimeError(f'liboqs returned a {len(shared_secret)} byte shared secret, expected {PQ_KEM_SHARED_SECRET_LENGTH}')

        return ciphertext, shared_secret


    @staticmethod
    def decapsulate(private_key: KemPrivateKey, ciphertext: bytes) -> bytes:

        if len(ciphertext) != PQ_KEM_CIPHERTEXT_LENGTH:
            raise InvalidKeyException(f'Unknown KEM ciphertext length: {len(ciphertext)}')

        with oqs.KeyEncapsulation(PQ_KEM_ALGORITHM, private_key.serialize()) as kem:
            shared_secret = kem.decap_secret(ciphertext)

        if len(shared_secret) != PQ_KEM_SHARED_SECRET_LENGTH:
            raise RuntimeError(f'liboqs returned a {len(shared_secret)} byte shared secret, expected {PQ_KEM_SHARED_SECRET_LENGTH}')

        return shared_secret
