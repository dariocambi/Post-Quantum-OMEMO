from enum import IntEnum

NS_OMEMO_TMP = "eu.siacs.conversations.axolotl"
NS_OMEMO_2 = "urn:xmpp:omemo:2"
NS_PQOMEMO = "urn:xmpp:pqomemo:0"

LEGACY_ENCODED_KEY_LENGTH = 33
ENCODED_KEY_LENGTH = 32
MAX_INT = 2**31 - 1

PQ_KEM_ALGORITHM              = "ML-KEM-1024"
PQ_KEM_PUBLIC_KEY_LENGTH      = 1568
PQ_KEM_PRIVATE_KEY_LENGTH     = 3168
PQ_KEM_CIPHERTEXT_LENGTH      = 1568
PQ_KEM_SHARED_SECRET_LENGTH   = 32

# Prefixed to the PQ prekey before signing, so that a signature over a PQ
# prekey can never be replayed as a signature over a classical one.
PQ_PREKEY_SIGNATURE_CONTEXT   = b"pqomemo:pq-prekey:v1"


class OMEMOTrust(IntEnum):
    UNTRUSTED = 0
    VERIFIED = 1
    UNDECIDED = 2
    BLIND = 3
