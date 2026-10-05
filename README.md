# Post-quantum OMEMO

Project SW6, Cryptography and Architectures for Computer Security, Politecnico di Milano. 
by Dario Cambi, Giorgio Ciraci.


## The problem

OMEMO (XEP-0384) is the end-to-end encryption used by XMPP clients. A session starts with X3DH, which is four Diffie-Hellman operations over 
Curve25519. After that the Double Ratchet takes over.

Shor's algorithm solves the discrete logarithm problem in polynomial time. So all four of those operations are broken, not just weakened.

The part that makes this urgent:

* an attacker can record traffic today and store it
* the traffic stays encrypted for now
* once a quantum computer exists, the attacker goes back and decrypts everything
* this is called harvest now, decrypt later

Signatures are different. A forged signature only helps an attacker who is there during the handshake. A machine built in fifteen years cannot go back
and impersonate anyone. That asymmetry is why we worked on the key agreement first.


## What we did

We added a fifth ingredient to the X3DH key derivation. It comes from ML-KEM-1024, through liboqs.

    before:  SK = HKDF( 0xFF*32 || DH1 || DH2 || DH3 || DH4 )
    after:   SK = HKDF( 0xFF*32 || DH1 || DH2 || DH3 || DH4 || SS_kem )

Nothing classical was removed. To get SK you now need the elliptic curve problem broken **and** the lattice problem broken. One is not enough. This is
the construction Signal published as PQXDH, so it is not our idea.

The code we touched is omemo-dr. That is the library Gajim uses for OMEMO: it declares it in its own pyproject.toml and imports it directly, so it is
a separate package only for packaging reasons. Upstream commit we started from: 9eae9e8d0a257eb5037619a893d14773f5efa142.


## Running it

    cd omemo-dr
    pip install -e .
    python -m unittest discover -s tests -t .

Two things to know:

* the -t . flag is needed, otherwise discovery breaks on the relative imports in test_session_manager.py
* liboqs must be installed on the system, because liboqs-python is a binding and not a self contained wheel

If you regenerate the protobuf files, pin protoc-wheel-0==21.11. The current protoc rewrites the whole generated file and injects a runtime check for
protobuf 7.35 or newer, which contradicts the protobuf>=4.21.0 the project declares. With the pinned version the existing files come back byte for
byte, so the diff only shows the fields we added.


## Design choices

**ML-KEM-1024.** It is the NIST standard (FIPS 203). It is IND-CCA. Its keys are small enough to publish in a bundle. PQXDH uses the same parameter
set. The code based alternatives that NIST also standardised, mainly HQC, have much bigger keys and ciphertexts. The bundle sits on a public node that
every contact downloads, so size is what decides here.

**The KEM has to be IND-CCA.** Bob's post-quantum prekey is published once and reused for many sessions. Anyone can encapsulate against it over and
over and watch whether the session works. That is a chosen ciphertext setting by construction. With an IND-CPA only KEM a reaction attack recovers the
private key.

**The prekey is signed.** ML-KEM uses implicit rejection (FIPS 203, section 6.3), so decapsulating a wrong ciphertext returns a pseudorandom value
instead of an error. The KEM cannot tell you that something was swapped. Without a signature a malicious server could:

* replace Bob's prekey with its own
* encapsulate to itself
* learn the post-quantum secret
* put everything back, with nobody noticing

The signature is the only thing that stops that. We sign with the existing XEdDSA identity key, so authentication stays classical. Deliberate, for the
reason in the first section.

**No downgrade.** Missing prekey in a bundle, or missing ciphertext in a message, both raise. There is no fallback path to slip into.


## Files we changed

Line numbers refer to the current state of the files.


### New: the KEM wrapper

**src/omemo_dr/pqkem/kem.py** (new, 97 lines)

Class KEM with three static methods: generate_key_pair, encapsulate, decapsulate. This is the only file in the codebase that imports oqs:

    grep -rn "import oqs" src/

We gave it the same shape as ecc/curve.py, the existing classical facade, so the rest of the code calls KEM.encapsulate the same way it calls
Curve.calculate_agreement.

At import time the module checks that liboqs is giving us what we think. It compares the four sizes, but it also compares the mechanism name (lines 33
to 36):

    reported_name = details['name']
    if reported_name != PQ_KEM_ALGORITHM:
        raise RuntimeError(...)

That is not redundant. Kyber1024 and ML-KEM-1024 report identical lengths, 1568/1568/32/3168, so a parameter block mixed up between the NIST draft and
the final standard passes every size check. It happened in libsignal and in monocles/pq-omemo-2. Only the name catches it.

decapsulate checks the ciphertext length and nothing else. Anything more would be pointless, see implicit rejection above.

**src/omemo_dr/pqkem/keys.py** (new, 63 lines)

KemPublicKey, KemPrivateKey, KemKeyPair, with their length checks. They do not inherit from anything in ecc/, but the structure mirrors what upstream
already does with CurvePublicKey and DjbECPrivateKey inside an ECKeyPair. Public and private are separate types because:

* the expected lengths differ, 1568 against 3168
* the public one can be built from bytes that arrived over the network, the private one cannot


### Constants and exceptions

**src/omemo_dr/const.py** (lines 5, 11 to 15, 19)

    NS_PQOMEMO = "urn:xmpp:pqomemo:0"

    PQ_KEM_ALGORITHM              = "ML-KEM-1024"
    PQ_KEM_PUBLIC_KEY_LENGTH      = 1568
    PQ_KEM_PRIVATE_KEY_LENGTH     = 3168
    PQ_KEM_CIPHERTEXT_LENGTH      = 1568
    PQ_KEM_SHARED_SECRET_LENGTH   = 32

    PQ_PREKEY_SIGNATURE_CONTEXT   = b"pqomemo:pq-prekey:v1"

The context string goes in front of the prekey before signing it, so a signature over a post-quantum prekey can never be replayed as a signature over
a classical one.

We did not touch ENCODED_KEY_LENGTH or LEGACY_ENCODED_KEY_LENGTH. Widening them to fit post-quantum sizes would weaken the check that stops random
data from being parsed as a curve point.

**src/omemo_dr/exceptions.py** (line 82)

New exception, HybridKeyAgreementError. It separates a protocol failure (master secret of the wrong length) from a key problem or from liboqs breaking
its own contract.

We used an exception and not an assert. Python strips asserts under -O, and that would delete exactly the guard that stops us from running classical
crypto while believing it is hybrid.


### Storage

**src/omemo_dr/protobuf/storage.proto** (lines 44 to 45, 87 onwards)

    // inside SessionStructure.PendingPreKey
    optional uint32 pqSignedPreKeyId = 4;
    optional bytes  kemCiphertext    = 5;

    message PqSignedPreKeyRecordStructure {
        optional uint32  id         = 1;
        optional bytes   publicKey  = 2;
        optional bytes   privateKey = 3;
        optional bytes   signature  = 4;
        optional fixed64 timestamp  = 5;
    }

A separate message, not an extension of SignedPreKeyRecordStructure, so the classical record stays byte identical. We never renumbered an existing
field. Renumbering silently corrupts sessions already on disk.

**src/omemo_dr/state/pqsignedprekeyrecord.py** (new, 59 lines)

The object that holds the post-quantum prekey and serialises itself. Modelled on state/signedprekeyrecord.py. One difference: get_key_pair rebuilds
the keys through KemPublicKey.from_bytes, not through Curve.decode_point, because that one enforces the 32 byte check and would reject an ML-KEM key.

**src/omemo_dr/state/store.py** (lines 130 to 152)

Five new abstract methods, mirroring the five that already exist for the classical signed prekey:

* load_pq_signed_pre_key
* store_pq_signed_pre_key
* get_current_pq_signed_pre_key_id
* get_pq_signed_pre_key_timestamp
* remove_old_pq_signed_pre_keys

Store is implemented outside this repository, in Gajim's SQLite backend. So every abstract method added here is a breaking change for the client, and
a full integration would need a schema migration there.

**src/omemo_dr/state/sessionstate.py** (lines 252 to 259, 305 to 327)

    self._session_structure.pendingPreKey.pqSignedPreKeyId = pq_signed_pre_key_id
    self._session_structure.pendingPreKey.kemCiphertext = kem_ciphertext

set_unacknowledged_pre_key_message takes the two extra parameters, UnacknowledgedPreKeyMessageItems gains two fields and their getters. This is what
makes the ciphertext replay below possible.

**tests/inmemorystore.py** (lines 92, 173 onwards)

Implements the five new Store methods on a pq_signed_prekeys table. Without it nothing can be instantiated, and every test dies with an abstract class
error that points at the wrong file.


### Key generation and bundle

**src/omemo_dr/util/keyhelper.py** (lines 7, 68 to 88)

New method generate_pq_signed_pre_key. It generates a KEM key pair, signs the serialised public key with the identity key, and wraps it in a
PqSignedPreKeyRecord. Line 74 is where the context prefix goes in:

    signature = Curve.calculate_signature(
        identity_key_pair.get_private_key(),
        PQ_PREKEY_SIGNATURE_CONTEXT + key_pair.get_public_key().serialize()
    )

**src/omemo_dr/structs.py** (lines 45 to 46, 60 to 61)

Two new fields on OMEMOBundleProto and OMEMOBundle:

    pqspk: PreKey           # Post-quantum signed pre-key
    pqspk_signature: bytes  # Signature of the post-quantum signed pre-key

We publish one rotated signed post-quantum prekey, and no one time post-quantum prekeys. The XEP asks for around 100 one time prekeys. With ML-KEM
that is roughly 118 kB on a public node every contact fetches, which is more than many XMPP servers accept. PQXDH made the same call in its first
version.

**src/omemo_dr/session_manager.py** (lines 15, 83 to 88, 149 to 156, 348, 415 to 426)

* line 15: imports NS_PQOMEMO
* lines 83 to 88: generate and store the post-quantum prekey during first run key generation
* lines 149 to 156: put it in the published bundle, with its signature
* line 348: the automatic republish notification now uses NS_PQOMEMO
* lines 415 to 426: rotation of the post-quantum prekey inside \_cycle_signed_pre_key

The rotation reuses spk_cycle_seconds and spk_archive_seconds instead of adding new config. That solves a problem for free. When Bob rotates there may
be a ciphertext still in flight, made against the previous key. The old key stays loadable until the archive window expires, so that handshake still
completes.

get_bundle still takes the namespace as a parameter, so both are supported. Only the automatic republish was switched over, because it has no caller
to ask.


### Wire format

**src/omemo_dr/protobuf/whisper.proto** (lines 22 to 23)

    optional uint32 pqSignedPreKeyId = 7;
    optional bytes  kemCiphertext    = 8;

A KEM is not symmetric like a Diffie-Hellman. Whoever encapsulates picks the secret and has to send a ciphertext, or the other side gets nothing.
Before this change there was nowhere to put those 1568 bytes.

**src/omemo_dr/protocol/whisper_pb2.py** (regenerated by protoc)

**src/omemo_dr/protocol/prekeywhispermessage.py** (lines 31 to 43, 55 to 69, 85 to 86, 111 to 118, plus the two getters)

The two fields go through the constructor, the new() builder and from_bytes. Lines 111 and 112 are the ones that matter:

    if not pre_key_whisper_message.kemCiphertext or not pre_key_whisper_message.pqSignedPreKeyId:
        raise InvalidMessageException("Missing KEM ciphertext or PQ signed prekey ID")

That is the no downgrade rule on the receiving side. A message without the ciphertext is refused, not accepted in some reduced mode.


### The handshake

**src/omemo_dr/ratchet/aliceparameters.py** and **src/omemo_dr/ratchet/bobparameters.py**

Two extra fields each, plus getters:

* AliceParameters carries the peer's post-quantum prekey and its id
* BobParameters carries our own key pair and the ciphertext we received

They are plain data holders and we kept them that way. The checks live upstream in sessionbuilder, where a readable error can be raised.

**src/omemo_dr/ratchet/ratchetingsession.py** (lines 8, 21, 68 to 81, 138 to 152, 163 to 167)

This is the core, and the change is small. Line 21:

    HYBRID_MASTER_SECRET_LENGTH = 32 + 4 * 32 + PQ_KEM_SHARED_SECRET_LENGTH   # 192

Initiator side, lines 68 to 77:

    # --- The KEM encapsulation step. This is the post-quantum part of the hybrid key agreement. ---
    kem_ciphertext, kem_shared_secret = KEM.encapsulate(
        parameters.get_their_pq_signed_pre_key()
    )
    secrets.extend(kem_shared_secret)

    if len(secrets) != HYBRID_MASTER_SECRET_LENGTH:
        raise HybridKeyAgreementError(...)

    log.info(f"Hybrid X3DH: classical=128B kem={len(kem_shared_secret)}B total={len(secrets)}B")

Responder side, lines 138 to 143, mirrored:

    kem_shared_secret = KEM.decapsulate(
        parameters.get_our_pq_signed_pre_key().get_private_key(),
        parameters.get_kem_ciphertext(),
    )
    secrets.extend(kem_shared_secret)

The position is the thing to get right. Both sides build one bytearray and run HKDF over it, so the layout has to match byte for byte:

    [0xFF x 32] || DH1 || DH2 || DH3 || DH4 || SS_kem

If one side appended the KEM secret somewhere else, the two would derive different keys. Every message would then fail to decrypt, and nothing in the
error would say why. So it is the last extend on both sides, with nothing in between.

The length check catches the other failure mode. 160 bytes means the KEM gave us nothing.

Lines 166 to 167 change the HKDF info string when the hybrid flag is set:

    if hybrid:
        domain_separator = "PQOMEMO Hybrid Payload v1"

Domain separation: a hybrid session and a classical one should never derive the same keys from inputs that overlap.

Untouched in this file: the four Curve.calculate_agreement calls, the discontinuity bytes, the HKDF parameters, the 64 byte split.


### Wiring

**src/omemo_dr/sessionbuilder.py** (lines 7, 74 to 86, 122 to 132, 153 to 165)

On the initiator side there are now two signature checks, both mandatory. The classical one was already there at line 120. Ours is lines 122 to 131:

    their_pq_signed_pre_key = bundle.get_pq_signed_pre_key()
    if their_pq_signed_pre_key is None:
        raise InvalidKeyException("Bundle carries no PQ device key!")

    if not Curve.verify_signature(
        bundle.get_identity_key().get_public_key(),
        PQ_PREKEY_SIGNATURE_CONTEXT + their_pq_signed_pre_key.serialize(),
        bundle.get_pq_signed_pre_key_signature(),
    ):
        raise InvalidKeyException("Invalid signature on PQ device key!")

The None check is there so a classical bundle fails with a readable message instead of a TypeError inside the KEM code.

Lines 153 to 165 capture the ciphertext returned by initialize_session_as_alice and pass it, with the prekey id, to
set_unacknowledged_pre_key_message.

On the responder side, lines 74 to 80 load the post-quantum prekey named by the incoming message and hand it to BobParameters. If it is gone, it
raises.

**src/omemo_dr/sessioncipher.py** (lines 74 to 75)

Two lines, and the least obvious change in the whole project:

    items.get_pq_signed_pre_key_id(),   # PQ signed prekey id
    items.get_kem_ciphertext(),         # KEM ciphertext

OMEMO reattaches the key exchange to every message until the peer replies, so sessioncipher rebuilds the PreKeyWhisperMessage on every send. If we
re-encapsulated each time, then:

* every message would carry a different shared secret
* the peer would derive keys matching nothing
* every message after the first would fail to decrypt
* the error would look like a ratchet bug, in a completely different file

So the ciphertext is stored once and replayed as it is. That is why storage.proto got those two extra fields on the pending prekey.

This is a consequence of the protocol, not of the KEM. A standalone prototype never hits it, because a prototype does not retransmit.


### Bundle parsing

**src/omemo_dr/state/prekeybundle.py** (lines 6, 9, 27 to 41, 50, 56 to 90, 103 onwards)

The constructor takes the three new values, there are getters for them, and from_proto parses the prekey with KemPublicKey.from_bytes. Lines 64 to 71
are the no downgrade rule on this side:

    if not pqspk or not pqspk_signature:
        # Fail close if PQ signed prekey is missing for PQOMEMO namespace
        if ns == NS_PQOMEMO:
            raise BundleValidationError("Bundle is missing the PQ signed pre key")

        # Fail open for other namespaces
        pq_spk, pq_spk_id, pqspk_signature = None, 0, b""

A silent fallback would let an attacker just delete that element from the bundle.

get_session_version returns 3 for NS_PQOMEMO too. We kept wire version 3 on purpose. Gajim only implements the legacy namespace anyway, and hybrid
sessions are kept apart from classical ones by the HKDF info string, not by a version byte.


## Tests

**tests/test_pq_session.py** (new, 13 tests in 6 classes)

    KemTest
      test_round_trip
      test_ciphertext_of_wrong_length_is_rejected
      test_foreign_ciphertext_decapsulates_to_a_pseudorandom_secret

    HybridMasterSecretTest
      test_both_sides_derive_the_same_keys
      test_hybrid_label_changes_the_derived_keys
      test_master_secret_of_classical_length_is_refused

    SessionTest
      test_messages_in_both_directions
      test_kem_ciphertext_is_replayed_until_bob_answers

    BundleAttackTest
      test_swapped_pq_prekey_under_the_real_identity_is_rejected
      test_swapped_identity_key_makes_the_session_diverge

    WireFormatTest
      test_round_trip_preserves_the_ciphertext
      test_prekey_message_without_ciphertext_is_rejected

    PqSignedPreKeyRecordTest
      test_serialisation_round_trip

Some notes on the ones that are not obvious.

**record_derivations** is a context manager that patches RatchetingSession.calculate_derived_keys and collects the (master_secret, hybrid) pair each
side feeds it. That is how we check that both sides really reached the same 192 bytes, instead of only checking that decryption worked.

**test_master_secret_of_classical_length_is_refused** swaps in a StrippedKEM that returns an empty shared secret, so the master secret comes out at
160 bytes. The guard has to raise. This is the test for the anti-downgrade check.

**test_kem_ciphertext_is_replayed_until_bob_answers** sends three messages before Bob replies, parses all three, and asserts that the set of
ciphertexts has size one. Then it decrypts all three in order.

**test_swapped_pq_prekey_under_the_real_identity_is_rejected** is the PQXDH 4.5 attack. The attacker replaces the prekey and its signature, but leaves
Bob's real identity key in place. The test also patches KEM.encapsulate and asserts it was never called, so we know the abort happened before any KEM
work.

**test_swapped_identity_key_makes_the_session_diverge** goes further: the attacker swaps the identity key too, and re-signs both prekeys under it. Now
every signature verifies and the handshake goes through. But DH1 and DH2 run against the attacker's identity, so the two sides end up with different
secrets and decryption fails. A silent compromise becomes a visible one.

That last test needed fixing compared to our standalone prototype. Ported as it was, it aborted too early, because omemo-dr also verifies the
classical prekey signature and the prototype did not model that. We had to re-sign both prekeys to reproduce the attack. So the real implementation
turned out stricter than our own model.


**pyproject.toml** (line 24)

    "liboqs-python>=0.16.0",

Small line, real consequence. A post-quantum OMEMO needs a native library that the classical one did not. Worth saying that liboqs describes itself as
software for prototyping and experimenting, with an explicit note about limitations of intended use.


## What we did not change

* **The Double Ratchet** (ratchet/rootkey.py, ratchet/chainkey.py). Break-in recovery is still classical. A KEM based ratchet step would carry a fresh
  public key and a ciphertext on every advance, about 3 kB against the 32 bytes it costs now. Signal shipped one (SPQR), two years after PQXDH, and it
  needed chunking with erasure codes to be practical. Out of scope, but we wanted to say why.
* **The symmetric layer.** SHA-256, HMAC-SHA-256 and AES-256 lose half their margin to Grover, which leaves 128 bits. Fine as it is.
* **ecc/ and the C extension.** Untouched. That is the point of a hybrid design.
* **The OMEMO 2 code path** (protocol/omemo_message.py, protocol/omemo_keyexchange.py, protobuf/omemo.proto). Gajim only declares the legacy
  namespace, and the string urn:xmpp:omemo:2 appears nowhere in the client. That half of the library is dead code in a real deployment, so patching it
  would have produced code that never runs.
* **The legacy payload cipher.** aes.py still uses AES-128 on the legacy path, and Grover takes that to about 64 bits. We found it while auditing and
  we are reporting it, but it is not a quantum problem and it was not our target. The fix is two characters plus one trap: aes_decrypt tells formats
  apart by testing len(key) >= 32, and a 32 byte key silently breaks that branch.


## Known gaps

* **No type byte on encoded KEM keys.** PQXDH recommends one, so that no encoding can be mistaken for another, and Cryspen's formal analysis found a
  key confusion attack it defends against. We rely on lengths instead, 32 or 33 bytes for Curve25519 against 1568 for ML-KEM, with separate parsers
  that reject anything else. It works. But it is an invariant of the current parameters, not a property of the encoding, and a KEM with a 32 byte key
  would remove the separation without anyone noticing.
* **Fingerprints are unchanged**, because the identity key is unchanged. A post-quantum identity would need the fingerprint to become a hash over all
  components. Otherwise with an ML-DSA key it turns into a few thousand characters and the verification UI stops being usable.
* **No interoperability** with unmodified OMEMO clients. Both the bundle format and the key exchange changed, so it is lost anyway, and advertising
  the classical namespace would have been a lie.
