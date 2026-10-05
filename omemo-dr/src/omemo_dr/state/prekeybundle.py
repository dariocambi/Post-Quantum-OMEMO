from __future__ import annotations

from ..const import MAX_INT
from ..const import NS_OMEMO_2
from ..const import NS_OMEMO_TMP
from ..const import NS_PQOMEMO
from ..ecc.djbec import CurvePublicKey
from ..ecc.djbec import EdPublicKey
from ..exceptions import BundleValidationError
from ..exceptions import InvalidKeyException
from ..identitykey import IdentityKey
from ..pqkem.keys import KemPublicKey
from ..structs import OMEMOBundleProto


class PreKeyBundle:
    def __init__(
        self,
        remote_device_id: int,
        namespace: str,
        pre_key_id: int,
        ec_public_key_pre_key_public: CurvePublicKey,
        signed_pre_key_id: int,
        ec_public_key_signed_pre_key_public: CurvePublicKey,
        signed_pre_key_signature: bytes,
        identity_key: IdentityKey,
        pq_signed_pre_key_id: int,
        kem_public_key_pq_signed_pre_key_public: KemPublicKey | None,
        pq_signed_pre_key_signature: bytes,
    ) -> None:
        self._remote_device_id = remote_device_id
        self._namespace = namespace
        self._pre_key_id = pre_key_id
        self._pre_key_public = ec_public_key_pre_key_public
        self._signed_pre_key_id = signed_pre_key_id
        self._signed_pre_key_public = ec_public_key_signed_pre_key_public
        self._signed_pre_key_signature = signed_pre_key_signature
        self._identity_key = identity_key
        self._pq_signed_pre_key_id = pq_signed_pre_key_id
        self._pq_signed_pre_key_public = kem_public_key_pq_signed_pre_key_public
        self._pq_signed_pre_key_signature = pq_signed_pre_key_signature

    @classmethod
    def from_proto(cls, bundle: OMEMOBundleProto) -> PreKeyBundle:
        prekey = bundle.pick_prekey()
        otpk = CurvePublicKey.from_bytes(prekey["key"])
        spk = CurvePublicKey.from_bytes(bundle.spk["key"])

        ns = bundle.namespace
        if ns in (NS_OMEMO_TMP, NS_PQOMEMO):
            ik_pub = CurvePublicKey.from_bytes(bundle.ik)
        elif ns == NS_OMEMO_2:
            ik_pub = EdPublicKey.from_bytes(bundle.ik).to_curve()
        else:
            raise BundleValidationError("Unknown namespace on bundle: %s", ns)

        ik = IdentityKey(ik_pub)

        # --- Extract PQ signed prekey and signature if present, otherwise set to None --- #
        pqspk = getattr(bundle, "pqspk", None)
        pqspk_signature = getattr(bundle, "pqspk_signature", None)

        
        if not pqspk or not pqspk_signature:

            # Fail close if PQ signed prekey is missing for PQOMEMO namespace
            if ns == NS_PQOMEMO:
                raise BundleValidationError("Bundle is missing the PQ signed pre key")

            # Fail open for other namespaces, set PQ signed prekey and signature to None
            pq_spk, pq_spk_id, pqspk_signature = None, 0, b""

        else:

            # Generate KemPublicKey from bytes and validate length
            try:
                pq_spk = KemPublicKey.from_bytes(pqspk["key"])
            except InvalidKeyException as error:
                raise BundleValidationError(f"Malformed PQ signed pre key: {error}") from error

            # Validate PQ signed prekey id is within range
            pq_spk_id = pqspk["id"]
            if not 0 <= pq_spk_id <= MAX_INT:
                raise BundleValidationError("PQ signed pre key id out of range")
            

        if not 1 <= bundle.device_id <= MAX_INT:
            raise BundleValidationError("Device id out of range")

        if not 1 <= prekey["id"] <= MAX_INT:
            raise BundleValidationError("Prekey id out of range")

        if not 0 <= bundle.spk["id"] <= MAX_INT:
            # Allow 0 to stay backwards compatible
            raise BundleValidationError("Signed pre key id out of range")

        return cls(
            bundle.device_id,
            bundle.namespace,
            prekey["id"],
            otpk,
            bundle.spk["id"],
            spk,
            bundle.spk_signature,
            ik,
            pq_spk_id,          # PQ signed prekey id
            pq_spk,             # PQ signed prekey public key
            pqspk_signature,    # PQ signed prekey signature
        )

    def get_remote_device_id(self) -> int:
        return self._remote_device_id

    def get_namespace(self) -> str:
        return self._namespace

    def get_pre_key_id(self) -> int:
        return self._pre_key_id

    def get_pre_key(self) -> CurvePublicKey:
        return self._pre_key_public

    def get_signed_pre_key_id(self) -> int:
        return self._signed_pre_key_id

    def get_signed_pre_key(self) -> CurvePublicKey:
        return self._signed_pre_key_public

    def get_signed_pre_key_signature(self) -> bytes:
        return self._signed_pre_key_signature

    def get_identity_key(self) -> IdentityKey:
        return self._identity_key

    def get_pq_signed_pre_key_id(self) -> int:
        return self._pq_signed_pre_key_id

    def get_pq_signed_pre_key(self) -> KemPublicKey | None:
        return self._pq_signed_pre_key_public

    def get_pq_signed_pre_key_signature(self) -> bytes:
        return self._pq_signed_pre_key_signature

    def get_session_version(self) -> int:
        if self._namespace in (NS_OMEMO_TMP, NS_PQOMEMO):
            # NS_PQOMEMO stays on wire version 3: hybrid sessions are kept
            # apart from classical ones by the HKDF info string, not by a
            # new version number.
            return 3

        elif self._namespace == NS_OMEMO_2:
            return 4

        else:
            raise AssertionError("Unknown session version")
