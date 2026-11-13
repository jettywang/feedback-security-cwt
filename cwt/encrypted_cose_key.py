from typing import Any

import cbor2
from cbor2 import CBORTag

from .cbor_processor import CBORProcessor
from .const import COSE_KEY_OPERATION_VALUES, COSE_NAMED_ALGORITHMS_SUPPORTED
from .cose import COSE
from .cose_key import COSEKey
from .cose_key_interface import COSEKeyInterface
from .enums import COSEKeyOps
from .exceptions import VerifyError


class EncryptedCOSEKey(CBORProcessor):
    """
    An encrypted COSE key.

    Every COSE_Encrypt0 envelope produced by this class is authenticated and
    bound to an *authenticated context* (the protocol purpose and the recipient
    context of the business link where the envelope is exchanged). The context
    is supplied as the external AAD of the underlying AEAD, so an envelope that
    is moved onto another business link, or presented to a different protocol
    purpose, fails authentication instead of decrypting successfully.

    Envelopes produced before this binding existed have no authenticated
    context. They can only be opened by opting into the legacy behavior
    explicitly through ``legacy=True``; decryption of a context-bound envelope
    never falls back to the legacy behavior automatically.
    """

    # A fixed domain separator that identifies the protocol use of the AAD.
    # It keeps the external AAD of an EncryptedCOSEKey distinct from any other
    # COSE message that happens to be encrypted with the same key.
    _CONTEXT_DOMAIN = "EncryptedCOSEKey/1"

    @staticmethod
    def build_context(purpose: str | bytes, recipient_context: str | bytes = b"") -> bytes:
        """
        Builds an authenticated context to bind an encrypted COSE key to a
        specific protocol purpose and recipient context.

        The returned value is the external AAD authenticated by the AEAD of the
        COSE_Encrypt0 envelope. Both the sender (``from_cose_key``) and the
        recipient (``to_cose_key``) must build the context from the same
        ``purpose`` and ``recipient_context``; any difference makes the AEAD
        verification fail.

        Args:
            purpose (str | bytes): A protocol purpose identifier of the business
                link where the encrypted key is exchanged (e.g. ``"cnf/eck"``).
            recipient_context (str | bytes): A recipient context that scopes the
                encrypted key to a specific recipient, link or session
                (e.g. a recipient identifier). It is optional but recommended.
        Returns:
            bytes: A CBOR-encoded authenticated context to be passed to
                ``from_cose_key()`` and ``to_cose_key()``.
        Raises:
            ValueError: Invalid arguments.
        """
        if isinstance(purpose, str):
            purpose = purpose.encode("utf-8")
        if not isinstance(purpose, bytes) or not purpose:
            raise ValueError("purpose should be a non-empty str or bytes.")
        if isinstance(recipient_context, str):
            recipient_context = recipient_context.encode("utf-8")
        if not isinstance(recipient_context, bytes):
            raise ValueError("recipient_context should be str or bytes.")
        return cbor2.dumps([EncryptedCOSEKey._CONTEXT_DOMAIN, purpose, recipient_context])

    @staticmethod
    def from_cose_key(
        key: COSEKeyInterface,
        encryption_key: COSEKeyInterface,
        context: bytes,
        nonce: bytes = b"",
        tagged: bool = False,
    ) -> list[Any] | bytes:
        """
        Returns an encrypted COSE key formatted to COSE_Encrypt0 structure.

        Args:
            key: COSEKeyInterface: A key to be encrypted.
            encryption_key: COSEKeyInterface: An encryption key to encrypt the
                target COSE key. It must be permitted to perform the
                ``encrypt`` (3) key operation when its ``key_ops`` is set.
            context (bytes): An authenticated context built by
                :func:`build_context <cwt.EncryptedCOSEKey.build_context>`.
                It binds the envelope to a specific protocol purpose and
                recipient context and is authenticated as external AAD.
            nonce (bytes): A nonce for encryption.
            tagged (bool): An indicator whether the response is wrapped by CWT
                tag(61) or not.
        Returns:
            list[Any] | bytes: A COSE_Encrypt0 structure of the target COSE key.
        Raises:
            ValueError: Invalid arguments.
            EncodeError: Failed to encrypt the COSE key.
        """
        if not isinstance(context, bytes) or not context:
            raise ValueError("context should be a non-empty bytes built by EncryptedCOSEKey.build_context().")
        if encryption_key.key_ops and COSEKeyOps.ENCRYPT not in encryption_key.key_ops:
            raise ValueError("The encryption key is not permitted to encrypt (key_ops should include 3).")
        protected: dict[int, Any] = {1: encryption_key.alg}
        unprotected: dict[int, Any] = {4: encryption_key.kid} if encryption_key.kid else {}
        if not nonce:
            try:
                nonce = encryption_key.generate_nonce()
            except NotImplementedError:
                raise ValueError("Nonce generation is not supported for the key. Set a nonce explicitly.")
        unprotected[5] = nonce
        b_payload = cbor2.dumps(key.to_dict())
        res: CBORTag = COSE().encode_and_encrypt(
            b_payload,
            encryption_key,
            protected,
            unprotected,
            external_aad=context,
            out="cbor2/CBORTag",
        )
        return res.value

    @staticmethod
    def to_cose_key(
        key: list[Any],
        encryption_key: COSEKeyInterface,
        context: bytes | None = None,
        alg: int | str | None = None,
        key_ops: list[int] | list[str] | None = None,
        legacy: bool = False,
    ) -> COSEKeyInterface:
        """
        Returns an decrypted COSE key.

        A context-bound envelope (the format produced by the current
        :func:`from_cose_key <cwt.EncryptedCOSEKey.from_cose_key>`) is opened
        with the same authenticated context used to create it. A legacy
        envelope without an authenticated context can only be opened by setting
        ``legacy=True`` explicitly. A failed context verification never falls
        back to the legacy behavior.

        After decryption, the algorithm and key operations of the recovered key
        are checked against the caller policy (``alg`` and ``key_ops``) when
        given. Note that this policy applies to the *wrapped* key inside the
        envelope, not to the ``encryption_key`` that wraps it.

        Args:
            key: COSEKeyInterface: A key formatted to COSE_Encrypt0 structure to be decrypted.
            encryption_key: COSEKeyInterface: An encryption key to decrypt the target COSE key.
                It must be permitted to perform the ``decrypt`` (4) key
                operation when its ``key_ops`` is set.
            context (bytes | None): An authenticated context built by
                :func:`build_context <cwt.EncryptedCOSEKey.build_context>`.
                Required unless ``legacy`` is True.
            alg (int | str | None): The expected algorithm of the decrypted
                (wrapped) key. The recovered key is rejected if its algorithm
                differs.
            key_ops (list[int] | list[str] | None): Key operations that the
                decrypted (wrapped) key must be permitted to perform. The
                recovered key is rejected if any of them is missing from its
                ``key_ops``.
            legacy (bool): An explicit opt-in to decrypt an old envelope that
                was produced without an authenticated context. It must not be
                set together with a ``context``.
        Returns:
            COSEKeyInterface: A key decrypted.
        Raises:
            ValueError: Invalid arguments.
            DecodeError: Failed to decode the COSE key.
            VerifyError: Failed to verify the COSE key or the recovered key
                does not satisfy the caller policy.
        """
        if legacy:
            if context is not None:
                raise ValueError("context must not be set when legacy is True.")
            external_aad = b""
        else:
            if not isinstance(context, bytes) or not context:
                raise ValueError(
                    "context is required. Use EncryptedCOSEKey.build_context() or set legacy=True "
                    "explicitly for an old envelope without an authenticated context."
                )
            external_aad = context
        if encryption_key.key_ops and COSEKeyOps.DECRYPT not in encryption_key.key_ops:
            raise ValueError("The encryption key is not permitted to decrypt (key_ops should include 4).")

        # The AEAD tag covers the authenticated context, so a mismatched
        # purpose/recipient context raises here. It must not be retried with
        # the legacy (empty AAD) behavior.
        res = cbor2.loads(
            COSE().decode(CBORTag(16, key), encryption_key, external_aad=external_aad),
            allow_duplicate_keys=False,
        )
        cose_key = COSEKey.new(res)
        EncryptedCOSEKey._verify_policy(cose_key, alg, key_ops)
        return cose_key

    @staticmethod
    def _verify_policy(
        cose_key: COSEKeyInterface,
        alg: int | str | None,
        key_ops: list[int] | list[str] | None,
    ) -> None:
        if alg is not None:
            expected_alg = alg if isinstance(alg, int) else COSE_NAMED_ALGORITHMS_SUPPORTED.get(alg, 0)
            if isinstance(alg, str) and expected_alg == 0:
                raise ValueError(f"Unsupported or unknown alg: {alg}.")
            if cose_key.alg != expected_alg:
                raise VerifyError(
                    f"The alg({cose_key.alg}) of the decrypted key does not match the expected alg({expected_alg})."
                )
        if key_ops is not None:
            if not isinstance(key_ops, list) or not key_ops:
                raise ValueError("key_ops should be a non-empty list.")
            expected_key_ops: list[int] = []
            for op in key_ops:
                if isinstance(op, str):
                    if op not in COSE_KEY_OPERATION_VALUES:
                        raise ValueError(f"Unsupported or unknown key_ops: {op}.")
                    expected_key_ops.append(COSE_KEY_OPERATION_VALUES[op])
                else:
                    expected_key_ops.append(op)
            if not cose_key.key_ops:
                raise VerifyError("The decrypted key has no key_ops, but key_ops are required by the policy.")
            missing = [op for op in expected_key_ops if op not in cose_key.key_ops]
            if missing:
                raise VerifyError(
                    f"The decrypted key is not permitted for the required key_ops: {missing}."
                )
