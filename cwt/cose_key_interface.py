from typing import Any

from .cbor_processor import CBORProcessor
from .const import (
    COSE_KEY_OPERATION_VALUES,
    COSE_KEY_TYPES,
    COSE_NAMED_ALGORITHMS_SUPPORTED,
)


class COSEKeyInterface(CBORProcessor):
    """
    The interface class for a COSE Key used for MAC, signing/verifying and encryption/decryption.
    """

    def __init__(self, params: dict[int, Any]):
        """
        Constructor.

        Args:
            params (dict[int, Any]): A COSE key common parameter object formatted to CBOR-like
                structure ((dict[int, Any])).
        """

        # kty
        if 1 not in params:
            raise ValueError("kty(1) not found.")
        if not isinstance(params[1], int) and not isinstance(params[1], str):
            raise ValueError("kty(1) should be int or str(tstr).")
        if isinstance(params[1], int) and params[1] not in [1, 2, 3, 4, 5, 6]:
            raise ValueError(f"Unknown kty: {params[1]}")
        if isinstance(params[1], str) and params[1] not in COSE_KEY_TYPES:
            raise ValueError(f"Unknown kty: {params[1]}")
        self._kty: int = params[1] if isinstance(params[1], int) else COSE_KEY_TYPES[params[1]]

        # kid
        if 2 in params and not isinstance(params[2], bytes):
            raise ValueError("kid(2) should be bytes(bstr).")
        self._kid = params[2] if 2 in params else None

        # alg
        self._alg = None
        if 3 in params:
            if not isinstance(params[3], int) and not isinstance(params[3], str):
                raise ValueError("alg(3) should be int or str(tstr).")
            if isinstance(params[3], str) and params[3] not in COSE_NAMED_ALGORITHMS_SUPPORTED:
                raise ValueError(f"Unsupported or unknown alg(3): {params[3]}.")
            self._alg = params[3] if isinstance(params[3], int) else COSE_NAMED_ALGORITHMS_SUPPORTED[params[3]]

        # key_ops
        if 4 in params and not isinstance(params[4], list):
            raise ValueError("key_ops(4) should be list.")
        self._key_ops: list[int] = params[4] if 4 in params else []
        for v in self._key_ops:
            if v not in COSE_KEY_OPERATION_VALUES.values():
                raise ValueError(f"key_ops(4) includes invalid value: {v}.")

        # Base IV
        if 5 in params and not isinstance(params[5], bytes):
            raise ValueError("Base IV(5) should be bytes(bstr).")
        self._base_iv = params[5] if 5 in params else None
        return

    @property
    def kty(self) -> int:
        """
        The identifier of the key type.
        """
        return self._kty

    @property
    def kid(self) -> bytes | None:
        """
        The key identifier.
        """
        return self._kid

    @property
    def alg(self) -> int | None:
        """
        The algorithm that is used with the key.
        """
        return self._alg

    @property
    def key_ops(self) -> list[int]:
        """
        A set of permissible operations that the key is to be used for.
        """
        return self._key_ops

    @property
    def base_iv(self) -> bytes | None:
        """
        Base IV to be xor-ed with Partial IVs.
        """
        return self._base_iv

    @property
    def nonce_length(self) -> int | None:
        """
        The nonce length (in bytes) required by the algorithm of the key,
        or ``None`` if the key does not perform content encryption.
        """
        return None

    def build_nonce(self, iv: bytes | None = None, partial_iv: bytes | None = None) -> bytes:
        """
        Builds the nonce to be passed to the underlying AEAD algorithm from
        the IV header parameters of a COSE message and the Base IV of the key.

        When a full IV (header parameter label 5) is given, it is used as the
        nonce directly and the Base IV is not consulted. When only a Partial IV
        (label 6) is given, it is zero-padded on the left to the length of the
        Base IV and XOR-ed with it, as defined in section 5.3 of RFC 9052.

        The caller is responsible for assigning distinct Partial IV values
        (e.g. an incrementing counter) for every message protected with the
        same key. This function never generates, reuses or defaults a nonce
        on its own.

        Args:
            iv (bytes | None): The full IV header parameter value, or ``None``.
            partial_iv (bytes | None): The Partial IV header parameter value,
                or ``None``.
        Returns:
            bytes: The nonce for the algorithm.
        Raises:
            ValueError: A Partial IV is given without a Base IV, the Partial IV
                is longer than the Base IV, both IVs are given, or neither IV
                is given.
        """
        if iv is not None:
            if partial_iv is not None:
                raise ValueError("IV and Partial IV must not both be present in the same security layer.")
            return iv
        if partial_iv is None:
            raise ValueError("IV or Partial IV should be set.")
        if self._base_iv is None:
            raise ValueError("Partial IV requires a Base IV in the key.")
        nonce_length = self.nonce_length
        if nonce_length is not None and len(self._base_iv) != nonce_length:
            raise ValueError(
                f"The length of Base IV should be {nonce_length} bytes for the algorithm."
            )
        if len(partial_iv) > len(self._base_iv):
            raise ValueError("Partial IV must not be longer than the Base IV.")
        padded = b"\x00" * (len(self._base_iv) - len(partial_iv)) + partial_iv
        return bytes(a ^ b for a, b in zip(self._base_iv, padded))

    @property
    def key(self) -> Any:
        """
        The body of the key. It can be bytes or various PublicKey/PrivateKey objects
        defined in ``pyca/cryptography``
        """
        raise NotImplementedError

    @property
    def crv(self) -> int:
        """
        The curve (``crv`` parameter value) of the key.
        """
        raise NotImplementedError

    def to_bytes(self) -> bytes:
        """
        Serializes the body of the key as a byte string.
        """
        raise NotImplementedError

    def to_dict(self) -> dict[int, Any]:
        """
        Returns the CBOR-like structure (dict[int, Any]) of the COSE key.

        Returns:
            dict[int, Any]: The CBOR-like structure of the COSE key.
        """
        res: dict[int, Any] = {1: self._kty}
        if self._kid:
            res[2] = self._kid
        if self._alg:
            res[3] = self._alg
        if self._key_ops:
            res[4] = self._key_ops
        if self._base_iv:
            res[5] = self._base_iv
        return res

    def generate_nonce(self) -> bytes:
        """
        Returns a nonce with the size suitable for the algorithm.
        This function will be called internally in :class:`CWT <cwt.CWT>`
        when no nonce is specified by the application.
        This function adopts ``secrets.token_bytes()`` to generate a nonce.
        If you do not want to use it, you should explicitly set a nonce to
        :class:`CWT <cwt.CWT>` functions
        (e.g., :func:`encode_and_encrypt <cwt.CWT.encode_and_encrypt>`).

        Returns:
            bytes: A byte string of the generated nonce.
        Raises:
            NotImplementedError: Not implemented.
        """
        raise NotImplementedError

    def sign(self, msg: bytes) -> bytes:
        """
        Returns a digital signature for the specified message
        using the specified key value.

        Args:
            msg (bytes): A message to be signed.
        Returns:
            bytes: The byte string of the encoded CWT.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            EncodeError: Failed to sign the message.
        """
        raise NotImplementedError

    def verify(self, msg: bytes, sig: bytes):
        """
        Verifies that the specified digital signature is valid
        for the specified message.

        Args:
            msg (bytes): A message to be verified.
            sig (bytes): A digital signature of the message.
        Returns:
            bytes: The byte string of the encoded CWT.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            VerifyError: Failed to verify.
        """
        raise NotImplementedError

    def validate_certificate(self, ca_certs: list[bytes]) -> bool:
        """
        Validate a certificate bound to the key with given trusted CA
        certificates if the key has `x5c` parameter.

        Args:
            ca_certs(list[bytes]): A list of DER-formatted trusted root CA
                certificates which contains a concatenated list of trusted root
                certificates. You should specify private CA certificates in your
                target system. There should be no need to use the public CA
                certificates for the Web PKI.
        Returns:
            bool: The indicator whether the validation is done or not.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            VerifyError: Failed to verify.
        """
        raise NotImplementedError

    def encrypt(self, msg: bytes, nonce: bytes, aad: bytes) -> bytes:
        """
        Encrypts the specified message.

        Args:
            msg (bytes): A message to be encrypted.
            nonce (bytes): A nonce for encryption.
            aad (bytes): Additional authenticated data.
        Returns:
            bytes: The byte string of encrypted data.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            EncodeError: Failed to encrypt the message.
        """
        raise NotImplementedError

    def decrypt(self, msg: bytes, nonce: bytes, aad: bytes) -> bytes:
        """
        Decrypts the specified message.

        Args:
            msg (bytes): An encrypted message.
            nonce (bytes): A nonce for encryption.
            aad (bytes): Additional authenticated data.
        Returns:
            bytes: The byte string of the decrypted data.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            DecodeError: Failed to decrypt the message.
        """
        raise NotImplementedError

    def wrap_key(self, key_to_wrap: bytes) -> bytes:
        """
        Wraps a key.

        Args:
            key_to_wrap: A key to wrap.
        Returns:
            bytes: A wrapped key as bytes.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            EncodeError: Failed to derive key.
        """
        raise NotImplementedError

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        """
        Unwraps a key.

        Args:
            wrapped_key: A key to be unwrapped.
        Returns:
            bytes: An unwrapped key as bytes.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            DecodeError: Failed to unwrap key.
        """
        raise NotImplementedError

    def derive_bytes(
        self,
        length: int,
        material: bytes = b"",
        info: bytes = b"",
        public_key: Any | None = None,
    ) -> bytes:
        """
        Derives a byte string with a key material or key exchange.

        Args:
            length (int): The length of derived byte string.
            material (bytes): A key material as bytes.
            info (bytes): application supplied information.
            public_key: A public key for key derivation with key exchange.
        Returns:
            bytes: A derived byte string.
        Raises:
            NotImplementedError: Not implemented.
            ValueError: Invalid arguments.
            EncodeError: Failed to derive key.
        """
        raise NotImplementedError
