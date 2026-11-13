from typing import Any, Self

from .cbor_processor import CBORProcessor
from .const import COSE_ALGORITHMS_KEY_WRAP, COSE_KEY_OPERATION_VALUES
from .cose_key import COSEKey
from .cose_key_interface import COSEKeyInterface
from .recipient import Recipient
from .recipient_interface import RecipientInterface


class Recipients(CBORProcessor):
    """
    A Set of COSE Recipients.
    """

    def __init__(self, recipients: list[RecipientInterface], verify_kid: bool = False):
        self._recipients = recipients
        self._verify_kid = verify_kid
        return

    @classmethod
    def from_list(
        cls,
        recipients: list[Any] | tuple[Any, ...],
        verify_kid: bool = False,
        context: list[Any] | dict[str, Any] | None = None,
        hpke_psk: bytes | None = None,
        extra_info: bytes = b"",
        hpke_aad: bytes = b"",
    ) -> Self:
        """
        Create Recipients from a CBOR-like list.
        """
        res: list[RecipientInterface] = []
        for r in recipients:
            res.append(Recipient.from_list(r, context, hpke_psk=hpke_psk, extra_info=extra_info, hpke_aad=hpke_aad))
        return cls(res, verify_kid)

    def encode(
        self,
        plaintext: bytes,
        external_aad: bytes,
        content_aad: str,
    ) -> tuple[list[list[Any]], COSEKeyInterface | None]:
        """
        Encodes every top-level recipient, recursing into nested recipient
        chains (e.g. a key-encryption key wrapped by another key wrap).

        Returns the encoded recipient structures together with the content key
        derived by a direct/key-agreement recipient, if any.
        """
        encoded: list[list[Any]] = []
        derived_key: COSEKeyInterface | None = None
        for r in self._recipients:
            aad = self._dumps([content_aad, r.b_protected, external_aad])
            key_bytes = plaintext
            if r.recipients:
                # The nested recipients protect this recipient's own key material.
                child_encoded, child_key = Recipients(r.recipients, self._verify_kid).encode(
                    r.key, external_aad, content_aad
                )
                if child_key is not None:
                    key_bytes = child_key.to_bytes()
                r._set_nested_recipients(child_encoded)
            res, candidate = r.encode(key_bytes, aad)
            if candidate is not None:
                derived_key = candidate
            encoded.append(res)
        return encoded, derived_key

    def derive_key(self, keys: list[COSEKeyInterface], alg: int, external_aad: bytes, content_aad: str) -> COSEKeyInterface:
        """
        Decodes an appropriate key from recipients or keys provided as a parameter ``keys``.

        Each recipient branch is evaluated independently so that a failed branch
        (rejected candidates or an authentication/decoding failure) never leaks
        algorithm/context state into later branches. The two failure modes are
        kept distinct:

        * ``ValueError("key is not found.")`` when no supplied key is eligible
          for any recipient (a kid / key_ops / alg mismatch at selection time),
          and
        * the underlying decode/verification error when an eligible key was
          actually tried but the recipient could not be authenticated/decoded.
          The raised error carries non-sensitive per-branch diagnostics
          (recipient alg and kid), never key material.
        """
        if not self._recipients:
            raise ValueError("No recipients.")

        not_found = ValueError("key is not found.")
        decode_err: Exception | None = None

        for r in self._recipients:
            if not r.kid and self._verify_kid:
                raise ValueError("kid should be specified in recipient.")

            aad = self._dumps([content_aad, r.b_protected, external_aad])
            branch_err: Exception | None = None

            # A nested recipient chain (e.g. a wrapped key-encryption key) is
            # resolved first through its own child recipients. This keeps the
            # branch self-contained: a parent whose kid/key_ops do not match any
            # supplied key can still be opened via a matching child.
            if r.recipients:
                try:
                    return self._decode_nested(r, aad, alg, keys, external_aad, content_aad)
                except Exception as e:
                    branch_err = e
                    decode_err = e

            candidates = self._select_candidates(r, keys)
            if not candidates:
                if branch_err is None:
                    # Selection miss only (kid/key_ops/alg mismatch): keep
                    # scanning without recording a decode failure.
                    continue
            else:
                for k in candidates:
                    try:
                        return self._decode_recipient(r, k, aad, alg)
                    except Exception as e:
                        # Isolate the failure: the next candidate/branch starts clean.
                        branch_err = e
                        decode_err = e

            if branch_err is not None:
                not_found = ValueError(
                    f"Failed to decode recipient (alg={r.alg}, kid={r.kid!r}): {branch_err}"
                )

        if decode_err is not None:
            raise decode_err
        raise not_found

    def _decode_nested(
        self,
        r: RecipientInterface,
        aad: bytes,
        alg: int,
        keys: list[COSEKeyInterface],
        external_aad: bytes,
        content_aad: str,
    ) -> COSEKeyInterface:
        wrapping_key = Recipients(r.recipients, self._verify_kid).derive_key(
            keys, r.alg, external_aad, content_aad
        )
        res = r.decode(wrapping_key, aad, alg=alg, as_cose_key=True)
        if not isinstance(res, COSEKeyInterface):
            raise TypeError("Internal type error.")
        return res

    def _decode_recipient(
        self,
        r: RecipientInterface,
        key: COSEKeyInterface,
        aad: bytes,
        alg: int,
    ) -> COSEKeyInterface:
        res = r.decode(key, aad, alg=alg, as_cose_key=True)
        if not isinstance(res, COSEKeyInterface):
            raise TypeError("Internal type error.")
        return res

    def _select_candidates(
        self, r: RecipientInterface, keys: list[COSEKeyInterface]
    ) -> list[COSEKeyInterface]:
        required_ops = self._required_key_ops(r.alg)
        constrains_key = self._enforces_key_metadata(r.alg)
        candidates: list[COSEKeyInterface] = []
        for k in keys:
            # 1. kid must match when the recipient carries one.
            if r.kid and k.kid != r.kid:
                continue

            # The key_ops/alg metadata is only meaningful for symmetric keys used
            # with the direct and AES key-wrap families. HKDF and key-agreement
            # recipients (including HPKE) accept arbitrary symmetric material, and
            # asymmetric agreement keys commonly carry signature-suite labels.
            if constrains_key and k.kty == 4:
                # 2. key_ops: an empty list means the operation set is unrestricted.
                if required_ops and k.key_ops and not any(op in k.key_ops for op in required_ops):
                    continue
                # 3. alg: a key without an alg label is not constrained. The
                # direct(-6) family returns the content key as-is, so its alg may
                # label the content algorithm rather than the recipient.
                if k.alg is not None and r.alg != -6 and k.alg != r.alg:
                    continue
            candidates.append(k)
        return candidates

    @staticmethod
    def _enforces_key_metadata(recipient_alg: int) -> bool:
        return recipient_alg == -6 or recipient_alg in COSE_ALGORITHMS_KEY_WRAP.values()

    @staticmethod
    def _required_key_ops(recipient_alg: int) -> list[int]:
        # Only the AES key-wrap family declares a required operation here; the
        # direct family needs no operation on the returned content key.
        if recipient_alg in COSE_ALGORITHMS_KEY_WRAP.values():
            return [COSE_KEY_OPERATION_VALUES["unwrapKey"]]
        return []

    def _create_key(self, alg: int, k: COSEKeyInterface, r: RecipientInterface) -> COSEKeyInterface:
        if r.alg == -6:  # direct
            # if k.alg != alg:
            #     raise ValueError("alg mismatch.")
            return k
        return COSEKey.new({1: 4, 3: alg, -1: r.decode(k)})
