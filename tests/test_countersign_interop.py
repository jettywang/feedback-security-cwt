# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Independent interoperability tests for COSE detached payloads and
countersignatures (RFC 9052 and RFC 9338).

All expected countersignature bytes in this file are derived from
explicitly constructed Countersign_structure arrays signed with the raw
COSE key. The production ``COSEMessage.countersign`` implementation is
never used to build the expected answers: it only appears as the
implementation under test, either verifying independently constructed
countersignatures or producing output that is checked against
independently built structures.
"""

import cbor2
import pytest

from cwt import COSE, COSEKey, COSEMessage, DecodeError, Signer, VerifyError
from cwt.enums import COSEAlgs, COSEHeaders

from .utils import key_path

# Countersignature header labels (RFC 9338).
ABBREVIATED_COUNTERSIGNATURE = 12

COUNTERSIGN_AAD = b"countersign-external-aad"
WRONG_AAD = b"wrong-external-aad"
PAYLOAD = b"Hello world!"

MSG_TYPES = ["sign1", "mac0", "encrypt0"]

# CBOR tags for the covered message types.
TAGS = {"sign1": 18, "mac0": 17, "encrypt0": 16}


def _load_key(name: str) -> COSEKey:
    with open(key_path(name)) as f:
        return COSEKey.from_jwk(f.read())


@pytest.fixture(scope="module")
def notary_key():
    return _load_key("private_key_es256.json")


@pytest.fixture(scope="module")
def notary_pub():
    return _load_key("public_key_es256.json")


def _countersign_structure(
    context: str,
    body_protected: bytes,
    sign_protected: bytes | None,
    external_aad: bytes,
    payload: bytes,
    other_fields: list[bytes],
) -> bytes:
    """
    Serializes a Countersign_structure (RFC 9338) from an explicit array.
    """
    structure = [context, body_protected]
    if sign_protected is not None:
        structure.append(sign_protected)
    structure.append(external_aad)
    structure.append(payload)
    structure.extend(other_fields)
    return cbor2.dumps(structure)


def _make_message(msg_type: str, payload: bytes) -> tuple[bytes, COSEKey]:
    """
    Creates an encoded COSE message of the given type. Returns (encoded, key).
    """
    sender = COSE.new(alg_auto_inclusion=True, kid_auto_inclusion=True)
    if msg_type == "sign1":
        key = _load_key("private_key_ed25519.json")
        return sender.encode_and_sign(payload, key), key
    if msg_type == "mac0":
        key = COSEKey.generate_symmetric_key(alg="HS256", kid="01")
        return sender.encode_and_mac(payload, key), key
    if msg_type == "encrypt0":
        key = COSEKey.generate_symmetric_key(alg="A256GCM", kid="01")
        return sender.encode_and_encrypt(payload, key), key
    raise ValueError(f"unknown message type: {msg_type}")


def _other_fields(tag: int, value: list) -> list[bytes]:
    """
    The fields bound by a V2 countersignature beyond the payload:
    the signature for Sign1 and the tag for MAC0. Encrypt0 has none.
    """
    return [value[3]] if tag in (18, 17) else []


def _context(tag: int, value: list, abbreviated: bool) -> str:
    if _other_fields(tag, value):
        return "CounterSignature0V2" if abbreviated else "CounterSignatureV2"
    return "CounterSignature0" if abbreviated else "CounterSignature"


def _independent_countersign(
    encoded: bytes,
    notary_key: COSEKey,
    aad: bytes = COUNTERSIGN_AAD,
    abbreviated: bool = False,
    detached_payload: bytes | None = None,
) -> tuple[bytes, bytes]:
    """
    Countersigns a COSE message without using the production countersign
    implementation. The original byte strings of the decoded message
    (protected headers, payload, signature/tag/ciphertext) are reused
    verbatim so no re-encoding can hide binding problems.
    Returns (countersigned message, expected signature bytes).
    """
    tagged = cbor2.loads(encoded)
    value = list(tagged.value)
    value[1] = dict(value[1])
    payload = value[2] if detached_payload is None else detached_payload
    other_fields = _other_fields(tagged.tag, value)
    context = _context(tagged.tag, value, abbreviated)
    if abbreviated:
        tbs = _countersign_structure(context, value[0], None, aad, payload, other_fields)
        signature = notary_key.sign(tbs)
        value[1][ABBREVIATED_COUNTERSIGNATURE] = signature
    else:
        sign_protected = cbor2.dumps({COSEHeaders.ALG: COSEAlgs.ES256})
        tbs = _countersign_structure(context, value[0], sign_protected, aad, payload, other_fields)
        signature = notary_key.sign(tbs)
        value[1][COSEHeaders.COUNTER_SIGNATURE_V2] = [sign_protected, {COSEHeaders.KID: notary_key.kid}, signature]
    return cbor2.dumps(cbor2.CBORTag(tagged.tag, value)), signature


def _tamper(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


class TestIndependentCountersign:
    """
    Countersignatures built from explicit structure arrays must be
    accepted by the production verifier.
    """

    @pytest.mark.parametrize("msg_type", MSG_TYPES)
    @pytest.mark.parametrize("abbreviated", [False, True])
    def test_independent_countersign_verifies(self, msg_type, abbreviated, notary_key, notary_pub):
        encoded, key = _make_message(msg_type, PAYLOAD)
        countersigned, expected_sig = _independent_countersign(encoded, notary_key, abbreviated=abbreviated)

        msg = COSEMessage.loads(countersigned)
        result = msg.counterverify(notary_pub, aad=COUNTERSIGN_AAD)
        if abbreviated:
            assert result is None
            assert msg.unprotected[ABBREVIATED_COUNTERSIGNATURE] == expected_sig
        else:
            assert result is not None
            assert result[2] == expected_sig
            assert result[1][COSEHeaders.KID] == notary_key.kid

        # The countersignature must not disturb the original message.
        assert COSE.new().decode(countersigned, key) == PAYLOAD

    @pytest.mark.parametrize("msg_type", MSG_TYPES)
    @pytest.mark.parametrize("abbreviated", [False, True])
    def test_countersign_binds_external_aad(self, msg_type, abbreviated, notary_key, notary_pub):
        encoded, _ = _make_message(msg_type, PAYLOAD)
        countersigned, _ = _independent_countersign(encoded, notary_key, abbreviated=abbreviated)
        with pytest.raises(VerifyError):
            COSEMessage.loads(countersigned).counterverify(notary_pub, aad=WRONG_AAD)

    @pytest.mark.parametrize("msg_type", MSG_TYPES)
    @pytest.mark.parametrize("abbreviated", [False, True])
    def test_countersign_binds_signature_tag_and_ciphertext(
        self, msg_type, abbreviated, notary_key, notary_pub
    ):
        encoded, _ = _make_message(msg_type, PAYLOAD)
        countersigned, _ = _independent_countersign(encoded, notary_key, abbreviated=abbreviated)
        tagged = cbor2.loads(countersigned)
        # Sign1/MAC0: the signature/tag is bound as an other_field.
        # Encrypt0: the ciphertext is bound as the payload.
        index = 3 if msg_type in ("sign1", "mac0") else 2
        tampered = list(tagged.value)
        tampered[index] = _tamper(tampered[index])
        msg = COSEMessage.loads(cbor2.dumps(cbor2.CBORTag(tagged.tag, tampered)))
        with pytest.raises(VerifyError):
            msg.counterverify(notary_pub, aad=COUNTERSIGN_AAD)

    @pytest.mark.parametrize("msg_type", ["sign1", "mac0"])
    @pytest.mark.parametrize("abbreviated", [False, True])
    def test_countersign_binds_payload(self, msg_type, abbreviated, notary_key, notary_pub):
        encoded, _ = _make_message(msg_type, PAYLOAD)
        countersigned, _ = _independent_countersign(encoded, notary_key, abbreviated=abbreviated)
        tagged = cbor2.loads(countersigned)
        tampered = list(tagged.value)
        tampered[2] = _tamper(tampered[2])
        msg = COSEMessage.loads(cbor2.dumps(cbor2.CBORTag(tagged.tag, tampered)))
        with pytest.raises(VerifyError):
            msg.counterverify(notary_pub, aad=COUNTERSIGN_AAD)


class TestDetachedPayload:
    """
    Detached payload handling: a detached message must verify when the
    same payload is supplied again, and must fail otherwise.
    """

    @pytest.mark.parametrize("msg_type", MSG_TYPES)
    def test_detach_and_supply_same_payload(self, msg_type):
        encoded, key = _make_message(msg_type, PAYLOAD)
        msg, detached = COSEMessage.loads(encoded).detach_payload()
        assert detached == (PAYLOAD if msg_type != "encrypt0" else cbor2.loads(encoded).value[2])
        detached_bytes = msg.dumps()

        # The payload position carries null on the wire.
        assert cbor2.loads(detached_bytes).value[2] is None

        # Supplying the same payload verifies; omitting or changing it fails.
        assert COSE.new().decode(detached_bytes, key, detached_payload=detached) == PAYLOAD
        with pytest.raises(ValueError):
            COSE.new().decode(detached_bytes, key)
        # Sign1/MAC0 fail verification, Encrypt0 fails decryption.
        error = DecodeError if msg_type == "encrypt0" else VerifyError
        with pytest.raises(error):
            COSE.new().decode(detached_bytes, key, detached_payload=_tamper(detached))

    @pytest.mark.parametrize("msg_type", MSG_TYPES)
    def test_detached_payload_countersign(self, msg_type, notary_key, notary_pub):
        encoded, _ = _make_message(msg_type, PAYLOAD)
        msg, detached = COSEMessage.loads(encoded).detach_payload()
        countersigned, _ = _independent_countersign(msg.dumps(), notary_key, detached_payload=detached)

        # The same payload supplied again verifies.
        COSEMessage.loads(countersigned).counterverify(notary_pub, aad=COUNTERSIGN_AAD, detached_payload=detached)
        # Without the payload the structure would contain null: must fail.
        with pytest.raises(VerifyError):
            COSEMessage.loads(countersigned).counterverify(notary_pub, aad=COUNTERSIGN_AAD)
        # A different payload must fail.
        with pytest.raises(VerifyError):
            COSEMessage.loads(countersigned).counterverify(
                notary_pub, aad=COUNTERSIGN_AAD, detached_payload=_tamper(detached)
            )

    @pytest.mark.parametrize("msg_type", ["sign1", "mac0"])
    def test_empty_payload_is_not_a_detached_payload(self, msg_type, notary_key, notary_pub):
        # An empty (but attached) payload is h'' on the wire.
        encoded, _ = _make_message(msg_type, b"")
        assert cbor2.loads(encoded).value[2] == b""
        countersigned, _ = _independent_countersign(encoded, notary_key)
        # It verifies without supplying any detached payload.
        COSEMessage.loads(countersigned).counterverify(notary_pub, aad=COUNTERSIGN_AAD)

        # Detaching the empty payload puts null on the wire instead.
        msg, detached = COSEMessage.loads(encoded).detach_payload()
        assert detached == b""
        detached_bytes = msg.dumps()
        assert cbor2.loads(detached_bytes).value[2] is None
        countersigned_detached, _ = _independent_countersign(detached_bytes, notary_key, detached_payload=detached)
        # Now the (empty) payload must be supplied explicitly: verifying
        # against null in the structure must fail.
        with pytest.raises(VerifyError):
            COSEMessage.loads(countersigned_detached).counterverify(notary_pub, aad=COUNTERSIGN_AAD)
        COSEMessage.loads(countersigned_detached).counterverify(
            notary_pub, aad=COUNTERSIGN_AAD, detached_payload=b""
        )


class TestProductionCountersignBinding:
    """
    Checks which fields the production countersign implementation actually
    binds, by verifying its output against independently built structures.
    """

    @pytest.mark.parametrize("msg_type", MSG_TYPES)
    @pytest.mark.parametrize("abbreviated", [False, True])
    def test_countersign_binds_expected_fields(self, msg_type, abbreviated, notary_key, notary_pub):
        encoded, _ = _make_message(msg_type, PAYLOAD)
        notary = Signer.new(notary_key, protected={"alg": "ES256"}, unprotected={"kid": "P-256-01"})
        countersigned = COSEMessage.loads(encoded).countersign(notary, aad=COUNTERSIGN_AAD, abbreviated=abbreviated)
        value = list(cbor2.loads(countersigned.dumps()).value)
        other_fields = _other_fields(TAGS[msg_type], value)

        if abbreviated:
            signature = value[1][ABBREVIATED_COUNTERSIGNATURE]
            sign_protected = None
        else:
            cs = value[1][COSEHeaders.COUNTER_SIGNATURE_V2]
            sign_protected = cs[0]
            signature = cs[2]

        # The exact structure the implementation must have signed.
        tbs = _countersign_structure(
            _context(TAGS[msg_type], value, abbreviated), value[0], sign_protected, COUNTERSIGN_AAD, value[2], other_fields
        )
        notary_pub.verify(tbs, signature)

        # A structure with the wrong field set must not verify: for
        # Sign1/MAC0 the signature/tag has to be bound (V2), for Encrypt0
        # no other fields may be bound.
        if other_fields:
            bad_tbs = _countersign_structure(
                "CounterSignature0" if abbreviated else "CounterSignature",
                value[0],
                sign_protected,
                COUNTERSIGN_AAD,
                value[2],
                [],
            )
        else:
            bad_tbs = _countersign_structure(
                "CounterSignature0V2" if abbreviated else "CounterSignatureV2",
                value[0],
                sign_protected,
                COUNTERSIGN_AAD,
                value[2],
                [value[2]],
            )
        with pytest.raises(VerifyError):
            notary_pub.verify(bad_tbs, signature)

    @pytest.mark.parametrize("msg_type", MSG_TYPES)
    def test_countersign_binds_detached_payload(self, msg_type, notary_key, notary_pub):
        encoded, _ = _make_message(msg_type, PAYLOAD)
        msg, detached = COSEMessage.loads(encoded).detach_payload()
        notary = Signer.new(notary_key, protected={"alg": "ES256"}, unprotected={"kid": "P-256-01"})
        countersigned = msg.countersign(notary, aad=COUNTERSIGN_AAD, detached_payload=detached)
        value = list(cbor2.loads(countersigned.dumps()).value)

        # The payload stays detached on the wire.
        assert value[2] is None
        cs = value[1][COSEHeaders.COUNTER_SIGNATURE_V2]
        tbs = _countersign_structure(
            _context(TAGS[msg_type], value, False),
            value[0],
            cs[0],
            COUNTERSIGN_AAD,
            detached,
            _other_fields(TAGS[msg_type], value),
        )
        notary_pub.verify(tbs, cs[2])


class TestOriginalEncodingPreserved:
    """
    The original encoding of a message must be preserved: re-encoding the
    protected headers would change the signed bytes and must not happen.
    """

    def test_sign1_with_non_canonical_protected_header(self, notary_key, notary_pub):
        key = _load_key("private_key_ed25519.json")
        pub = _load_key("public_key_ed25519.json")

        # {1: -8} (alg: EdDSA) as an indefinite-length map. Any re-encoding
        # would produce the canonical form a10127 instead.
        protected = b"\xbf\x01\x27\xff"
        assert cbor2.loads(protected) == {COSEHeaders.ALG: COSEAlgs.EDDSA}
        assert cbor2.dumps(cbor2.loads(protected)) != protected

        tbs = cbor2.dumps(["Signature1", protected, b"", PAYLOAD])
        signature = key.sign(tbs)
        encoded = cbor2.dumps(cbor2.CBORTag(18, [protected, {COSEHeaders.KID: key.kid}, PAYLOAD, signature]))

        # The primary signature verifies against the original encoding.
        assert COSE.new().decode(encoded, pub) == PAYLOAD

        # A countersignature over the raw protected bytes verifies, and
        # the original encoding survives verbatim in the output.
        countersigned, _ = _independent_countersign(encoded, notary_key)
        assert protected in countersigned
        assert b"\x43\xa1\x01\x27" not in countersigned  # no canonical re-encoding
        COSEMessage.loads(countersigned).counterverify(notary_pub, aad=COUNTERSIGN_AAD)
