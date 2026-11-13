# pylint: disable=R0201, W0621

"""
Tests for COSE Partial IV (header parameter label 6) support.

A message that carries only a Partial IV is combined with the Base IV of the
content key used to protect it (RFC 9052 section 5.3):

    nonce = Base IV XOR (zero-padded Partial IV)

The caller is responsible for assigning Partial IV values (e.g. an
incrementing counter); the library never generates, reuses or defaults a
nonce on behalf of a Partial IV.
"""

import cbor2
import pytest

from cwt import COSE, COSEKey, Recipient
from cwt.enums import COSEAlgs, COSEHeaders, COSEKeyParams

# Fixed key material so that full-IV and Partial-IV outputs can be compared.
_A128GCM_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
_BASE_IV_12 = bytes.fromhex("0102030405060708090a0b0c")
_FULL_IV_12 = bytes.fromhex("112233445566778899aabbcc")
# _FULL_IV_12 XOR _BASE_IV_12, i.e. the Partial IV equivalent of _FULL_IV_12.
_PARTIAL_IV_12 = bytes.fromhex("102030405060708090a0b0c0")
_PAYLOAD = b"Hello world!"


def _key(alg: int = COSEAlgs.A128GCM, base_iv: bytes | None = _BASE_IV_12, kid: bytes = b"k") -> COSEKey:
    params: dict = {
        COSEKeyParams.KTY: 4,
        COSEKeyParams.ALG: alg,
        COSEKeyParams.K: _A128GCM_KEY,
        COSEKeyParams.KID: kid,
    }
    if base_iv is not None:
        params[COSEKeyParams.BASE_IV] = base_iv
    return COSEKey.new(params)


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


@pytest.fixture(scope="session")
def cose():
    return COSE.new(alg_auto_inclusion=True)


class TestPartialIV:
    def test_partial_iv_produces_same_ciphertext_as_full_iv(self, cose):
        key = _key()
        full = cose.encode_and_encrypt(_PAYLOAD, key, unprotected={COSEHeaders.IV: _FULL_IV_12})
        partial = cose.encode_and_encrypt(_PAYLOAD, key, unprotected={COSEHeaders.PARTIAL_IV: _PARTIAL_IV_12})
        assert cbor2.loads(full).value[2] == cbor2.loads(partial).value[2]
        # The Partial IV is kept verbatim in the header, including its length.
        assert cbor2.loads(partial).value[1][COSEHeaders.PARTIAL_IV] == _PARTIAL_IV_12
        assert COSEHeaders.IV not in cbor2.loads(partial).value[1]

    def test_partial_iv_matches_fixed_full_iv_vector(self, cose):
        key = _key()
        partial = cose.encode_and_encrypt(_PAYLOAD, key, unprotected={COSEHeaders.PARTIAL_IV: _PARTIAL_IV_12})
        # Pinned ciphertext produced with the equivalent full IV, so the XOR
        # combination is checked against a fixed-key/fixed-nonce reference.
        expected_ciphertext = bytes.fromhex("7be8607f3ef34258a6b8ff89693b3b798069d9adad5b6e32fca12c52")
        assert cbor2.loads(partial).value[2] == expected_ciphertext
        full = cose.encode_and_encrypt(_PAYLOAD, key, unprotected={COSEHeaders.IV: _FULL_IV_12})
        assert full != partial  # headers differ (label 6 vs 5)...
        assert cbor2.loads(full).value[2] == cbor2.loads(partial).value[2]  # ...but protected content is equal.

    def test_partial_iv_round_trip(self, cose):
        key = _key()
        encoded = cose.encode_and_encrypt(_PAYLOAD, key, unprotected={COSEHeaders.PARTIAL_IV: _PARTIAL_IV_12})
        assert cose.decode(encoded, key) == _PAYLOAD

    def test_partial_iv_in_protected_header(self, cose):
        key = _key()
        encoded = cose.encode_and_encrypt(
            _PAYLOAD,
            key,
            protected={COSEHeaders.ALG: COSEAlgs.A128GCM, COSEHeaders.PARTIAL_IV: _PARTIAL_IV_12},
        )
        protected = cbor2.loads(encoded).value[0]
        assert cbor2.loads(protected)[COSEHeaders.PARTIAL_IV] == _PARTIAL_IV_12
        assert cose.decode(encoded, key) == _PAYLOAD

    def test_full_iv_in_protected_header_is_used_directly(self, cose):
        key = _key()
        encoded = cose.encode_and_encrypt(
            _PAYLOAD, key, protected={COSEHeaders.ALG: COSEAlgs.A128GCM, COSEHeaders.IV: _FULL_IV_12}
        )
        assert cose.decode(encoded, key) == _PAYLOAD

    def test_leading_zeros_are_preserved(self, cose):
        key = _key()
        # A Partial IV shorter than the Base IV is left-padded with zero bytes.
        short_partial = b"\x00\x00\x30\x40"
        expected_nonce = _xor(_BASE_IV_12, b"\x00" * 8 + short_partial)
        assert key.build_nonce(partial_iv=short_partial) == expected_nonce
        encoded = cose.encode_and_encrypt(_PAYLOAD, key, unprotected={COSEHeaders.PARTIAL_IV: short_partial})
        # The stored Partial IV keeps the leading zero bytes and original length.
        assert cbor2.loads(encoded).value[1][COSEHeaders.PARTIAL_IV] == short_partial
        assert cose.decode(encoded, key) == _PAYLOAD

    def test_zero_length_partial_iv_uses_base_iv_as_nonce(self, cose):
        key = _key()
        assert key.build_nonce(partial_iv=b"") == _BASE_IV_12
        encoded = cose.encode_and_encrypt(_PAYLOAD, key, unprotected={COSEHeaders.PARTIAL_IV: b""})
        assert cose.decode(encoded, key) == _PAYLOAD

    @pytest.mark.parametrize(
        "alg, base_iv, nonce_length, key_len",
        [
            (COSEAlgs.CHACHA20_POLY1305, bytes(range(12)), 12, 32),
            (COSEAlgs.AES_CCM_16_64_128, bytes(range(13)), 13, 16),
            (COSEAlgs.AES_CCM_64_64_128, bytes(range(7)), 7, 16),
            (COSEAlgs.A128CTR, bytes(range(16)), 16, 16),
        ],
    )
    def test_algorithms_with_different_nonce_lengths(self, cose, alg, base_iv, nonce_length, key_len):
        key = COSEKey.new(
            {
                COSEKeyParams.KTY: 4,
                COSEKeyParams.ALG: alg,
                COSEKeyParams.K: bytes(range(key_len)),
                COSEKeyParams.BASE_IV: base_iv,
                COSEKeyParams.KID: b"k",
            }
        )
        assert key.nonce_length == nonce_length
        partial = b"\x00\x01\x02\x03"
        full = _xor(base_iv, b"\x00" * (nonce_length - len(partial)) + partial)
        kwargs = {"enable_non_aead": True} if alg in (COSEAlgs.A128CTR,) else {}
        encoded_full = cose.encode_and_encrypt(_PAYLOAD, key, unprotected={COSEHeaders.IV: full}, **kwargs)
        encoded_partial = cose.encode_and_encrypt(
            _PAYLOAD, key, unprotected={COSEHeaders.PARTIAL_IV: partial}, **kwargs
        )
        assert cbor2.loads(encoded_full).value[2] == cbor2.loads(encoded_partial).value[2]
        assert cose.decode(encoded_partial, key, **kwargs) == _PAYLOAD

    def test_partial_iv_with_multi_recipient_direct(self, cose):
        key = _key(kid=b"shared")
        recipient = Recipient.new(
            unprotected={COSEHeaders.ALG: COSEAlgs.DIRECT, COSEHeaders.KID: b"shared"}
        )
        encoded = cose.encode_and_encrypt(
            _PAYLOAD,
            key,
            unprotected={COSEHeaders.PARTIAL_IV: _PARTIAL_IV_12},
            recipients=[recipient],
        )
        assert cbor2.loads(encoded).tag == 96
        assert cose.decode(encoded, key) == _PAYLOAD

    def test_partial_iv_with_two_recipients_key_wrap(self, cose):
        wrap_key_one = COSEKey.from_symmetric_key(bytes(range(16)), alg="A128KW", kid=b"w1")
        wrap_key_two = COSEKey.from_symmetric_key(bytes(range(16, 32)), alg="A128KW", kid=b"w2")
        cek = _key(kid=b"")  # CEK with the Base IV.
        recipients = [
            Recipient.new(
                unprotected={COSEHeaders.ALG: COSEAlgs.A128KW, COSEHeaders.KID: b"w1"},
                sender_key=wrap_key_one,
            ),
            Recipient.new(
                unprotected={COSEHeaders.ALG: COSEAlgs.A128KW, COSEHeaders.KID: b"w2"},
                sender_key=wrap_key_two,
            ),
        ]
        encoded = cose.encode_and_encrypt(
            _PAYLOAD, cek, unprotected={COSEHeaders.PARTIAL_IV: _PARTIAL_IV_12}, recipients=recipients
        )
        # A wrapped CEK rebuilt on decode carries no Base IV, so Partial IV
        # cannot be resolved without out-of-band Base IV provisioning.
        with pytest.raises(ValueError) as err:
            cose.decode(encoded, [wrap_key_one, wrap_key_two])
        assert "Base IV" in str(err.value)
        # The same recipients decode a full-IV message because no Base IV is needed.
        encoded_full = cose.encode_and_encrypt(
            _PAYLOAD, cek, unprotected={COSEHeaders.IV: _FULL_IV_12}, recipients=recipients
        )
        assert cose.decode(encoded_full, [wrap_key_one, wrap_key_two]) == _PAYLOAD

    def test_missing_base_iv_raises_on_encode(self, cose):
        key = _key(base_iv=None)
        with pytest.raises(ValueError) as err:
            cose.encode_and_encrypt(_PAYLOAD, key, unprotected={COSEHeaders.PARTIAL_IV: _PARTIAL_IV_12})
        assert "Base IV" in str(err.value)

    def test_missing_base_iv_raises_on_decode(self, cose):
        with_base = _key()
        encoded = cose.encode_and_encrypt(
            _PAYLOAD, with_base, unprotected={COSEHeaders.PARTIAL_IV: _PARTIAL_IV_12}
        )
        without_base = _key(base_iv=None)
        with pytest.raises(ValueError) as err:
            cose.decode(encoded, without_base)
        assert "Base IV" in str(err.value)

    def test_partial_iv_longer_than_base_iv_raises(self, cose):
        key = _key()
        assert len(_BASE_IV_12) == 12
        with pytest.raises(ValueError) as err:
            key.build_nonce(partial_iv=b"\x00" * 13)
        assert "Partial IV must not be longer than the Base IV." in str(err.value)
        with pytest.raises(ValueError):
            cose.encode_and_encrypt(_PAYLOAD, key, unprotected={COSEHeaders.PARTIAL_IV: b"\x00" * 13})

    def test_base_iv_length_mismatch_raises(self):
        key = _key(base_iv=bytes(range(7)))  # A128GCM requires a 12-byte nonce.
        with pytest.raises(ValueError) as err:
            key.build_nonce(partial_iv=b"\x01")
        assert "Base IV should be 12 bytes" in str(err.value)

    def test_iv_and_partial_iv_together_rejected(self, cose):
        key = _key()
        with pytest.raises(ValueError) as err:
            cose.encode_and_encrypt(
                _PAYLOAD,
                key,
                unprotected={COSEHeaders.IV: _FULL_IV_12, COSEHeaders.PARTIAL_IV: _PARTIAL_IV_12},
            )
        assert "IV and Partial IV must not both be present" in str(err.value)
        with pytest.raises(ValueError) as err:
            cose.encode_and_encrypt(
                _PAYLOAD,
                key,
                protected={COSEHeaders.IV: _FULL_IV_12},
                unprotected={COSEHeaders.PARTIAL_IV: _PARTIAL_IV_12},
            )
        assert "IV and Partial IV must not both be present" in str(err.value)

    def test_no_iv_still_auto_generates_full_nonce(self, cose):
        # Without any IV header the existing random-full-IV behavior is retained.
        key = _key()
        encoded = cose.encode_and_encrypt(_PAYLOAD, key)
        headers = cbor2.loads(encoded).value[1]
        assert COSEHeaders.IV in headers
        assert len(headers[COSEHeaders.IV]) == 12
        assert cose.decode(encoded, key) == _PAYLOAD

    def test_build_nonce_requires_an_iv(self):
        key = _key()
        with pytest.raises(ValueError) as err:
            key.build_nonce()
        assert "IV or Partial IV should be set." in str(err.value)

    def test_build_nonce_full_iv_ignores_base_iv(self):
        key = _key()
        assert key.build_nonce(iv=_FULL_IV_12) == _FULL_IV_12

    def test_decode_rejects_message_with_both_ivs(self, cose):
        # The encoder can never produce such a message, so craft the CBOR.
        malformed = cbor2.dumps(cbor2.CBORTag(16, [b"", {5: bytes(12), 6: b"\x01\x02"}, b"ciphertext"]))
        with pytest.raises(ValueError) as err:
            cose.decode(malformed, _key())
        assert "IV and Partial IV must not both be present" in str(err.value)

    def test_decode_rejects_non_bstr_partial_iv(self, cose):
        malformed = cbor2.dumps(cbor2.CBORTag(16, [b"", {6: "not-bstr"}, b"ciphertext"]))
        with pytest.raises(ValueError) as err:
            cose.decode(malformed, _key())
        assert "IV and Partial IV must be bstr." in str(err.value)
