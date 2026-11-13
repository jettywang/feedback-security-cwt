# pylint: disable=R0201, R0904, W0621
# R0201: Method could be a function
# R0904: Too many public methods
# W0621: Redefined outer name

"""
Offline context-binding cross-checks for COSE-HPKE per draft-ietf-cose-hpke-23.

These tests pin down which layer of each COSE-HPKE mode authenticates each
context input, using the existing Appendix C test vectors
(tests/vectors/testvectors.txt):

  Integrated Encryption (COSE_Encrypt0, HPKE-0..7):
    - HPKE ``info``  = ``hpke_info`` (application-supplied, default h'')
    - HPKE ``aad``   = Enc_structure = ["Encrypt0", protected, external_aad]
    - ``psk_id``     = protected header (-5), also bound via Enc_structure
    - ``extra_info`` / ``hpke_aad`` belong to Key Encryption mode only and
      MUST NOT affect this mode.

  Key Encryption (COSE_Encrypt + HPKE-N-KE recipient):
    - HPKE ``info``  = Recipient_structure =
      ["HPKE Recipient", next_layer_alg, recipient_protected_header, extra_info]
      (binds the content-layer algorithm, the recipient protected header and
      the application-supplied ``extra_info``)
    - HPKE ``aad``   = ``hpke_aad`` (application-supplied recipient aad)
    - ``external_aad`` is authenticated ONLY by the content layer through
      Enc_structure = ["Encrypt", protected, external_aad]
    - ``psk_id``     = recipient protected header (-5), bound via
      Recipient_structure
    - ``hpke_info`` belongs to Integrated Encryption only and MUST NOT affect
      this mode.

Each negative test mutates exactly one context input and asserts at which
layer authentication fails:

  - "Failed to open."    = the HPKE layer (the only layer of COSE_Encrypt0,
                           or the recipient/key-encryption layer of
                           COSE_Encrypt)
  - "Failed to decrypt." = the content-encryption layer of COSE_Encrypt
                           (reached only after the recipient layer has
                           already succeeded)

The expected Enc_structure/Recipient_structure byte strings are constructed
independently of the cwt implementation (hand-built with cbor2 directly from
the structures defined in RFC 9052 / draft-ietf-cose-hpke-23 and pinned
against hard-coded hex constants), and the vector ciphertexts are opened with
pyhpke/cryptography directly, not via COSE.encode()/COSE.decode().

Failure output MUST NOT leak key material: every negative test asserts that
neither the PSK, the psk_id, the recipient private key nor the derived CEK
appears anywhere in the exception chain.
"""

import cbor2
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

from cwt import COSE, COSEKey, DecodeError

from .test_cose_hpke_vectors import _E0, _E0_PSK, _KE, _KE_PSK, PSK, PSK_ID

PLAINTEXT = b"hpke test payload"

# Error messages that identify the layer at which authentication failed.
HPKE_LAYER_ERROR = "Failed to open."  # HPKE open(): Encrypt0 itself, or the KE recipient layer
CONTENT_LAYER_ERROR = "Failed to decrypt."  # CEK content-encryption layer of COSE_Encrypt

# HPKE cipher suites from draft-ietf-cose-hpke-23 Table 1, keyed by the base
# (Integrated Encryption) algorithm ID: (KEM id, KDF id, AEAD id).
_HPKE_SUITES = {
    35: (16, 1, 1),  # HPKE-0: DHKEM(P-256) + HKDF-SHA256 + AES-128-GCM
    37: (17, 2, 2),  # HPKE-1: DHKEM(P-384) + HKDF-SHA384 + AES-256-GCM
    39: (18, 3, 2),  # HPKE-2: DHKEM(P-521) + HKDF-SHA512 + AES-256-GCM
    41: (32, 1, 1),  # HPKE-3: DHKEM(X25519) + HKDF-SHA256 + AES-128-GCM
    42: (32, 1, 3),  # HPKE-4: DHKEM(X25519) + HKDF-SHA256 + ChaCha20Poly1305
    43: (33, 3, 2),  # HPKE-5: DHKEM(X448) + HKDF-SHA512 + AES-256-GCM
    44: (33, 3, 3),  # HPKE-6: DHKEM(X448) + HKDF-SHA512 + ChaCha20Poly1305
    45: (16, 1, 2),  # HPKE-7: DHKEM(P-256) + HKDF-SHA256 + AES-256-GCM
}

# Key Encryption algorithm IDs mapped to their base (Integrated) counterpart.
_KE_TO_BASE = {46: 35, 47: 37, 48: 39, 49: 41, 50: 42, 51: 43, 52: 44, 53: 45}

# Content-encryption algorithms (COSE alg IDs) to AEAD constructors.
_CONTENT_AEAD = {1: AESGCM, 2: AESGCM, 3: AESGCM, 24: ChaCha20Poly1305}

# Expected context structures, constructed by hand from RFC 9052 Section 5.3
# and draft-ietf-cose-hpke-23 Section 4.2 for the HPKE-0 vectors with
# external aad/info, and pinned here as hex so the structures under test are
# not produced by the implementation being tested.
# Enc_structure for "HPKE-0-Encrypt0-external-aad-external-info":
#   ["Encrypt0", h'A1011823', h'65787465726E616C2D616164']  (= external_aad)
EXPECTED_E0_ENC_STRUCTURE = bytes.fromhex("8368456e63727970743044a10118234c65787465726e616c2d616164")
# Recipient_structure for "HPKE-0-KE-external-aad-external-info-external-hpke-aad":
#   ["HPKE Recipient", 1, h'A101182E', h'65787465726E616C2D696E666F']  (= extra_info)
EXPECTED_KE_RECIPIENT_STRUCTURE = bytes.fromhex("846e48504b4520526563697069656e740144a101182e4d65787465726e616c2d696e666f")
# Enc_structure for the content layer of the same KE vector:
#   ["Encrypt", h'A10101', h'65787465726E616C2D616164']
EXPECTED_KE_ENC_STRUCTURE = bytes.fromhex("8367456e637279707443a101014c65787465726e616c2d616164")


def _vector(vectors, label):
    for v in vectors:
        if label in v:
            return v
    raise ValueError(f"vector not found: {label}")


def _cose_key(key_hex):
    return COSEKey.new(cbor2.loads(bytes.fromhex(key_hex)))


def _private_key_bytes(key_hex):
    """Extract the private key parameter (-4) from a COSE_Key, for leak checks."""
    return cbor2.loads(bytes.fromhex(key_hex))[-4]


def _kem_key(key_hex):
    return KEMKey.from_pyca_cryptography_key(_cose_key(key_hex).key)


def _suite(alg):
    kem, kdf, aead = _HPKE_SUITES[alg]
    return CipherSuite.new(KEMId(kem), KDFId(kdf), AEADId(aead))


def _independent_open_encrypt0(key_hex, ct_hex, external_aad, hpke_info, psk=None):
    """Open a COSE_Encrypt0 HPKE vector without using cwt's COSE/HPKE classes.

    Builds Enc_structure by hand and uses pyhpke directly. Returns the
    plaintext and the Enc_structure that was authenticated.
    """
    msg = cbor2.loads(bytes.fromhex(ct_hex))
    assert msg.tag == 16
    b_protected, unprotected, ciphertext = msg.value
    protected = cbor2.loads(b_protected)
    enc_structure = cbor2.dumps(["Encrypt0", b_protected, external_aad])
    psk_args = {"psk": psk, "psk_id": protected[-5]} if psk is not None else {}
    ctx = _suite(protected[1]).create_recipient_context(unprotected[-4], _kem_key(key_hex), info=hpke_info, **psk_args)
    return ctx.open(ciphertext, aad=enc_structure), enc_structure


def _independent_open_ke(key_hex, ct_hex, external_aad, extra_info, hpke_aad, psk=None):
    """Open a COSE_Encrypt HPKE-KE vector without using cwt's COSE/HPKE classes.

    Builds Recipient_structure and Enc_structure by hand, unwraps the CEK with
    pyhpke directly and decrypts the content layer with cryptography directly.
    Returns the plaintext, Recipient_structure, Enc_structure and the CEK.
    """
    msg = cbor2.loads(bytes.fromhex(ct_hex))
    assert msg.tag == 96
    b_protected, unprotected, ciphertext, recipients = msg.value
    content_alg = cbor2.loads(b_protected)[1]
    rec_b_protected, rec_unprotected, rec_ciphertext = recipients[0]
    rec_alg = cbor2.loads(rec_b_protected)[1]
    recipient_structure = cbor2.dumps(["HPKE Recipient", content_alg, rec_b_protected, extra_info])
    psk_args = {"psk": psk, "psk_id": cbor2.loads(rec_b_protected)[-5]} if psk is not None else {}
    ctx = _suite(_KE_TO_BASE[rec_alg]).create_recipient_context(
        rec_unprotected[-4], _kem_key(key_hex), info=recipient_structure, **psk_args
    )
    cek = ctx.open(rec_ciphertext, aad=hpke_aad)
    enc_structure = cbor2.dumps(["Encrypt", b_protected, external_aad])
    plaintext = _CONTENT_AEAD[content_alg](cek).decrypt(unprotected[5], ciphertext, enc_structure)
    return plaintext, recipient_structure, enc_structure, cek


def _tamper_encrypt0_protected(ct_hex, mutate):
    """Re-encode a COSE_Encrypt0 vector with a mutated protected header."""
    msg = cbor2.loads(bytes.fromhex(ct_hex))
    b_protected, unprotected, ciphertext = msg.value
    protected = cbor2.loads(b_protected)
    mutate(protected)
    return cbor2.dumps(cbor2.CBORTag(16, [cbor2.dumps(protected), unprotected, ciphertext]))


def _tamper_encrypt_protected(ct_hex, mutate):
    """Re-encode a COSE_Encrypt vector with a mutated outer protected header."""
    msg = cbor2.loads(bytes.fromhex(ct_hex))
    b_protected, unprotected, ciphertext, recipients = msg.value
    protected = cbor2.loads(b_protected)
    mutate(protected)
    return cbor2.dumps(cbor2.CBORTag(96, [cbor2.dumps(protected), unprotected, ciphertext, recipients]))


def _tamper_recipient_protected(ct_hex, mutate):
    """Re-encode a COSE_Encrypt vector with a mutated recipient protected header."""
    msg = cbor2.loads(bytes.fromhex(ct_hex))
    b_protected, unprotected, ciphertext, recipients = msg.value
    rec_b_protected, rec_unprotected, rec_ciphertext = recipients[0]
    protected = cbor2.loads(rec_b_protected)
    mutate(protected)
    tampered_recipient = [cbor2.dumps(protected), rec_unprotected, rec_ciphertext]
    return cbor2.dumps(cbor2.CBORTag(96, [b_protected, unprotected, ciphertext, [tampered_recipient]]))


def _assert_no_secret_leak(err, secrets):
    """Assert no key material appears anywhere in the exception chain."""
    messages = []
    exc = err
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        messages.append(str(exc))
        messages.append(repr(exc))
        exc = exc.__cause__ if exc.__cause__ is not None else exc.__context__
    log = "\n".join(messages)
    for secret in secrets:
        assert secret.hex() not in log, "failure log leaks key material (hex)"
        assert secret.decode("latin-1") not in log, "failure log leaks key material (raw)"


class TestIndependentStructures:
    """Expected context structures and vector openings, constructed independently of cwt."""

    def test_expected_structure_constants(self):
        """Hand-built structures for the HPKE-0 vectors match the pinned hex constants."""
        key_hex, ct_hex, external_aad, hpke_info, _ = _vector(_E0, "HPKE-0-Encrypt0-external-aad-external-info")
        _, enc_structure = _independent_open_encrypt0(key_hex, ct_hex, external_aad, hpke_info)
        assert enc_structure == EXPECTED_E0_ENC_STRUCTURE

        key_hex, ct_hex, external_aad, extra_info, hpke_aad, _ = _vector(
            _KE, "HPKE-0-KE-external-aad-external-info-external-hpke-aad"
        )
        _, recipient_structure, enc_structure, _ = _independent_open_ke(key_hex, ct_hex, external_aad, extra_info, hpke_aad)
        assert recipient_structure == EXPECTED_KE_RECIPIENT_STRUCTURE
        assert enc_structure == EXPECTED_KE_ENC_STRUCTURE

    @pytest.mark.parametrize(
        "key_hex, ct_hex, external_aad, hpke_info",
        [v[:4] for v in _E0],
        ids=[v[4] for v in _E0],
    )
    def test_encrypt0_vectors_opened_without_cwt(self, key_hex, ct_hex, external_aad, hpke_info):
        plaintext, _ = _independent_open_encrypt0(key_hex, ct_hex, external_aad, hpke_info)
        assert plaintext == PLAINTEXT

    @pytest.mark.parametrize(
        "key_hex, ct_hex, external_aad, extra_info, hpke_aad",
        [v[:5] for v in _KE],
        ids=[v[5] for v in _KE],
    )
    def test_ke_vectors_opened_without_cwt(self, key_hex, ct_hex, external_aad, extra_info, hpke_aad):
        plaintext, _, _, _ = _independent_open_ke(key_hex, ct_hex, external_aad, extra_info, hpke_aad)
        assert plaintext == PLAINTEXT

    @pytest.mark.parametrize(
        "key_hex, ct_hex, external_aad, hpke_info",
        [v[:4] for v in _E0_PSK],
        ids=[v[4] for v in _E0_PSK],
    )
    def test_encrypt0_psk_vectors_opened_without_cwt(self, key_hex, ct_hex, external_aad, hpke_info):
        plaintext, _ = _independent_open_encrypt0(key_hex, ct_hex, external_aad, hpke_info, psk=PSK)
        assert plaintext == PLAINTEXT

    @pytest.mark.parametrize(
        "key_hex, ct_hex, external_aad, extra_info, hpke_aad",
        [v[:5] for v in _KE_PSK],
        ids=[v[5] for v in _KE_PSK],
    )
    def test_ke_psk_vectors_opened_without_cwt(self, key_hex, ct_hex, external_aad, extra_info, hpke_aad):
        plaintext, _, _, _ = _independent_open_ke(key_hex, ct_hex, external_aad, extra_info, hpke_aad, psk=PSK)
        assert plaintext == PLAINTEXT


class TestIntegratedContextBinding:
    """Integrated Encryption: every context input is authenticated at the HPKE
    layer itself (the only layer of COSE_Encrypt0)."""

    @pytest.fixture(params=[v for v in _E0 if v[4].endswith("external-aad-external-info")], ids=lambda v: v[4])
    def vector(self, request):
        key_hex, ct_hex, external_aad, hpke_info, _ = request.param
        return key_hex, ct_hex, external_aad, hpke_info

    def test_baseline(self, vector):
        key_hex, ct_hex, external_aad, hpke_info = vector
        res = COSE.new().decode(bytes.fromhex(ct_hex), _cose_key(key_hex), external_aad=external_aad, hpke_info=hpke_info)
        assert res == PLAINTEXT

    def test_wrong_external_aad_fails_at_hpke_layer(self, vector):
        """external_aad is bound via Enc_structure -> HPKE open() must fail."""
        key_hex, ct_hex, _, hpke_info = vector
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(
                bytes.fromhex(ct_hex), _cose_key(key_hex), external_aad=b"wrong-external-aad", hpke_info=hpke_info
            )
        assert HPKE_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [_private_key_bytes(key_hex)])

    def test_wrong_hpke_info_fails_at_hpke_layer(self, vector):
        """hpke_info is the HPKE info parameter -> HPKE open() must fail."""
        key_hex, ct_hex, external_aad, _ = vector
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(
                bytes.fromhex(ct_hex), _cose_key(key_hex), external_aad=external_aad, hpke_info=b"wrong-hpke-info"
            )
        assert HPKE_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [_private_key_bytes(key_hex)])

    def test_extra_info_is_ignored(self, vector):
        """extra_info belongs to Key Encryption mode only; it MUST NOT affect Encrypt0."""
        key_hex, ct_hex, external_aad, hpke_info = vector
        res = COSE.new().decode(
            bytes.fromhex(ct_hex), _cose_key(key_hex), external_aad=external_aad, hpke_info=hpke_info, extra_info=b"ignored"
        )
        assert res == PLAINTEXT

    def test_hpke_aad_is_ignored(self, vector):
        """hpke_aad (recipient aad) belongs to Key Encryption mode only; it MUST NOT affect Encrypt0."""
        key_hex, ct_hex, external_aad, hpke_info = vector
        res = COSE.new().decode(
            bytes.fromhex(ct_hex), _cose_key(key_hex), external_aad=external_aad, hpke_info=hpke_info, hpke_aad=b"ignored"
        )
        assert res == PLAINTEXT


class TestIntegratedProtectedHeaderBinding:
    """Integrated Encryption: the protected header (incl. the algorithm) is
    bound via Enc_structure -> any change must fail at the HPKE layer."""

    @pytest.fixture
    def vector(self):
        return _vector(_E0, "HPKE-0-Encrypt0-external-aad-external-info")

    def test_alg_change_in_protected_fails_at_hpke_layer(self, vector):
        """Changing HPKE-0 (35) to HPKE-7 (45) in protected changes both the
        suite and the Enc_structure -> HPKE open() must fail."""
        key_hex, ct_hex, external_aad, hpke_info, _ = vector
        tampered = _tamper_encrypt0_protected(ct_hex, lambda p: p.__setitem__(1, 45))
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(tampered, _cose_key(key_hex), external_aad=external_aad, hpke_info=hpke_info)
        assert HPKE_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [_private_key_bytes(key_hex)])

    def test_added_header_in_protected_fails_at_hpke_layer(self, vector):
        """Adding an unrelated header (cty) to protected changes the
        Enc_structure -> HPKE open() must fail."""
        key_hex, ct_hex, external_aad, hpke_info, _ = vector
        tampered = _tamper_encrypt0_protected(ct_hex, lambda p: p.__setitem__(3, b"text/plain"))
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(tampered, _cose_key(key_hex), external_aad=external_aad, hpke_info=hpke_info)
        assert HPKE_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [_private_key_bytes(key_hex)])


class TestIntegratedPSKBinding:
    """Integrated Encryption with PSK: psk_id lives in the protected header and
    both psk and psk_id are authenticated at the HPKE layer."""

    @pytest.fixture
    def vector(self):
        return _vector(_E0_PSK, "HPKE-0-Encrypt0-PSK-external-aad-external-info")

    def test_baseline(self, vector):
        key_hex, ct_hex, external_aad, hpke_info, _ = vector
        res = COSE.new().decode(
            bytes.fromhex(ct_hex), _cose_key(key_hex), external_aad=external_aad, hpke_info=hpke_info, hpke_psk=PSK
        )
        assert res == PLAINTEXT

    def test_missing_psk_rejected_before_decryption(self, vector):
        """psk_id present but no hpke_psk -> rejected by input validation,
        before any HPKE operation."""
        key_hex, ct_hex, external_aad, hpke_info, _ = vector
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(bytes.fromhex(ct_hex), _cose_key(key_hex), external_aad=external_aad, hpke_info=hpke_info)
        assert "hpke_psk is required when psk_id (-5) is provided." in str(err.value)
        _assert_no_secret_leak(err.value, [PSK_ID, _private_key_bytes(key_hex)])

    def test_wrong_psk_fails_at_hpke_layer(self, vector):
        key_hex, ct_hex, external_aad, hpke_info, _ = vector
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(
                bytes.fromhex(ct_hex),
                _cose_key(key_hex),
                external_aad=external_aad,
                hpke_info=hpke_info,
                hpke_psk=b"\x00" * 32,
            )
        assert HPKE_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [PSK, PSK_ID, _private_key_bytes(key_hex)])

    def test_tampered_psk_id_fails_at_hpke_layer(self, vector):
        """psk_id is bound both as the HPKE psk_id and via Enc_structure ->
        HPKE open() must fail."""
        key_hex, ct_hex, external_aad, hpke_info, _ = vector
        tampered = _tamper_encrypt0_protected(ct_hex, lambda p: p.__setitem__(-5, b"tampered-psk-id"))
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(tampered, _cose_key(key_hex), external_aad=external_aad, hpke_info=hpke_info, hpke_psk=PSK)
        assert HPKE_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [PSK, PSK_ID, _private_key_bytes(key_hex)])


class TestKeyEncryptionContextBinding:
    """Key Encryption: hpke_aad, extra_info, the content-layer algorithm and
    the recipient protected header are authenticated at the recipient (HPKE)
    layer; external_aad and the outer protected header are authenticated at
    the content-encryption layer."""

    @pytest.fixture(
        params=[v for v in _KE if v[5].endswith("external-aad-external-info-external-hpke-aad")], ids=lambda v: v[5]
    )
    def vector(self, request):
        key_hex, ct_hex, external_aad, extra_info, hpke_aad, _ = request.param
        return key_hex, ct_hex, external_aad, extra_info, hpke_aad

    def test_baseline(self, vector):
        key_hex, ct_hex, external_aad, extra_info, hpke_aad = vector
        res = COSE.new().decode(
            bytes.fromhex(ct_hex),
            _cose_key(key_hex),
            external_aad=external_aad,
            extra_info=extra_info,
            hpke_aad=hpke_aad,
        )
        assert res == PLAINTEXT

    def test_wrong_hpke_aad_fails_at_recipient_layer(self, vector):
        """hpke_aad is the HPKE aad of the recipient layer -> HPKE open() must
        fail; the content layer is never reached."""
        key_hex, ct_hex, external_aad, extra_info, _ = vector
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(
                bytes.fromhex(ct_hex),
                _cose_key(key_hex),
                external_aad=external_aad,
                extra_info=extra_info,
                hpke_aad=b"wrong-hpke-aad",
            )
        assert HPKE_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [_private_key_bytes(key_hex)])

    def test_wrong_extra_info_fails_at_recipient_layer(self, vector):
        """extra_info is bound via Recipient_structure (HPKE info) -> HPKE
        open() must fail; the content layer is never reached."""
        key_hex, ct_hex, external_aad, _, hpke_aad = vector
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(
                bytes.fromhex(ct_hex),
                _cose_key(key_hex),
                external_aad=external_aad,
                extra_info=b"wrong-extra-info",
                hpke_aad=hpke_aad,
            )
        assert HPKE_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [_private_key_bytes(key_hex)])

    def test_wrong_external_aad_fails_at_content_layer(self, vector):
        """external_aad is NOT part of the HPKE recipient context in Key
        Encryption mode: CEK unwrapping (recipient layer) must succeed and
        authentication must fail only at the content-encryption layer
        (Enc_structure)."""
        key_hex, ct_hex, external_aad, extra_info, hpke_aad = vector
        _, _, _, cek = _independent_open_ke(key_hex, ct_hex, external_aad, extra_info, hpke_aad)
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(
                bytes.fromhex(ct_hex),
                _cose_key(key_hex),
                external_aad=b"wrong-external-aad",
                extra_info=extra_info,
                hpke_aad=hpke_aad,
            )
        assert CONTENT_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [cek, _private_key_bytes(key_hex)])

    def test_hpke_info_is_ignored(self, vector):
        """hpke_info belongs to Integrated Encryption only; in Key Encryption
        mode the HPKE info is the Recipient_structure, so hpke_info MUST NOT
        affect decoding."""
        key_hex, ct_hex, external_aad, extra_info, hpke_aad = vector
        res = COSE.new().decode(
            bytes.fromhex(ct_hex),
            _cose_key(key_hex),
            external_aad=external_aad,
            extra_info=extra_info,
            hpke_aad=hpke_aad,
            hpke_info=b"ignored",
        )
        assert res == PLAINTEXT


class TestKeyEncryptionProtectedHeaderBinding:
    """Key Encryption: the content-layer algorithm is bound at the recipient
    layer (next_layer_alg of Recipient_structure); the outer protected header
    is bound at the content layer (Enc_structure); the recipient protected
    header is bound at the recipient layer (Recipient_structure)."""

    @pytest.fixture
    def vector(self):
        return _vector(_KE, "HPKE-0-KE-external-aad-external-info-external-hpke-aad")

    def test_content_alg_change_fails_at_recipient_layer(self, vector):
        """Changing the content alg (A128GCM -> A256GCM) in the outer protected
        header changes next_layer_alg in Recipient_structure -> HPKE open()
        must fail at the recipient layer."""
        key_hex, ct_hex, external_aad, extra_info, hpke_aad, _ = vector
        tampered = _tamper_encrypt_protected(ct_hex, lambda p: p.__setitem__(1, 3))
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(tampered, _cose_key(key_hex), external_aad=external_aad, extra_info=extra_info, hpke_aad=hpke_aad)
        assert HPKE_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [_private_key_bytes(key_hex)])

    def test_added_header_in_outer_protected_fails_at_content_layer(self, vector):
        """Adding an unrelated header (cty) to the outer protected header
        leaves Recipient_structure untouched (CEK unwrapping succeeds) but
        changes the content-layer Enc_structure -> content decryption must
        fail."""
        key_hex, ct_hex, external_aad, extra_info, hpke_aad, _ = vector
        _, _, _, cek = _independent_open_ke(key_hex, ct_hex, external_aad, extra_info, hpke_aad)
        tampered = _tamper_encrypt_protected(ct_hex, lambda p: p.__setitem__(3, b"text/plain"))
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(tampered, _cose_key(key_hex), external_aad=external_aad, extra_info=extra_info, hpke_aad=hpke_aad)
        assert CONTENT_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [cek, _private_key_bytes(key_hex)])

    def test_added_header_in_recipient_protected_fails_at_recipient_layer(self, vector):
        """Adding a header to the recipient protected header changes
        recipient_protected_header in Recipient_structure -> HPKE open() must
        fail at the recipient layer."""
        key_hex, ct_hex, external_aad, extra_info, hpke_aad, _ = vector
        tampered = _tamper_recipient_protected(ct_hex, lambda p: p.__setitem__(-100, b"extra"))
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(tampered, _cose_key(key_hex), external_aad=external_aad, extra_info=extra_info, hpke_aad=hpke_aad)
        assert HPKE_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [_private_key_bytes(key_hex)])


class TestKeyEncryptionPSKBinding:
    """Key Encryption with PSK: psk_id lives in the recipient protected header
    and both psk and psk_id are authenticated at the recipient (HPKE) layer."""

    @pytest.fixture
    def vector(self):
        return _vector(_KE_PSK, "HPKE-0-KE-PSK-external-aad-external-info-external-hpke-aad")

    def test_baseline(self, vector):
        key_hex, ct_hex, external_aad, extra_info, hpke_aad, _ = vector
        res = COSE.new().decode(
            bytes.fromhex(ct_hex),
            _cose_key(key_hex),
            external_aad=external_aad,
            extra_info=extra_info,
            hpke_aad=hpke_aad,
            hpke_psk=PSK,
        )
        assert res == PLAINTEXT

    def test_missing_psk_rejected_before_decryption(self, vector):
        """psk_id present but no hpke_psk -> rejected by input validation,
        before any HPKE operation."""
        key_hex, ct_hex, external_aad, extra_info, hpke_aad, _ = vector
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(
                bytes.fromhex(ct_hex), _cose_key(key_hex), external_aad=external_aad, extra_info=extra_info, hpke_aad=hpke_aad
            )
        assert "hpke_psk is required when psk_id (-5) is provided." in str(err.value)
        _assert_no_secret_leak(err.value, [PSK_ID, _private_key_bytes(key_hex)])

    def test_wrong_psk_fails_at_recipient_layer(self, vector):
        key_hex, ct_hex, external_aad, extra_info, hpke_aad, _ = vector
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(
                bytes.fromhex(ct_hex),
                _cose_key(key_hex),
                external_aad=external_aad,
                extra_info=extra_info,
                hpke_aad=hpke_aad,
                hpke_psk=b"\x00" * 32,
            )
        assert HPKE_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [PSK, PSK_ID, _private_key_bytes(key_hex)])

    def test_tampered_psk_id_fails_at_recipient_layer(self, vector):
        """psk_id is bound both as the HPKE psk_id and via Recipient_structure
        -> HPKE open() must fail at the recipient layer."""
        key_hex, ct_hex, external_aad, extra_info, hpke_aad, _ = vector
        tampered = _tamper_recipient_protected(ct_hex, lambda p: p.__setitem__(-5, b"tampered-psk-id"))
        with pytest.raises(DecodeError) as err:
            COSE.new().decode(
                tampered,
                _cose_key(key_hex),
                external_aad=external_aad,
                extra_info=extra_info,
                hpke_aad=hpke_aad,
                hpke_psk=PSK,
            )
        assert HPKE_LAYER_ERROR in str(err.value)
        _assert_no_secret_leak(err.value, [PSK, PSK_ID, _private_key_bytes(key_hex)])
