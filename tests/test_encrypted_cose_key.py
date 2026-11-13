from secrets import token_bytes

import cbor2
import pytest

from cwt import COSE, COSEKey, DecodeError, EncryptedCOSEKey, VerifyError
from cwt.algs.symmetric import AESGCMKey
from cwt.enums import COSEAlgs, COSEKeyOps

PURPOSE = "cnf/eck"
RECIPIENT = "presenter-01"


class NoNonceKey(AESGCMKey):
    """An AEAD key whose nonce generation is intentionally unsupported."""

    def generate_nonce(self):
        raise NotImplementedError


class TestEncryptedCOSEKey:
    """
    Tests for EncryptedCOSEKey.
    """

    @pytest.fixture
    def enc_key(self):
        # The wrapping key: its permissions are content-encryption operations.
        return COSEKey.from_symmetric_key(
            b"a-client-secret-of-cwt-recipient",
            alg="ChaCha20/Poly1305",
            kid="recipient-01",
        )

    @pytest.fixture
    def pop_key(self):
        # The wrapped key: its permissions are MAC operations, distinct from
        # the encrypt/decrypt permissions of the wrapping key.
        return COSEKey.from_symmetric_key(
            b"a-client-secret-of-cwt-presenter",
            alg="HMAC 256/256",
        )

    @pytest.fixture
    def context(self):
        return EncryptedCOSEKey.build_context(PURPOSE, RECIPIENT)

    def test_encrypted_cose_key_from_cose_key_with_nonce(self, enc_key, pop_key, context):
        nonce = token_bytes(12)
        res = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context, nonce=nonce)
        assert isinstance(res, list)
        assert len(res) == 3
        protected = cbor2.loads(res[0])
        assert protected[1] == 24
        assert isinstance(res[1], dict)
        assert isinstance(res[1][5], bytes) and res[1][5] == nonce

    def test_encrypted_cose_key_from_cose_key_with_invalid_encryption_key(self, context):
        # An HMAC key has MAC permissions only, so it must not wrap another key.
        enc_key = COSEKey.from_symmetric_key(alg="HMAC 256/64")
        pop_key = COSEKey.from_symmetric_key(alg="HMAC 256/256")
        with pytest.raises(ValueError) as err:
            EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
            pytest.fail("from_cose_key should fail.")
        assert "not permitted to encrypt" in str(err.value)

    def test_encrypted_cose_key_from_cose_key_without_nonce_support(self, context):
        # A key that passes the wrapping-permission check but cannot generate a
        # nonce must raise the explicit nonce error rather than fail silently.
        params = COSEKey.from_symmetric_key(alg="A128GCM").to_dict()
        enc_key = NoNonceKey(params)
        pop_key = COSEKey.from_symmetric_key(alg="HMAC 256/256")
        with pytest.raises(ValueError) as err:
            EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
            pytest.fail("from_cose_key should fail.")
        assert "Nonce generation is not supported for the key. Set a nonce explicitly." in str(err.value)

    def test_build_context(self):
        ctx = EncryptedCOSEKey.build_context(PURPOSE, RECIPIENT)
        assert cbor2.loads(ctx) == ["EncryptedCOSEKey/1", PURPOSE.encode(), RECIPIENT.encode()]
        assert EncryptedCOSEKey.build_context(PURPOSE, RECIPIENT) == ctx
        # Different recipient contexts produce different authenticated data.
        assert EncryptedCOSEKey.build_context(PURPOSE, "another") != ctx
        assert EncryptedCOSEKey.build_context("other-purpose", RECIPIENT) != ctx

    @pytest.mark.parametrize("purpose", ["", b"", 1])
    def test_build_context_with_invalid_purpose(self, purpose):
        with pytest.raises(ValueError):
            EncryptedCOSEKey.build_context(purpose, RECIPIENT)

    def test_from_cose_key_requires_context(self, enc_key, pop_key):
        with pytest.raises(ValueError) as err:
            EncryptedCOSEKey.from_cose_key(pop_key, enc_key, b"")
            pytest.fail("from_cose_key should fail.")
        assert "context should be a non-empty bytes" in str(err.value)

    def test_to_cose_key_without_context_requires_explicit_legacy(self, enc_key, pop_key, context):
        envelope = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
        with pytest.raises(ValueError) as err:
            EncryptedCOSEKey.to_cose_key(envelope, enc_key)
            pytest.fail("to_cose_key should fail.")
        assert "context is required" in str(err.value)

    def test_correct_context_recovers_original_key(self, enc_key, pop_key, context):
        envelope = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
        recovered = EncryptedCOSEKey.to_cose_key(envelope, enc_key, context=context)
        assert recovered.kty == pop_key.kty
        assert recovered.alg == pop_key.alg
        assert recovered.key == pop_key.key
        assert recovered.key_ops == pop_key.key_ops

    def test_different_purpose_is_rejected(self, enc_key, pop_key, context):
        envelope = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
        other_context = EncryptedCOSEKey.build_context("another-business-link", RECIPIENT)
        with pytest.raises(DecodeError):
            EncryptedCOSEKey.to_cose_key(envelope, enc_key, context=other_context)
            pytest.fail("to_cose_key should reject an envelope moved to another protocol purpose.")

    def test_different_recipient_context_is_rejected(self, enc_key, pop_key, context):
        envelope = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
        other_context = EncryptedCOSEKey.build_context(PURPOSE, "attacker-context")
        with pytest.raises(DecodeError):
            EncryptedCOSEKey.to_cose_key(envelope, enc_key, context=other_context)
            pytest.fail("to_cose_key should reject an envelope moved to another recipient context.")

    def test_context_failure_does_not_fall_back_to_legacy(self, enc_key, pop_key, context):
        envelope = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
        # A wrong context must fail even if legacy mode were attempted, and the
        # caller must never be silently downgraded to the empty-AAD path.
        with pytest.raises(DecodeError):
            EncryptedCOSEKey.to_cose_key(envelope, enc_key, context=EncryptedCOSEKey.build_context(PURPOSE, "wrong"))
        with pytest.raises(DecodeError):
            EncryptedCOSEKey.to_cose_key(envelope, enc_key, legacy=True)

    def test_legacy_envelope_requires_explicit_opt_in(self, enc_key, pop_key, context):
        # An old envelope is produced without an authenticated context.
        nonce = enc_key.generate_nonce()
        protected = {1: enc_key.alg}
        unprotected = {4: enc_key.kid, 5: nonce}
        legacy_envelope = COSE().encode_and_encrypt(
            cbor2.dumps(pop_key.to_dict()),
            enc_key,
            protected,
            unprotected,
            out="cbor2/CBORTag",
        ).value

        # The context-bound path must not accept a legacy envelope.
        with pytest.raises(DecodeError):
            EncryptedCOSEKey.to_cose_key(legacy_envelope, enc_key, context=context)

        # It can only be opened through the explicit legacy opt-in.
        recovered = EncryptedCOSEKey.to_cose_key(legacy_envelope, enc_key, legacy=True)
        assert recovered.key == pop_key.key
        assert recovered.alg == pop_key.alg

    def test_legacy_rejects_context_combination(self, enc_key, pop_key):
        envelope = EncryptedCOSEKey.from_cose_key(
            pop_key, enc_key, EncryptedCOSEKey.build_context(PURPOSE, RECIPIENT)
        )
        with pytest.raises(ValueError) as err:
            EncryptedCOSEKey.to_cose_key(
                envelope,
                enc_key,
                context=EncryptedCOSEKey.build_context(PURPOSE, RECIPIENT),
                legacy=True,
            )
            pytest.fail("to_cose_key should fail.")
        assert "context must not be set when legacy is True" in str(err.value)

    def test_legacy_still_enforces_key_policy(self, enc_key, pop_key):
        nonce = enc_key.generate_nonce()
        legacy_envelope = COSE().encode_and_encrypt(
            cbor2.dumps(pop_key.to_dict()),
            enc_key,
            {1: enc_key.alg},
            {4: enc_key.kid, 5: nonce},
            out="cbor2/CBORTag",
        ).value
        with pytest.raises(VerifyError):
            EncryptedCOSEKey.to_cose_key(legacy_envelope, enc_key, alg="A128GCM", legacy=True)

    def test_alg_policy_mismatch_is_rejected(self, enc_key, pop_key, context):
        envelope = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
        with pytest.raises(VerifyError):
            EncryptedCOSEKey.to_cose_key(envelope, enc_key, context=context, alg="A128GCM")
        with pytest.raises(VerifyError):
            EncryptedCOSEKey.to_cose_key(envelope, enc_key, context=context, alg=COSEAlgs.A128GCM)

    def test_alg_policy_match_accepted(self, enc_key, pop_key, context):
        envelope = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
        recovered = EncryptedCOSEKey.to_cose_key(envelope, enc_key, context=context, alg="HMAC 256/256")
        assert recovered.key == pop_key.key
        recovered = EncryptedCOSEKey.to_cose_key(envelope, enc_key, context=context, alg=COSEAlgs.HS256)
        assert recovered.alg == COSEAlgs.HS256

    def test_unknown_alg_policy_rejected(self, enc_key, pop_key, context):
        envelope = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
        with pytest.raises(ValueError):
            EncryptedCOSEKey.to_cose_key(envelope, enc_key, context=context, alg="not-an-alg")

    def test_key_ops_policy_mismatch_is_rejected(self, enc_key, pop_key, context):
        envelope = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
        # The wrapped key is a MAC key; it must never satisfy content-encryption
        # (i.e. the wrapping key's) permissions.
        with pytest.raises(VerifyError):
            EncryptedCOSEKey.to_cose_key(envelope, enc_key, context=context, key_ops=["encrypt"])
        with pytest.raises(VerifyError):
            EncryptedCOSEKey.to_cose_key(envelope, enc_key, context=context, key_ops=[COSEKeyOps.DECRYPT])

    def test_key_ops_policy_match_accepted(self, enc_key, pop_key, context):
        envelope = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
        recovered = EncryptedCOSEKey.to_cose_key(
            envelope,
            enc_key,
            context=context,
            key_ops=["MAC create", "MAC verify"],
        )
        assert recovered.key == pop_key.key
        recovered = EncryptedCOSEKey.to_cose_key(
            envelope,
            enc_key,
            context=context,
            key_ops=[COSEKeyOps.MAC_CREATE],
        )
        assert COSEKeyOps.MAC_CREATE in recovered.key_ops

    def test_wrapping_and_wrapped_permissions_are_distinct(self, enc_key, pop_key, context):
        # The wrapping key is permitted to encrypt/decrypt, not to MAC.
        assert COSEKeyOps.ENCRYPT in enc_key.key_ops
        assert COSEKeyOps.DECRYPT in enc_key.key_ops
        assert COSEKeyOps.MAC_CREATE not in enc_key.key_ops
        # The wrapped key is permitted to MAC, not to encrypt/decrypt.
        assert COSEKeyOps.MAC_CREATE in pop_key.key_ops
        assert COSEKeyOps.MAC_VERIFY in pop_key.key_ops
        assert COSEKeyOps.ENCRYPT not in pop_key.key_ops

        envelope = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
        # A policy expressed in the wrapping key's permissions fails against
        # the wrapped key, and vice versa.
        with pytest.raises(VerifyError):
            EncryptedCOSEKey.to_cose_key(envelope, enc_key, context=context, key_ops=[COSEKeyOps.ENCRYPT])
        recovered = EncryptedCOSEKey.to_cose_key(
            envelope, enc_key, context=context, key_ops=[COSEKeyOps.MAC_CREATE, COSEKeyOps.MAC_VERIFY]
        )
        assert recovered.key_ops == pop_key.key_ops

    def test_encryption_key_must_have_encrypt_permission(self, pop_key, context):
        wrap_only = COSEKey.from_symmetric_key(alg="A128GCM", key_ops=["encrypt"])
        assert EncryptedCOSEKey.from_cose_key(pop_key, wrap_only, context)
        decrypt_only = COSEKey.from_symmetric_key(alg="A128GCM", key_ops=["decrypt"])
        with pytest.raises(ValueError) as err:
            EncryptedCOSEKey.from_cose_key(pop_key, decrypt_only, context)
            pytest.fail("from_cose_key should fail.")
        assert "not permitted to encrypt" in str(err.value)

    def test_encryption_key_must_have_decrypt_permission(self, enc_key, pop_key, context):
        envelope = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
        encrypt_only = COSEKey.from_symmetric_key(
            b"a-client-secret-of-cwt-recipient",
            alg="ChaCha20/Poly1305",
            kid="recipient-01",
            key_ops=["encrypt"],
        )
        with pytest.raises(ValueError) as err:
            EncryptedCOSEKey.to_cose_key(envelope, encrypt_only, context=context)
            pytest.fail("to_cose_key should fail.")
        assert "not permitted to decrypt" in str(err.value)

    def test_key_ops_policy_requires_non_empty_list(self, enc_key, pop_key, context):
        envelope = EncryptedCOSEKey.from_cose_key(pop_key, enc_key, context)
        with pytest.raises(ValueError):
            EncryptedCOSEKey.to_cose_key(envelope, enc_key, context=context, key_ops=[])

    def test_round_trip_with_policy_and_aesgcm(self):
        enc_key = COSEKey.from_symmetric_key(alg="A128GCM", kid="recipient-01")
        wrapped = COSEKey.from_symmetric_key(alg="A128GCM", key_ops=["encrypt", "decrypt"])
        context = EncryptedCOSEKey.build_context("key-distribution", "device-42")
        envelope = EncryptedCOSEKey.from_cose_key(wrapped, enc_key, context)
        recovered = EncryptedCOSEKey.to_cose_key(
            envelope,
            enc_key,
            context=context,
            alg="A128GCM",
            key_ops=["encrypt", "decrypt"],
        )
        assert recovered.key == wrapped.key
        assert recovered.alg == wrapped.alg

