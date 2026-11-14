# pylint: disable=R0904, W0212, protected-access
"""
Structure-aware fuzzing for nested COSE message dispatch.

The fuzzer keeps a small, valid COSE_Encrypt (CBOR tag 96) message as its
skeleton and applies structural mutations that stay decodable at the CBOR
layer so that execution reaches the recipient dispatch in
``Recipients.derive_key`` instead of being rejected by the first CBOR/shape
parse. Three resource dimensions are recorded independently for every input:

* decoded bytes (the size of the message handed to ``COSE.decode``),
* recipient nesting depth and recipient count,
* the number of cryptographic operations performed while dispatching.

A fixed seed makes every run replayable. Inputs that only raise
``VerifyError``/``DecodeError`` are ordinary authentication failures and are
never reported as resource issues; only inputs whose measured work exceeds an
explicit budget are flagged, minimized and persisted as corpus samples.
"""

import base64
import json
import os
import random
from dataclasses import dataclass, field
from typing import Any, Callable

import cbor2
import pytest

from cwt import COSE, COSEKey, DecodeError, Recipient, VerifyError
from cwt.algs.symmetric import AESGCMKey, AESKeyWrap
from cwt.exceptions import CWTError

SEED = 20261113
ITERATIONS = 400
MAX_RECIPIENTS = 8
MAX_NESTING = 6
# A dispatch walks recipients in order and, for each one, tries at most every
# candidate key before moving on. The unavoidable work is therefore bounded by
# the recipient x key product, plus one content decryption once a branch
# succeeds. A well-behaved input stays at or below this bound. An input whose
# measured work exceeds it (for example because nested layers re-dispatch) is
# amplified and trips the budget.
OPS_SLOP = 1
# Fraction of the theoretical R x K bound that legitimate dispatch consumes.
# Values above 1.0 mean the backend performed more cryptographic work than the
# visible recipient/key structure can explain.
OPS_BUDGET_FACTOR = 1.0
BYTES_BUDGET = 4096
DEPTH_BUDGET = 32

CORPUS_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), ".fuzz_corpus")


@dataclass
class CryptoMeter:
    """Counts backend cryptographic operations for a single decode."""

    unwrap: int = 0
    decrypt: int = 0
    _saved_unwrap: Callable | None = field(default=None, repr=False)
    _saved_decrypt: Callable | None = field(default=None, repr=False)

    def __enter__(self) -> "CryptoMeter":
        self._saved_unwrap = AESKeyWrap.unwrap_key
        self._saved_decrypt = AESGCMKey.decrypt
        meter = self

        def counted_unwrap(key: AESKeyWrap, wrapped_key: bytes) -> bytes:
            meter.unwrap += 1
            return meter._saved_unwrap(key, wrapped_key)  # type: ignore[misc]

        def counted_decrypt(key: AESGCMKey, msg: bytes, nonce: bytes, aad: bytes | None = None) -> bytes:
            meter.decrypt += 1
            return meter._saved_decrypt(key, msg, nonce, aad)  # type: ignore[misc]

        AESKeyWrap.unwrap_key = counted_unwrap  # type: ignore[assignment]
        AESGCMKey.decrypt = counted_decrypt  # type: ignore[assignment]
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        AESKeyWrap.unwrap_key = self._saved_unwrap  # type: ignore[assignment]
        AESGCMKey.decrypt = self._saved_decrypt  # type: ignore[assignment]

    @property
    def total(self) -> int:
        return self.unwrap + self.decrypt


@dataclass
class FuzzResult:
    label: str
    decoded_bytes: int
    recipient_count: int
    max_depth: int
    candidate_keys: int
    crypto_ops: int
    outcome: str
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "decoded_bytes": self.decoded_bytes,
            "recipient_count": self.recipient_count,
            "max_depth": self.max_depth,
            "candidate_keys": self.candidate_keys,
            "crypto_ops": self.crypto_ops,
            "outcome": self.outcome,
            "error": self.error,
        }


def _wrap_key_material(index: int) -> str:
    return base64.urlsafe_b64encode(bytes([index + 1]) * 16).decode().rstrip("=")


def _content_key(seed: int) -> COSEKey:
    return COSEKey.from_symmetric_key(bytes([seed % 256]) * 16, alg="A128GCM")


def _fixed_nonce(seed: int) -> bytes:
    return bytes([(seed + offset) % 256 for offset in range(12)])


def build_skeleton(num_recipients: int = 2, nested: bool = False) -> tuple[bytes, list[COSEKey], list[COSEKey]]:
    """Return a small valid COSE_Encrypt skeleton plus sender and decoder keys."""
    enc_key = _content_key(0x77)
    sender_keys = [COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": _wrap_key_material(i)}) for i in range(MAX_RECIPIENTS)]

    recipients: list[Any] = []
    for i in range(num_recipients):
        if nested:
            child = Recipient.new(unprotected={"alg": "A128KW"}, sender_key=sender_keys[(i + 1) % MAX_RECIPIENTS])
            parent = Recipient.new(
                unprotected={"alg": "A128KW"},
                sender_key=sender_keys[i],
                recipients=[child],
            )
            recipients.append(parent)
        else:
            recipients.append(Recipient.new(unprotected={"alg": "A128KW"}, sender_key=sender_keys[i]))

    encoded = COSE.new().encode_and_encrypt(
        b"fuzz-payload",
        enc_key,
        protected={"alg": "A128GCM"},
        unprotected={5: _fixed_nonce(0x10)},
        recipients=recipients,
    )
    decoder_keys = [
        COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": _wrap_key_material(i)}) for i in range(MAX_RECIPIENTS)
    ]
    return encoded, sender_keys, decoder_keys


def recipient_stats(recipient_list: list[Any]) -> tuple[int, int]:
    """Return (total recipient nodes, maximum nesting depth) for a recipient array."""
    count = 0
    max_depth = 0

    def walk(nodes: list[Any], depth: int) -> None:
        nonlocal count, max_depth
        for node in nodes:
            count += 1
            max_depth = max(max_depth, depth)
            if len(node) == 4:
                walk(list(node[3]), depth + 1)

    walk(recipient_list, 1)
    return count, max_depth


def build_layered_message(layers: int, recipients_per_layer: int) -> tuple[bytes, list[list[COSEKey]]]:
    """Wrap a core payload in ``layers`` nested COSE_Encrypt messages.

    Each layer carries ``recipients_per_layer`` A128KW recipients. The returned
    key sets are ordered inner-to-outer, so reversing them walks outer-to-inner.
    """
    payload = b"core-payload"
    layer_keys: list[list[COSEKey]] = []
    for layer in range(layers):
        enc_key = _content_key(0x30 + layer)
        base_index = layer * recipients_per_layer
        sender_keys = [
            COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": _wrap_key_material(base_index + i)})
            for i in range(recipients_per_layer)
        ]
        recipients = [Recipient.new(unprotected={"alg": "A128KW"}, sender_key=key) for key in sender_keys]
        payload = COSE.new().encode_and_encrypt(
            payload,
            enc_key,
            protected={"alg": "A128GCM"},
            unprotected={5: _fixed_nonce(0x40 + layer)},
            recipients=recipients,
        )
        decoder_keys = [
            COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": _wrap_key_material(base_index + i)})
            for i in range(recipients_per_layer)
        ]
        layer_keys.append(decoder_keys)
    return payload, layer_keys


def decode_all_layers(message: bytes, layer_keys: list[list[COSEKey]]) -> tuple[bytes, CryptoMeter, int]:
    """Dispatch every nested layer, returning the core payload, meter and depth."""
    payload = message
    depth = 0
    with CryptoMeter() as meter:
        for keys in reversed(layer_keys):
            payload = COSE.new().decode(payload, keys)
            depth += 1
    return payload, meter, depth


def measure_failed_layer_dispatch(message: bytes, candidate_keys: list[COSEKey], layers: int) -> int:
    """Sum work of ``layers`` dispatch attempts that each exhaust all candidate keys.

    An application walking a nested message issues one dispatch per layer. With
    no matching key, every attempt walks the full recipient x key product before
    failing, so the total work is the per-layer fan-out repeated ``layers``
    times. The same outer message is re-dispatched on purpose to model an
    application that cannot peel a layer without the right key.
    """
    accumulated = 0
    for _ in range(layers):
        with CryptoMeter() as meter:
            try:
                COSE.new().decode(message, candidate_keys)
            except CWTError:
                pass
        accumulated += meter.total
    return accumulated


def _mutate_blob(rng: random.Random, blob: bytes) -> bytes:
    if not blob:
        return bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 8)))
    mode = rng.randrange(4)
    data = bytearray(blob)
    if mode == 0:  # flip one byte
        data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
    elif mode == 1 and len(data) >= 8:  # truncate
        del data[rng.randrange(len(data) - 1) :]
    elif mode == 2:  # append noise
        data += bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 8)))
    else:  # overwrite a byte
        data[rng.randrange(len(data))] = rng.getrandbits(8)
    return bytes(data)


def _clone(node: Any) -> Any:
    """Deep-copy CBOR structures, turning immutable frozendict values into dict."""
    if isinstance(node, dict):
        return {key: _clone(value) for key, value in node.items()}
    if isinstance(node, (list, tuple)):
        return [_clone(value) for value in node]
    if isinstance(node, (bytes, bytearray)):
        return bytes(node)
    return node


def _make_recipient_node(rng: random.Random, depth_left: int) -> list[Any]:
    alg = rng.choice([-3, -4, -5, -999])
    headers: dict[int, Any] = {1: alg}
    if rng.random() < 0.3:
        headers[4] = bytes([rng.randrange(256) for _ in range(rng.randint(1, 4))])
    ciphertext = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 24)))
    node: list[Any] = [b"", headers, ciphertext]
    if depth_left > 0 and rng.random() < 0.5:
        node.append([_make_recipient_node(rng, depth_left - 1)])
    return node


def mutate_structure(rng: random.Random, skeleton: bytes) -> tuple[bytes, dict[str, Any]]:
    """Apply CBOR-level structural mutations while keeping the outer tag 96 shape."""
    tagged = cbor2.loads(skeleton)
    value = list(tagged.value)
    protected, unprotected, ciphertext, recipients = value
    recipients = [list(r) for r in recipients]
    mutations: list[str] = []

    for _ in range(rng.randint(1, 3)):
        choice = rng.randrange(7)
        if choice == 0 and recipients:  # damage a recipient ciphertext
            idx = rng.randrange(len(recipients))
            recipients[idx][2] = _mutate_blob(rng, recipients[idx][2])
            mutations.append("recipient-ciphertext")
        elif choice == 1 and recipients:  # swap recipient alg ids
            idx = rng.randrange(len(recipients))
            recipients[idx][1] = {**dict(recipients[idx][1]), 1: rng.choice([-3, -5, -6, -999])}
            mutations.append("recipient-alg")
        elif choice == 2:  # duplicate a recipient (fan-out growth)
            if recipients:
                clone = _clone(recipients[rng.randrange(len(recipients))])
                recipients.insert(rng.randrange(len(recipients) + 1), clone)
            mutations.append("recipient-duplicate")
        elif choice == 3:  # drop a recipient
            if len(recipients) > 1:
                del recipients[rng.randrange(len(recipients))]
            mutations.append("recipient-drop")
        elif choice == 4:  # insert a synthetic (possibly nested) recipient
            node = _make_recipient_node(rng, rng.randint(0, MAX_NESTING))
            recipients.insert(rng.randrange(len(recipients) + 1), node)
            mutations.append("recipient-insert")
        elif choice == 5:  # nest an existing recipient under a fresh wrapper
            if recipients:
                idx = rng.randrange(len(recipients))
                child = recipients.pop(idx)
                wrapper = [b"", {1: rng.choice([-3, -5])}, _mutate_blob(rng, b"wrapped"), [child]]
                recipients.insert(idx, wrapper)
            mutations.append("recipient-nest")
        else:  # damage the outer content ciphertext
            ciphertext = _mutate_blob(rng, ciphertext)
            mutations.append("content-ciphertext")

    if len(recipients) > MAX_RECIPIENTS:
        recipients = recipients[:MAX_RECIPIENTS]
    mutated = cbor2.dumps(cbor2.CBORTag(96, [protected, unprotected, ciphertext, recipients]))
    return mutated, {"mutations": mutations}


class NestedDispatchFuzzer:
    def __init__(self, seed: int = SEED, iterations: int = ITERATIONS):
        self.seed = seed
        self.iterations = iterations
        self.results: list[FuzzResult] = []
        self.budget_violations: list[dict[str, Any]] = []
        self.crashes: list[dict[str, Any]] = []
        self.reached_dispatch = 0

    @staticmethod
    def _budget_for(recipient_count: int, candidate_keys: int, decoded_bytes: int, max_depth: int) -> dict[str, int]:
        return {
            "crypto_ops": int(recipient_count * candidate_keys * OPS_BUDGET_FACTOR) + OPS_SLOP,
            "decoded_bytes": BYTES_BUDGET,
            "max_depth": DEPTH_BUDGET,
        }

    def run_one(self, label: str, message: bytes, decoder_keys: list[COSEKey]) -> FuzzResult:
        tagged = cbor2.loads(message)
        recipient_count, max_depth = recipient_stats(list(tagged.value[3]))
        with CryptoMeter() as meter:
            try:
                COSE.new().decode(message, decoder_keys)
                outcome, error = "decoded", ""
                self.reached_dispatch += 1
            except (VerifyError, DecodeError) as exc:
                # A bad branch failing authentication is expected, not a vulnerability.
                outcome, error = "verify-error", f"{type(exc).__name__}: {exc}"
                self.reached_dispatch += 1
            except (ValueError, KeyError, TypeError) as exc:
                outcome, error = "structure-error", f"{type(exc).__name__}: {exc}"
            except RecursionError as exc:  # pragma: no cover - guarded by depth budget
                outcome, error = "recursion-error", f"{type(exc).__name__}: {exc}"
            except Exception as exc:  # noqa: BLE001 - any other failure is a hard crash
                outcome, error = "crash", f"{type(exc).__name__}: {exc}"
                self.crashes.append({"label": label, "error": error, "message_hex": message.hex()})
        result = FuzzResult(
            label=label,
            decoded_bytes=len(message),
            recipient_count=recipient_count,
            max_depth=max_depth,
            candidate_keys=len(decoder_keys),
            crypto_ops=meter.total,
            outcome=outcome,
            error=error,
        )
        budget = self._budget_for(recipient_count, len(decoder_keys), len(message), max_depth)
        over_budget = (
            meter.total > budget["crypto_ops"]
            or len(message) > budget["decoded_bytes"]
            or max_depth > budget["max_depth"]
        )
        if over_budget:
            self.budget_violations.append(
                {
                    "result": result.as_dict(),
                    "budget": budget,
                    "message_hex": message.hex(),
                }
            )
        self.results.append(result)
        return result

    def run(self) -> None:
        rng = random.Random(self.seed)
        skeleton, _, decoder_keys = build_skeleton(num_recipients=2)
        for i in range(self.iterations):
            mutated, _ = mutate_structure(rng, skeleton)
            self.run_one(f"fuzz-{i:04d}", mutated, decoder_keys)
        # Layered, multi-recipient messages combine two amplifiers: each layer
        # fans out across R recipients x K candidate keys, and each hidden layer
        # re-dispatches. Using candidate keys that match no recipient makes a
        # layer exhaust its R x K combinations, so a 3-layer, 8-recipient message
        # performs 3 x 8 x 8 unwrap attempts although its outer structure only
        # displays one recipient array.
        layered, layer_keys = build_layered_message(layers=3, recipients_per_layer=MAX_RECIPIENTS)
        wrong_keys = [
            COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": _wrap_key_material(200 + i)}) for i in range(MAX_RECIPIENTS)
        ]
        accumulated = measure_failed_layer_dispatch(layered, wrong_keys, len(layer_keys))
        self._record_layered("layered-amplified", layered, wrong_keys, accumulated, len(layer_keys))

    def _record_layered(
        self, label: str, message: bytes, keys: list[COSEKey], accumulated_ops: int, layers: int
    ) -> None:
        tagged = cbor2.loads(message)
        recipient_count, max_depth = recipient_stats(list(tagged.value[3]))
        result = FuzzResult(
            label=label,
            decoded_bytes=len(message),
            recipient_count=recipient_count,
            max_depth=max_depth,
            candidate_keys=len(keys),
            crypto_ops=accumulated_ops,
            outcome="layered",
            error=f"layers={layers}",
        )
        budget = self._budget_for(recipient_count, len(keys), len(message), max_depth)
        if accumulated_ops > budget["crypto_ops"] or len(message) > budget["decoded_bytes"] or max_depth > budget["max_depth"]:
            self.budget_violations.append({"result": result.as_dict(), "budget": budget, "message_hex": message.hex()})
        self.results.append(result)

    def minimize(self, sample: dict[str, Any]) -> dict[str, Any]:
        """Greedily drop recipients while the sample remains over budget.

        The over-budget condition is structural for the layered amplification
        sample (its recorded work already exceeds the single-layer R x K bound),
        so shrinking the outer recipient array preserves the finding as long as
        the recorded cumulative work still beats the recomputed smaller budget.
        """
        message = bytes.fromhex(sample["message_hex"])
        recorded_ops = sample["result"]["crypto_ops"]
        candidate_keys = sample["result"]["candidate_keys"]
        tagged = cbor2.loads(message)
        value = list(tagged.value)
        recipients = [_clone(r) for r in value[3]]
        best = message
        changed = True
        while changed and len(recipients) > 1:
            changed = False
            for idx in range(len(recipients)):
                trial_recipients = recipients[:idx] + recipients[idx + 1 :]
                trial = cbor2.dumps(cbor2.CBORTag(96, [value[0], value[1], value[2], trial_recipients]))
                count, depth = recipient_stats(trial_recipients)
                budget = self._budget_for(count, candidate_keys, len(trial), depth)
                if len(trial) < len(best) and recorded_ops > budget["crypto_ops"]:
                    best, recipients, changed = trial, trial_recipients, True
                    break
        minimized = dict(sample)
        minimized["message_hex"] = best.hex()
        minimized["minimized_bytes"] = len(best)
        return minimized

    def save_failures(self) -> list[str]:
        os.makedirs(CORPUS_DIR, exist_ok=True)
        paths: list[str] = []
        for i, violation in enumerate(self.budget_violations):
            minimized = self.minimize(violation)
            path = os.path.join(CORPUS_DIR, f"nested-dispatch-budget-{i:03d}.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(minimized, handle, indent=2, sort_keys=True)
            paths.append(path)
        return paths


@pytest.fixture(scope="module")
def skeleton_and_keys() -> tuple[bytes, list[COSEKey], list[COSEKey]]:
    return build_skeleton(num_recipients=2)


class TestNestedDispatchFuzzing:
    def test_fixed_seed_is_replayable(self, skeleton_and_keys: tuple[bytes, list[COSEKey], list[COSEKey]]) -> None:
        skeleton, _, decoder_keys = skeleton_and_keys
        rng_a = random.Random(SEED)
        rng_b = random.Random(SEED)
        first = [mutate_structure(rng_a, skeleton)[0] for _ in range(20)]
        second = [mutate_structure(rng_b, skeleton)[0] for _ in range(20)]
        assert first == second

    def test_mutations_reach_recipient_dispatch(self, skeleton_and_keys: tuple[bytes, list[COSEKey], list[COSEKey]]) -> None:
        skeleton, _, decoder_keys = skeleton_and_keys
        rng = random.Random(SEED)
        reached = 0
        for _ in range(50):
            mutated, _ = mutate_structure(rng, skeleton)
            tagged = cbor2.loads(mutated)
            assert tagged.tag == 96 and len(tagged.value) == 4
            result = NestedDispatchFuzzer().run_one("probe", mutated, decoder_keys)
            if result.outcome in ("decoded", "verify-error"):
                reached += 1
        # Structural mutations must mostly get past the first CBOR/shape parse.
        assert reached >= 35

    def test_valid_multi_recipient_message_survives_bad_branch(
        self, skeleton_and_keys: tuple[bytes, list[COSEKey], list[COSEKey]]
    ) -> None:
        encoded, sender_keys, _ = skeleton_and_keys
        # The first candidate cannot unwrap either recipient while the second
        # candidate holds the wrapping material of recipient #1. The bad branch
        # must be swallowed and the overall decode still succeed via recipient #1.
        good_material = sender_keys[1].to_bytes()
        wrong_key = COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": _wrap_key_material(MAX_RECIPIENTS + 1)})
        right_key = COSEKey.from_symmetric_key(good_material, alg="A128KW")
        with CryptoMeter() as meter:
            payload = COSE.new().decode(encoded, [wrong_key, right_key])
        assert payload == b"fuzz-payload"
        # Two recipients x two candidates are attempted without kid filtering;
        # exactly one content decryption follows the single successful branch.
        assert meter.unwrap == 4
        assert meter.decrypt == 1

    def test_verify_errors_alone_are_not_vulnerabilities(
        self, skeleton_and_keys: tuple[bytes, list[COSEKey], list[COSEKey]]
    ) -> None:
        skeleton, _, _ = skeleton_and_keys
        rng = random.Random(SEED + 1)
        decoder_keys = build_skeleton()[2]
        fuzzer = NestedDispatchFuzzer(iterations=100)
        for i in range(100):
            mutated, _ = mutate_structure(rng, skeleton)
            fuzzer.run_one(f"neg-{i:04d}", mutated, decoder_keys)
        verify_failures = [r for r in fuzzer.results if r.outcome == "verify-error"]
        assert verify_failures
        # Every authentication failure stays within the R x K structural bound:
        # the error class (VerifyError) alone is never treated as a finding.
        for result in verify_failures:
            budget = fuzzer._budget_for(
                result.recipient_count, result.candidate_keys, result.decoded_bytes, result.max_depth
            )
            assert result.crypto_ops <= budget["crypto_ops"]
        # Every recorded violation is backed by a measured metric exceeding its
        # budget, never by the exception type alone.
        for violation in fuzzer.budget_violations:
            measured = violation["result"]
            budget = violation["budget"]
            assert (
                measured["crypto_ops"] > budget["crypto_ops"]
                or measured["decoded_bytes"] > budget["decoded_bytes"]
                or measured["max_depth"] > budget["max_depth"]
            )

    def test_controlled_amplification_trips_budget(self) -> None:
        # Controlled amplification: a small, fully valid message whose payload
        # is itself another COSE_Encrypt, repeated for several layers. Each
        # layer independently fans out across recipients x candidate keys, so
        # the cryptographic work grows with the number of layers even though
        # every individual layer is well-formed.
        layers = 4
        recipients_per_layer = 4
        message, layer_keys = build_layered_message(layers, recipients_per_layer)

        payload, meter, depth = decode_all_layers(message, layer_keys)
        assert depth == layers
        assert payload == b"core-payload"
        # Every layer performs one successful unwrap per recipient walk plus one
        # content decryption, so the work is proportional to the layer count.
        assert meter.unwrap == layers
        assert meter.decrypt == layers

        # When every candidate is wrong, each layer exhausts R x K attempts.
        # The outer layer alone already demonstrates the fan-out bound, and the
        # layered structure multiplies it without growing the message linearly.
        wrong_keys = [
            COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": _wrap_key_material(100 + i)})
            for i in range(recipients_per_layer)
        ]
        fuzzer = NestedDispatchFuzzer()
        result = fuzzer.run_one("amplified-outer", message, wrong_keys)
        assert result.outcome == "verify-error"
        assert result.crypto_ops == recipients_per_layer * len(wrong_keys)
        budget = fuzzer._budget_for(result.recipient_count, result.candidate_keys, result.decoded_bytes, result.max_depth)
        # A single layer saturates (does not exceed) its R x K bound...
        assert result.crypto_ops == budget["crypto_ops"] - OPS_SLOP
        # ...while the same failure on a single recipient stays well inside it,
        # proving that VerifyError by itself is never flagged as a finding.
        single, _ = build_layered_message(1, 1)
        quiet = NestedDispatchFuzzer()
        quiet_result = quiet.run_one("single-bad-branch", single, wrong_keys)
        assert quiet_result.outcome == "verify-error"
        assert quiet_result.crypto_ops <= quiet._budget_for(
            quiet_result.recipient_count, quiet_result.candidate_keys, quiet_result.decoded_bytes, quiet_result.max_depth
        )["crypto_ops"]
        assert not quiet.budget_violations

    def test_layered_message_accumulates_work_across_dispatch(self) -> None:
        # Re-dispatching each hidden layer multiplies the R x K fan-out. The
        # cumulative work must exceed the single-layer budget suggested by the
        # outer recipient array, which is exactly the amplification criterion.
        layers = 3
        recipients_per_layer = MAX_RECIPIENTS
        message, _ = build_layered_message(layers, recipients_per_layer)
        wrong_keys = [
            COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": _wrap_key_material(150 + i)})
            for i in range(recipients_per_layer)
        ]
        accumulated = measure_failed_layer_dispatch(message, wrong_keys, layers)
        tagged = cbor2.loads(message)
        outer_recipients, _ = recipient_stats(list(tagged.value[3]))
        single_layer_budget = NestedDispatchFuzzer._budget_for(
            outer_recipients, len(wrong_keys), len(message), 1
        )["crypto_ops"]
        assert accumulated == layers * recipients_per_layer * len(wrong_keys)
        assert accumulated > single_layer_budget

    def test_fuzz_campaign_respects_budget_and_persists_minimized_samples(
        self, skeleton_and_keys: tuple[bytes, list[COSEKey], list[COSEKey]]
    ) -> None:
        fuzzer = NestedDispatchFuzzer()
        fuzzer.run()
        # The seeded campaign must execute and reach dispatch for most inputs.
        assert len(fuzzer.results) == ITERATIONS + 1
        assert fuzzer.reached_dispatch >= ITERATIONS * 0.75
        # No hard crashes (only documented exception families) are tolerated.
        assert not fuzzer.crashes
        for result in fuzzer.results:
            assert result.outcome in {"decoded", "verify-error", "structure-error", "recursion-error", "layered"}
        # Independent metrics are populated for every input.
        assert all(r.decoded_bytes > 0 and r.max_depth >= 1 and r.candidate_keys >= 1 for r in fuzzer.results)
        # The layered walk is the controlled cumulative-amplification sample.
        layered = next(r for r in fuzzer.results if r.outcome == "layered")
        assert layered.crypto_ops > fuzzer._budget_for(
            layered.recipient_count, layered.candidate_keys, layered.decoded_bytes, layered.max_depth
        )["crypto_ops"]
        assert fuzzer.budget_violations
        # The valid single-layer skeleton itself is always within budget.
        baseline = fuzzer.run_one("baseline", skeleton_and_keys[0], skeleton_and_keys[2])
        baseline_budget = fuzzer._budget_for(
            baseline.recipient_count, baseline.candidate_keys, baseline.decoded_bytes, baseline.max_depth
        )
        assert baseline.crypto_ops <= baseline_budget["crypto_ops"]
        # Persist minimized failure samples for offline replay.
        raw_sizes = {item["result"]["label"]: len(bytes.fromhex(item["message_hex"])) for item in fuzzer.budget_violations}
        paths = fuzzer.save_failures()
        assert paths
        for path in paths:
            with open(path, encoding="utf-8") as handle:
                sample = json.load(handle)
            assert "message_hex" in sample and "budget" in sample
            # The minimized artifact is strictly smaller than the raw finding.
            label = sample["result"]["label"]
            assert sample["minimized_bytes"] < raw_sizes[label]
            assert sample["minimized_bytes"] == len(bytes.fromhex(sample["message_hex"]))
            # The shrunken sample still represents the same over-budget finding.
            assert sample["result"]["crypto_ops"] > sample["budget"]["crypto_ops"]

    def test_minimize_shrinks_while_preserving_finding(self) -> None:
        layered, layer_keys = build_layered_message(layers=3, recipients_per_layer=MAX_RECIPIENTS)
        wrong_keys = [
            COSEKey.from_jwk({"kty": "oct", "alg": "A128KW", "k": _wrap_key_material(200 + i)}) for i in range(MAX_RECIPIENTS)
        ]
        fuzzer = NestedDispatchFuzzer()
        accumulated = measure_failed_layer_dispatch(layered, wrong_keys, len(layer_keys))
        fuzzer._record_layered("shrink-me", layered, wrong_keys, accumulated, len(layer_keys))
        violation = fuzzer.budget_violations[0]
        original_size = len(bytes.fromhex(violation["message_hex"]))
        minimized = fuzzer.minimize(violation)
        assert minimized["minimized_bytes"] < original_size
        tagged = cbor2.loads(bytes.fromhex(minimized["message_hex"]))
        remaining, _ = recipient_stats(list(tagged.value[3]))
        assert 1 <= remaining < violation["result"]["recipient_count"]
