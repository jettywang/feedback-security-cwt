# -*- coding: utf-8 -*-
"""接口契约自测：三分级 + 默认拒绝 + 篡改拒绝。运行：.venv/bin/python legacy-non-aead-migration/test_contract.py"""
import sys
sys.path.insert(0, "legacy-non-aead-migration")

import cbor2
from cwt import COSE, COSEKey
from cose_open_contract import (
    Authenticity,
    PolicyRejectionError,
    UnauthenticatedPayloadAccessError,
    open_cose_message,
)

claims = cbor2.dumps({"amount": 100})
enc = COSE.new(alg_auto_inclusion=True)

# C 类：新生成 AEAD
gcm_key = COSEKey.from_symmetric_key(b"gcm-key-01234567", alg="A128GCM")
msg_c = enc.encode_and_encrypt(claims, gcm_key)
opened = open_cose_message(msg_c, gcm_key)
assert opened.authenticity is Authenticity.AEAD_VERIFIED
assert opened.payload == claims
print("C 类 AEAD 新消息        -> AEAD_VERIFIED, payload 正常可取")

# A 类：仅加密历史消息
ctr_key = COSEKey.from_symmetric_key(b"ctr-key-01234567", alg="A128CTR")
msg_a = enc.encode_and_encrypt(claims, ctr_key, enable_non_aead=True)
try:
    open_cose_message(msg_a, ctr_key)
    raise AssertionError("默认应拒绝")
except PolicyRejectionError as e:
    print(f"A 类默认策略            -> 拒绝: {e.__class__.__name__}")

opened_a = open_cose_message(msg_a, ctr_key, allow_legacy_unauthenticated=True)
assert opened_a.authenticity is Authenticity.UNAUTHENTICATED_LEGACY
try:
    opened_a.payload
    raise AssertionError("未认证明文不应可常规访问")
except UnauthenticatedPayloadAccessError:
    print("A 类 opt-in 兼容读取    -> UNAUTHENTICATED_LEGACY, .payload 被拒绝")
assert opened_a.payload_unauthenticated() == claims
print("A 类显式逃生门          -> payload_unauthenticated() 可取（调用方自担风险）")

# B 类：另有可信外层认证的历史消息
opened_b = open_cose_message(
    msg_a, ctr_key,
    allow_legacy_unauthenticated=True,
    outer_authenticity_verified=True,
)
assert opened_b.authenticity is Authenticity.EXTERNALLY_AUTHENTICATED
assert opened_b.payload == claims
print("B 类外层已认证          -> EXTERNALLY_AUTHENTICATED, payload 可取")

# 篡改拒绝：AEAD 路径
tag = cbor2.loads(msg_c)
p, u, ct = tag.value
forged = cbor2.dumps(cbor2.CBORTag(16, [p, u, ct[:-1] + bytes([ct[-1] ^ 1])]))
try:
    open_cose_message(forged, gcm_key)
    raise AssertionError("篡改应被拒绝")
except Exception as e:
    print(f"AEAD 篡改               -> 拒绝: {type(e).__name__}")

print("\n全部断言通过。")
