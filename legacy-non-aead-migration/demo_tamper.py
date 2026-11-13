# -*- coding: utf-8 -*-
"""
离线演示：非 AEAD（AES-CTR / AES-CBC）COSE 消息的密文篡改 ≠ 解密失败，
与 AEAD（AES-GCM）的篡改拒绝作对照。

运行：.venv/bin/python legacy-non-aead-migration/demo_tamper.py
"""
import cbor2

from cwt import COSE, COSEKey

CLAIMS = {"amount": 100, "role": "user"}


def tamper_ciphertext(msg: bytes, offset: int, xor: int) -> bytes:
    """对 COSE_Encrypt0 (tag 16) 的密文字节做定向翻转，保持其余结构不变。"""
    tag = cbor2.loads(msg)
    assert tag.tag == 16, f"expected Encrypt0, got tag {tag.tag}"
    protected, unprotected, ct = tag.value
    ct = bytearray(ct)
    ct[offset] ^= xor
    return cbor2.dumps(cbor2.CBORTag(16, [protected, unprotected, bytes(ct)]))


def try_decode(name, msg, key, **kwargs):
    try:
        out = COSE.new().decode(msg, key, **kwargs)
        print(f"  [{name}] decode 成功, 返回明文: {out!r}")
        return out
    except Exception as e:
        print(f"  [{name}] decode 拒绝: {type(e).__name__}: {e}")
        return None


def section(title):
    print(f"\n=== {title} ===")


# ---------------------------------------------------------------- CTR 可塑性
section("1. AES-CTR：定向比特翻转 —— 解密成功且 CBOR 仍然合法")
key_ctr = COSEKey.from_symmetric_key(b"ctr-key-01234567", alg="A128CTR")
payload = cbor2.dumps(CLAIMS)
msg = COSE.new(alg_auto_inclusion=True).encode_and_encrypt(payload, key_ctr, enable_non_aead=True)

# 默认开关：库本身拒绝非 AEAD
try_decode("CTR 默认开关", msg, key_ctr)

# 找到 payload 中 100 (0x18 0x64) 的 0x64 的偏移，翻转 0x20 -> 68
idx = payload.index(0x64)
forged = tamper_ciphertext(msg, idx, 0x20)
out = try_decode("CTR 篡改后 (enable_non_aead=True)", forged, key_ctr, enable_non_aead=True)
if out is not None:
    decoded = cbor2.loads(out)
    print(f"  -> 篡改后声明仍被 CBOR 正常解析: {decoded}")
    assert decoded["amount"] == 68 and decoded != CLAIMS
    print("  -> amount 被攻击者从 100 改为 68，库未报任何错误：'能解密' != '已验证'")

# ---------------------------------------------------------------- CBC 填充盲区
section("2. AES-CBC：篡改中间块 —— 填充检查通过，解密成功")
key_cbc = COSEKey.from_symmetric_key(b"cbc-key-01234567", alg="A128CBC")
# bstr 载荷，长度 >= 2 个块，使最后一个块含有效填充
payload2 = cbor2.dumps(b"amount=100;to=alice;note=hello-world!!")
msg2 = COSE.new(alg_auto_inclusion=True).encode_and_encrypt(payload2, key_cbc, enable_non_aead=True)
print(f"  明文 {len(payload2)} 字节 -> 填充后 48 字节 (3 块)")

# 翻转第 2 个密文块(偏移 16+j)：明文块 3 对应字节被翻转，填充字节完好
forged2 = tamper_ciphertext(msg2, 16 + 5, 0x01)
out2 = try_decode("CBC 篡改中间块", forged2, key_cbc, enable_non_aead=True)
if out2 is not None:
    print(f"  -> 填充检查通过、解密成功，但内容已被破坏: {cbor2.loads(out2)!r}")

# 对照：篡改最后一个密文块 -> 整块明文随机化。
# 注意：python-cwt 的 unpad 是 decrypted[0:-decrypted[-1]]，不校验填充字节，
# 因此连"填充检查失败"都不会发生——解密永远"成功"，只是返回垃圾或空串。
forged3 = tamper_ciphertext(msg2, 47, 0xFF)
try_decode("CBC 篡改最后一块", forged3, key_cbc, enable_non_aead=True)

# ---------------------------------------------------------------- AEAD 对照
section("3. AES-GCM (AEAD)：任意一字节篡改 —— 一律拒绝")
key_gcm = COSEKey.from_symmetric_key(b"gcm-key-01234567", alg="A128GCM")
msg3 = COSE.new(alg_auto_inclusion=True).encode_and_encrypt(cbor2.dumps(CLAIMS), key_gcm)
tag = cbor2.loads(msg3)
ct_len = len(tag.value[2])
try_decode("GCM 未篡改(基线)", msg3, key_gcm)
try_decode("GCM 篡改首字节", tamper_ciphertext(msg3, 0, 0x01), key_gcm)
try_decode("GCM 篡改末字节", tamper_ciphertext(msg3, ct_len - 1, 0x01), key_gcm)

section("结论")
print("  CTR/CBC：'解密成功' 只证明密钥正确，不证明密文未被篡改。")
print("  CBC 的 unpad 不校验填充：任何密文都能解出某种明文，失败通道根本不存在。")
print("  GCM：解密与完整性验证原子绑定，篡改必然导致 decode 抛异常。")
