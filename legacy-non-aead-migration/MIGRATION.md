# 非 AEAD 历史 COSE 消息迁移方案

## 1. 假设审查：为什么"能解密 = 已验证"不成立

**python-cwt 的开关行为**（`cwt/cose.py`）：

- `encode_and_encrypt` / `decode` / `decode_with_headers` 均有 `enable_non_aead: bool = False`
  参数。默认遇 AES-CTR/CBC（alg -65534~-65529，RFC 9459 已标记 Deprecated）直接
  `raise ValueError("Deprecated non-AEAD algorithm")`——库的默认姿态就是拒绝。
- 一旦显式传 `enable_non_aead=True`，`decode()` 的**返回行为与 AEAD 完全同构**：
  成功时返回 `bytes` 明文，签名里没有任何"未认证"标记。调用方若只看"没抛异常"，
  无法区分"完整性已验证"和"仅完成了解密运算"。
- 非 AEAD 消息的 alg 只能放 unprotected 头、protected 头必须为空（RFC 9459 §4），
  意味着算法标识本身也不在任何密码学保护之下。

**返回行为的结论**：`decode()` 不抛异常，对 AEAD 意味着"机密性 + 完整性 + 真实性"，
对 CTR/CBC 只意味着"密钥正确且密文长度合法"。把两者统一当作"已验证"是把
机密性原语误当成认证原语。

## 2. 离线演示摘要（`demo_tamper.py`，可重复运行）

| 场景 | 结果 |
|---|---|
| CTR：翻转密文 1 bit（定向攻击 `amount` 字段） | decode 成功，`100 → 68`，CBOR 仍合法解析，无任何报错 |
| CBC：翻转中间密文块 1 byte | decode 成功，填充完好，内容静默损坏 |
| CBC：翻转最后一块 1 byte | decode 仍"成功"——python-cwt 的 unpad 是 `decrypted[0:-decrypted[-1]]`，**不校验填充字节**，失败通道根本不存在 |
| GCM：翻转任意 1 byte | `DecodeError: Failed to decrypt.`，篡改必然被拒绝 |

## 3. 三种局部检查各自缺什么保证

- **只检查填充**：填充最多覆盖最后一个块的 ≤16 字节，对前面所有块的篡改完全失明；
  随机垃圾约有 1/256 概率"碰巧合法"；校验实现若区分填充错误与解密错误还会构成
  padding oracle。而 python-cwt 连校验都没做——填充检查在任何形态下都不构成完整性。
- **只检查 CBOR 格式**：well-formedness ≠ integrity。CTR 是逐比特异或，攻击者可精确
  选择翻转位置，把数值字段改成另一个合法 CBOR 值（演示中的 `100→68`）。结构合法
  只说明攻击者"保持了格式"，不说明内容未被选择。
- **只检查声明字段（exp/iss/aud 等）**：这是对**攻击者可塑的明文**做语义校验。攻击者
  可以把声明翻转成另一个同样"看起来合理"的值（未过期的时间戳、另一个合法 issuer）。
  语义检查没有密钥绑定，无法区分"发送方写的值"和"攻击者改的值"。

三者共同的缺失：**没有任何机制把密文与密钥绑定起来**。完整性只能来自 MAC/AEAD
标签或外层签名，无法从旧消息自身"恢复"——它从未携带过。

## 4. 接口契约（`cose_open_contract.py`，含自测 `test_contract.py`）

```
open_cose_message(data, keys, *,
                  allow_legacy_unauthenticated=False,
                  outer_authenticity_verified=False) -> OpenedMessage
```

- 返回 `OpenedMessage`，`authenticity` 为三级之一：`AEAD_VERIFIED` /
  `EXTERNALLY_AUTHENTICATED` / `UNAUTHENTICATED_LEGACY`，调用方必须按级分支。
- 非 AEAD 默认 `PolicyRejectionError`（与库默认一致，拒绝是显式的）。
- `UNAUTHENTICATED_LEGACY` 的 `.payload` 属性抛 `UnauthenticatedPayloadAccessError`；
  只有显式调用 `payload_unauthenticated()` 才能取到明文——"承认未认证"是代码级的。
- `outer_authenticity_verified=True` 是调用方的书面确认：外层签名/MAC/可信通道
  **必须先验证**，本接口不替外层机制背书。
- AEAD 路径的篡改拒绝由库异常（`DecodeError`/`VerifyError`）保证，契约不吞异常。

## 5. 逐类迁移决策

### A 类：只有加密的历史消息（CTR/CBC，无外层认证）
- **保留兼容读取**，但必须同时满足：显式 `allow_legacy_unauthenticated=True`、
  结果标记 `UNAUTHENTICATED_LEGACY`、明文仅经 `payload_unauthenticated()` 取出。
- **禁止**用于授权、金额、身份等安全决策；允许的用途限于：迁移批处理、人工审核、
  有独立可信渠道交叉核对的展示。
- **迁移动作**：持密钥方批量重包——解密（兼容路径）→ 用 AEAD 重新加密（A256GCM
  或 ChaCha20-Poly1305）→ 原子替换并记录迁移日志。无法在线重包的冷数据，补一层
  COSE_Sign 包裹或 HMAC 侧车文件，使其升格为 B 类。
- **不得**在迁移后声称"原始消息一直是可信的"——重包只是从迁移时刻起提供完整性。

### B 类：另有可信外层认证的历史消息
- 先验证外层（COSE_Sign 签名 / 通道 MAC / 可信存储证明），再解密；顺序不可颠倒，
  且外层验证失败必须整体拒绝，不能降级为 A 类处理。
- 验证通过后按 `EXTERNALLY_AUTHENTICATED` 接受，可用于正常业务。
- 仍应在外层凭证轮换/续期时顺手重包为 AEAD，消除对"外层机制永远不出错"的依赖
  （纵深防御），但无强制截止期。

### C 类：新生成的消息
- 只允许 AEAD 算法（A128GCM/A256GCM/AES-CCM/ChaCha20-Poly1305）；入口解析时
  直接拒绝非 AEAD alg（即保持 `enable_non_aead=False` 默认，永不传 True）。
- 写入路径加 CI 守卫：禁止 `enable_non_aead=True` 出现在生产代码（仅允许在
  迁移工具/测试中，配合 code owner 评审）。

## 6. 明确不声称的事

- 不从 A 类旧消息"恢复"完整性：它们从未携带 MAC/标签，任何事后检查都无法补发。
- 不把"解密成功 + 格式合法 + 声明合理"的组合当作认证的替代品。
- 不因外层认证（B 类）而声称内层密文自身可认证——背书来自外层，且仅在外层
  验证通过的时刻成立。
