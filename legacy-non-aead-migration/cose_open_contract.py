# -*- coding: utf-8 -*-
"""
接口契约（参考实现）：统一 COSE 消息开封入口。

设计原则：
1. 返回值永远不裸给 bytes —— 每条消息都带强制性的 authenticity 分级。
2. 非 AEAD 默认拒绝（与 python-cwt 的 enable_non_aead=False 默认一致）。
3. 兼容读取历史消息必须显式 opt-in，且未认证明文只能通过显式命名的
   逃生门方法取得，防止被无意当作已验证数据使用。
4. 外层认证（如 COSE_Sign 包裹、通道 MAC）必须由调用方先验证并显式声明；
   本模块不替外层机制背书，也不从旧消息中"恢复"它从未携带的完整性。
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any

import cbor2

from cwt import COSE
from cwt.cose_key_interface import COSEKeyInterface
from cwt.const import COSE_ALGORITHMS_CEK_NON_AEAD

NON_AEAD_ALGS: frozenset[int] = frozenset(COSE_ALGORITHMS_CEK_NON_AEAD.values())


class Authenticity(enum.Enum):
    """消息真实性的三个互斥等级，调用方必须据此分支处理。"""

    AEAD_VERIFIED = "aead-verified"
    """消息自身携带密码学完整性（A*-GCM / A*-CCM / ChaCha20-Poly1305），篡改必然被拒绝。"""

    EXTERNALLY_AUTHENTICATED = "externally-authenticated"
    """非 AEAD 旧消息，但调用方已验证可信的外层认证（签名/MAC/可信通道）。"""

    UNAUTHENTICATED_LEGACY = "unauthenticated-legacy"
    """非 AEAD 旧消息，仅有机密性。明文可被任意篡改，禁止用于授权决策。"""


class PolicyRejectionError(Exception):
    """策略拒绝：默认配置下遇到非 AEAD 算法，或调用方未显式 opt-in。"""


class UnauthenticatedPayloadAccessError(Exception):
    """试图通过常规属性访问未认证明文。"""


@dataclass(frozen=True)
class OpenedMessage:
    """开封结果。payload 的访问级别由 authenticity 决定。"""

    _payload: bytes
    authenticity: Authenticity
    alg: int
    protected: dict[str | int, Any]
    unprotected: dict[str | int, Any]

    @property
    def payload(self) -> bytes:
        """已认证明文的常规入口；对未认证旧消息一律抛异常。"""
        if self.authenticity is Authenticity.UNAUTHENTICATED_LEGACY:
            raise UnauthenticatedPayloadAccessError(
                "该消息仅加密未认证（非 AEAD 历史消息），明文可能被篡改。"
                "如确需读取，请显式调用 payload_unauthenticated() 并自行承担风险。"
            )
        return self._payload

    def payload_unauthenticated(self) -> bytes:
        """显式逃生门：调用即表示调用方书面承认明文未经验证。"""
        return self._payload


def _peek_alg(data: bytes) -> int:
    """在不解密的前提下读取 alg（非 AEAD 的 alg 在 unprotected 头中）。"""
    tag = cbor2.loads(data)
    if not isinstance(tag, cbor2.CBORTag) or tag.tag not in (16, 96):
        raise ValueError(f"不是 COSE_Encrypt0/Encrypt 消息 (tag={getattr(tag, 'tag', None)})")
    protected_bstr, unprotected, _ = tag.value
    protected = cbor2.loads(protected_bstr) if protected_bstr else {}
    return protected.get(1, unprotected.get(1, 0))


def open_cose_message(
    data: bytes,
    keys: COSEKeyInterface | list[COSEKeyInterface],
    *,
    allow_legacy_unauthenticated: bool = False,
    outer_authenticity_verified: bool = False,
) -> OpenedMessage:
    """
    统一开封入口。

    Args:
        data: COSE_Encrypt0/Encrypt 编码字节。
        keys: 解密密钥。
        allow_legacy_unauthenticated: 显式允许读取非 AEAD 历史消息（兼容开关）。
        outer_authenticity_verified: 调用方声明已验证外层认证（签名/MAC/可信通道）。
            仅声明不够——调用方必须先完成验证；本参数是契约上的书面确认。

    Returns:
        OpenedMessage，authenticity 字段指示三级真实性之一。

    Raises:
        PolicyRejectionError: 非 AEAD 且未显式 opt-in。
        DecodeError/VerifyError: AEAD 验证失败或解密失败（篡改即拒绝）。
    """
    alg = _peek_alg(data)
    cose = COSE.new()

    if alg not in NON_AEAD_ALGS:
        # AEAD：解密与完整性验证原子绑定，失败即抛异常。
        p, u, payload = cose.decode_with_headers(data, keys)
        return OpenedMessage(payload, Authenticity.AEAD_VERIFIED, alg, p, u)

    if not allow_legacy_unauthenticated:
        raise PolicyRejectionError(
            f"拒绝非 AEAD 历史算法 alg={alg}。如需兼容读取，"
            "请显式设置 allow_legacy_unauthenticated=True，"
            "并按返回的 authenticity 分级处理。"
        )

    p, u, payload = cose.decode_with_headers(data, keys, enable_non_aead=True)
    level = (
        Authenticity.EXTERNALLY_AUTHENTICATED
        if outer_authenticity_verified
        else Authenticity.UNAUTHENTICATED_LEGACY
    )
    return OpenedMessage(payload, level, alg, p, u)
