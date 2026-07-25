"""API Token 生成与验证模块

Token 格式: zbi_ + 44 位 base64url 随机字符（共 48 字符）
存储时使用 SHA-256 哈希，原始 token 仅在创建时返回一次。
"""

import hashlib
import secrets
from datetime import datetime
from typing import Optional, Tuple


def generate_api_token() -> Tuple[str, str]:
    """生成 API Token。

    Returns:
        (raw_token, token_hash): 原始 token 和 SHA-256 哈希
        原始 token 仅在创建时展示一次，后续用哈希验证。
    """
    raw_bytes = secrets.token_bytes(32)
    raw_token = "zbi_" + secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return raw_token, token_hash


def hash_token(raw_token: str) -> str:
    """对原始 token 做 SHA-256 哈希"""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def mask_token(raw_token: str) -> str:
    """脱敏展示 token：保留前缀和后 4 位"""
    if len(raw_token) <= 12:
        return raw_token[:4] + "****"
    return raw_token[:7] + "****" + raw_token[-4:]


SCOPE_HIERARCHY = {
    "read": {"read"},
    "search": {"read", "search"},
    "download": {"read", "search", "download"},
}


def has_scope(token_scopes: str, required: str) -> bool:
    """检查 token 是否拥有指定的权限。

    token_scopes 是逗号分隔的字符串，如 "read,search"。
    层级：download > search > read（download 包含所有低级权限）。
    """
    if not token_scopes:
        token_scopes = "read"
    scopes = set(s.strip() for s in token_scopes.split(",") if s.strip())
    allowed = set()
    for s in scopes:
        if s in SCOPE_HIERARCHY:
            allowed |= SCOPE_HIERARCHY[s]
        else:
            allowed.add(s)
    return required in allowed
