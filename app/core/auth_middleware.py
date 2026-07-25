import asyncio
import logging
import os
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import config
from app.core.db import ensure_api_token_table, get_api_token_by_hash, update_api_token_last_used
from app.core.token_auth import hash_token
from app.core.security import get_algorithm, get_secret_key

logger = logging.getLogger(__name__)

# API Token 白名单：使用 API Token 访问时不需要 scope 检查的路径前缀
# 所有路径需要 token 有 read scope 作为基础
_API_TOKEN_SCOPE_REQUIRED: dict[str, str] = {
    # read scope — 查询类接口
    "/api/v1/tasks/list": "read",
    "/api/v1/tmdb/": "read",
    "/api/v1/bangumi/": "read",
    "/api/v1/piratebay/search": "search",
    "/api/v1/anime/": "search",
    "/api/v1/subtitle/sub/search": "search",
    "/api/v1/subtitle/user/quota": "search",
    "/api/v1/system/status": "read",
    "/api/v1/system/paths": "read",
    "/api/v1/system/rename-templates": "read",
    "/api/v1/system/trackers": "read",
    "/api/v1/health": "read",
    "/api/v1/notifications/": "read",
    # download scope — 操作类接口
    "/api/v1/magnet/": "download",
    "/api/v1/tasks/add": "download",
    "/api/v1/tasks/cancel": "download",
    "/api/v1/subtitle/sub/download": "download",
}

# API Token 管理接口必须用 Web 登录的 JWT，不允许用 API Token 访问
_API_TOKEN_BLOCKED_PREFIXES = [
    "/api/v1/api-tokens",
]

# 放行白名单：无需 JWT 认证的接口路径
_AUTH_WHITELIST = [
    "/api/v1/users/login",
    "/api/v1/users/refresh",
    "/api/v1/health",
    "/api/v1/system/status",
    "/api/v1/system/env-config",
    "/api/v1/system/existing-config",
    "/api/v1/system/setup",
    "/api/v1/system/test-connection",
    "/api/v1/system/preferences",
    "/api/v1/system/config/apply-default-tmdb-key",
    "/api/v1/system/config/apply-default-assrt-key",
]

# Cookie 名称后缀：与 users.py 保持一致，支持多实例
_COOKIE_SUFFIX = os.getenv("ZONGZI_COOKIE_SUFFIX", "")
_ACCESS_TOKEN_COOKIE = f"access_token{'_' + _COOKIE_SUFFIX if _COOKIE_SUFFIX else ''}"


def _verify_token_sync(token: str) -> Optional[str]:
    """同步校验 JWT，在线程池中调用以避免阻塞事件循环。返回 username 或 None。"""
    try:
        payload = jwt.decode(token, get_secret_key(), algorithms=[get_algorithm()])
        if payload.get("type") != "access":
            return None
        username = payload.get("sub")
        if not username or username != config.get("security.username"):
            return None
        return username
    except JWTError:
        return None


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """
    全局 JWT 认证中间件
    - 仅拦截 /api/ 开头的请求
    - 白名单中的路径无需认证，直接放行
    - 支持 API Token（zbi_ 前缀），通过数据库验证
    - 其余 API 请求必须携带有效的 Bearer Token 或 httpOnly Cookie
    - 优先从 Cookie 读取 Token，其次从 Authorization 头读取
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path.rstrip("/")

        # 非 API / MCP 路径直接放行（静态文件、前端页面、Swagger 文档等）
        if not path.startswith("/api/") and not path.startswith("/mcp"):
            return await call_next(request)

        # OPTIONS 预检请求直接放行（配合 CORS 中间件）
        if request.method == "OPTIONS":
            return await call_next(request)

        # 白名单路径直接放行
        for wp in _AUTH_WHITELIST:
            wp_clean = wp.rstrip("/")
            if path == wp_clean or path.startswith(wp_clean + "/"):
                return await call_next(request)

        # 提取 Token：API Token（zbi_ 前缀）优先于 JWT Cookie
        # 这样外部 MCP 客户端在 Authorization 头传 API Token 时不会
        # 被浏览器自动携带的 JWT Cookie 覆盖
        token: Optional[str] = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            bearer = auth_header[len("Bearer "):]
            if bearer.startswith("zbi_"):
                token = bearer  # API Token 优先

        if not token:
            token = request.cookies.get(_ACCESS_TOKEN_COOKIE)

        if not token:
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header[len("Bearer "):]

        if not token:
            return self._unauthorized("未登录，请先登录")

        # --- API Token 验证（zbi_ 前缀）---
        if token.startswith("zbi_"):
            return await self._verify_api_token(request, token, path, call_next)

        # --- JWT 验证 ---
        username = await asyncio.to_thread(_verify_token_sync, token)
        if username is None:
            return self._unauthorized("无效的凭证或凭证已过期")

        return await call_next(request)

    async def _verify_api_token(self, request: Request, token: str, path: str, call_next):
        """验证 API Token 并检查权限"""
        # 确保 api_token 表存在
        ensure_api_token_table()

        # API Token 管理接口不允许用 API Token 访问
        for blocked in _API_TOKEN_BLOCKED_PREFIXES:
            if path == blocked or path.startswith(blocked + "/"):
                return self._unauthorized("API Token 无权访问令牌管理接口")

        token_hash = hash_token(token)
        token_data = get_api_token_by_hash(token_hash)
        if token_data is None:
            return self._unauthorized("API Token 无效或已过期")

        # MCP 路径：设置 scopes contextvar，各 tool 内部通过 require_scope() 做权限检查
        if path.startswith("/mcp"):
            from app.mcp.auth import set_mcp_scopes
            set_mcp_scopes(token_data.get("scopes", "read"))
            try:
                update_api_token_last_used(token_data["id"])
            except Exception:
                pass
            return await call_next(request)

        # 确定需要的 scope
        required_scope = "read"  # 默认最小权限
        for prefix, scope in _API_TOKEN_SCOPE_REQUIRED.items():
            if path == prefix.rstrip("/") or path.startswith(prefix.rstrip("/") + "/") or path.startswith(prefix):
                required_scope = scope
                break

        # 检查权限
        from app.core.token_auth import has_scope
        if not has_scope(token_data.get("scopes", "read"), required_scope):
            return self._unauthorized(f"API Token 权限不足，需要 {required_scope} 权限")

        # 更新最后使用时间（异步）
        try:
            update_api_token_last_used(token_data["id"])
        except Exception:
            pass

        return await call_next(request)

    @staticmethod
    def _unauthorized(message: str) -> JSONResponse:
        """返回统一的未认证响应（与 BaseResponse 格式一致，code=40100）"""
        return JSONResponse(
            status_code=200,
            content={"code": 40100, "message": message, "data": None}
        )
