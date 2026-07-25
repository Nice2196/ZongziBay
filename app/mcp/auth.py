"""MCP 工具权限检查模块

每个 MCP 工具调用都会经过 auth 中间件，中间件将 API Token 的 scopes
存入 ContextVar，工具在执行前通过 require_scope() 检查权限。
"""

from contextvars import ContextVar

from app.core.token_auth import has_scope

# ContextVar: 由中间件在每次 MCP 请求时设置，工具执行时读取
_mcp_scopes: ContextVar[str] = ContextVar("_mcp_scopes", default="read")


# 每个 MCP 工具所需的权限级别
# read    — 只读查询（任务列表、媒体信息、系统状态）
# search  — 搜索类（种子搜索、字幕搜索、磁力解析）
# download — 写操作（提交下载、取消任务）
MCP_TOOL_SCOPES: dict[str, str] = {
    "search_torrents": "search",
    "parse_magnet": "search",
    "add_download": "download",
    "list_downloads": "read",
    "cancel_download": "download",
    "search_movie": "read",
    "search_tv": "read",
    "get_trending": "read",
    "get_media_detail": "read",
    "get_bangumi_calendar": "read",
    "search_subtitles": "search",
    "get_system_status": "read",
}


class MCPPermissionError(Exception):
    """MCP 工具权限不足异常。由 FastMCP 框架捕获后返回给客户端。"""

    def __init__(self, required: str, current: str):
        self.required = required
        self.current = current
        super().__init__(
            f"权限不足：此操作需要 {required} 权限，"
            f"当前 API Token 仅拥有 {current} 权限。"
            f"请在 ZongziBay 设置页生成具有 {required} 权限的 Token。"
        )


def set_mcp_scopes(scopes: str) -> None:
    """由 auth 中间件调用，为当前请求设置 token 的 scopes。"""
    _mcp_scopes.set(scopes if scopes else "read")


def require_scope(required: str) -> None:
    """检查当前 MCP 请求是否有足够权限。

    Args:
        required: 需要的权限级别 (read / search / download)

    Raises:
        MCPPermissionError: 权限不足时抛出，FastMCP 将转换为 MCP 错误响应
    """
    scopes = _mcp_scopes.get()
    if not has_scope(scopes, required):
        raise MCPPermissionError(required, scopes)
