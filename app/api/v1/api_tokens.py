"""API Token 管理路由

提供 Token 的创建、列表、启用/禁用、删除等管理接口。
所有接口需要 JWT 认证（通过 Web 设置页访问）。
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.db import (
    create_api_token,
    delete_api_token,
    get_api_tokens,
    update_api_token_status,
)
from app.core.token_auth import SCOPE_HIERARCHY, generate_api_token, mask_token
from app.schemas.auth import TokenData
from app.schemas.base import BaseResponse
from app.core.security import get_current_user

router = APIRouter()


class CreateTokenRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=64, description="令牌名称")
    scopes: str = Field("read", description="权限范围: read / search / download")
    expires_in_days: Optional[int] = Field(None, ge=1, le=3650, description="过期天数，不填则永不过期")


class TokenItem(BaseModel):
    id: int
    name: str
    scopes: str
    is_active: bool
    last_used_at: Optional[str] = None
    created_at: str
    expires_at: Optional[str] = None


class TokenListResponse(BaseModel):
    total: int
    items: list[TokenItem]


class CreateTokenResponse(BaseModel):
    id: int
    name: str
    token: str  # 完整 token，仅此一次展示
    scopes: str
    expires_at: Optional[str] = None
    masked: str  # 脱敏后的 token 供复制展示


@router.post("", response_model=BaseResponse[CreateTokenResponse], summary="创建 API Token")
async def create_token(
    body: CreateTokenRequest = Body(...),
    current_user: TokenData = Depends(get_current_user),
):
    """创建一个新的 API Token。
    完整 Token 仅在创建时返回，之后无法再查看。
    """
    if body.scopes not in SCOPE_HIERARCHY:
        raise HTTPException(status_code=400, detail=f"无效的权限范围，可选值: {', '.join(SCOPE_HIERARCHY.keys())}")

    raw_token, token_hash = generate_api_token()

    from datetime import datetime, timedelta

    expires_at = None
    if body.expires_in_days:
        expires_at = (datetime.now() + timedelta(days=body.expires_in_days)).strftime("%Y-%m-%d %H:%M:%S")

    token_id = create_api_token(
        name=body.name.strip(),
        token_hash=token_hash,
        scopes=body.scopes,
        expires_at=expires_at,
    )

    return BaseResponse.success(data=CreateTokenResponse(
        id=token_id,
        name=body.name.strip(),
        token=raw_token,
        scopes=body.scopes,
        expires_at=expires_at,
        masked=mask_token(raw_token),
    ))


@router.get("", response_model=BaseResponse[TokenListResponse], summary="获取 API Token 列表")
async def list_tokens(
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页数量"),
    current_user: TokenData = Depends(get_current_user),
):
    """获取所有 API Token 列表（不包含原始 token）。"""
    items, total = get_api_tokens(page, page_size)
    token_list = [
        TokenItem(
            id=item["id"],
            name=item["name"],
            scopes=item["scopes"],
            is_active=bool(item["is_active"]),
            last_used_at=item.get("last_used_at"),
            created_at=item["created_at"],
            expires_at=item.get("expires_at"),
        )
        for item in items
    ]
    return BaseResponse.success(data=TokenListResponse(total=total, items=token_list))


@router.put("/{token_id}/toggle", response_model=BaseResponse, summary="启用/禁用 API Token")
async def toggle_token(
    token_id: int,
    body: Dict[str, bool] = Body(...),
    current_user: TokenData = Depends(get_current_user),
):
    """启用或禁用指定的 API Token。请求体: {"is_active": true/false}"""
    is_active = body.get("is_active", True)
    success = update_api_token_status(token_id, is_active)
    if not success:
        raise HTTPException(status_code=404, detail="Token 不存在")
    return BaseResponse.success(message="已启用" if is_active else "已禁用")


@router.delete("/{token_id}", response_model=BaseResponse, summary="删除 API Token")
async def remove_token(
    token_id: int,
    current_user: TokenData = Depends(get_current_user),
):
    """永久删除指定的 API Token。删除后使用该 Token 的服务将立即失效。"""
    success = delete_api_token(token_id)
    if not success:
        raise HTTPException(status_code=404, detail="Token 不存在")
    return BaseResponse.success(message="Token 已删除")
