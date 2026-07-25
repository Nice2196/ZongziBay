// @ts-ignore
/* eslint-disable */
import request from "@/request";

/** 创建 API Token POST /api/v1/api-tokens */
export async function createApiToken(
  body: { name: string; scopes: string; expires_in_days?: number | null },
  options?: { [key: string]: any }
) {
  return request<API.BaseResponse & {
    data?: {
      id: number
      name: string
      token: string
      scopes: string
      expires_at: string | null
      masked: string
    }
  }>("/api/v1/api-tokens", {
    method: "POST",
    data: body,
    ...(options || {}),
  });
}

/** 获取 API Token 列表 GET /api/v1/api-tokens */
export async function getApiTokens(
  params?: { page?: number; page_size?: number },
  options?: { [key: string]: any }
) {
  return request<API.BaseResponse & {
    data?: {
      total: number
      items: {
        id: number
        name: string
        scopes: string
        is_active: boolean
        last_used_at: string | null
        created_at: string
        expires_at: string | null
      }[]
    }
  }>("/api/v1/api-tokens", {
    method: "GET",
    params,
    ...(options || {}),
  });
}

/** 启用/禁用 API Token PUT /api/v1/api-tokens/{id}/toggle */
export async function toggleApiToken(
  tokenId: number,
  isActive: boolean,
  options?: { [key: string]: any }
) {
  return request<API.BaseResponse>(
    `/api/v1/api-tokens/${tokenId}/toggle`,
    { method: "PUT", data: { is_active: isActive }, ...(options || {}) }
  );
}

/** 删除 API Token DELETE /api/v1/api-tokens/{id} */
export async function deleteApiToken(
  tokenId: number,
  options?: { [key: string]: any }
) {
  return request<API.BaseResponse>(
    `/api/v1/api-tokens/${tokenId}`,
    { method: "DELETE", ...(options || {}) }
  );
}
