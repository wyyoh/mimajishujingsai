import { apiError } from "./wording";

export const LOGIN_REQUIRED_EVENT = "grid:login-required";

export async function requestJSON<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...options, credentials: "same-origin" });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401 && data.detail === "LOCAL_OPERATOR_LOGIN_REQUIRED") {
      window.dispatchEvent(new Event(LOGIN_REQUIRED_EVENT));
    }
    throw new Error(typeof data.detail === "string" ? apiError(data.detail) : `请求信息不符合要求，请检查所选数据和配置（HTTP ${response.status}）。`);
  }
  return data as T;
}

export function api<T>(path: string, body?: unknown): Promise<T> {
  return requestJSON<T>(path, body === undefined ? undefined : {
    method: "POST",
    headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
    body: JSON.stringify(body),
  });
}
