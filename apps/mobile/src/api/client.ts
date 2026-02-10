import { AuthUserView } from "@susukonnect/shared";

export const API_BASE_URL =
  process.env.EXPO_PUBLIC_API_BASE_URL ?? "http://localhost:4000/v1";

type HttpMethod = "GET" | "POST" | "PATCH" | "DELETE";

export interface ApiErrorShape {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
  data?: unknown;
}

export interface MfaChallengePayload {
  challengeId: string;
  expiresAt?: string;
  demoCode?: string;
}

export interface AuthSession {
  token: string;
  expiresAt: string;
  user: AuthUserView;
}

export async function apiCall<T>(
  path: string,
  options: {
    method?: HttpMethod;
    token?: string;
    body?: unknown;
  } = {}
): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: options.method ?? "GET",
    headers: {
      "Content-Type": "application/json",
      ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const payload = (await response.json()) as { data?: T } & ApiErrorShape;
  if (!response.ok) {
    throw payload;
  }
  return payload.data as T;
}

export function isMfaRequiredError(error: unknown): error is ApiErrorShape & { data: MfaChallengePayload } {
  const candidate = error as ApiErrorShape;
  return candidate?.error?.code === "MFA_REQUIRED";
}
