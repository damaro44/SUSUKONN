export const API_BASE_URL = process.env.EXPO_PUBLIC_API_BASE_URL ?? "http://localhost:4100/v1";

type HttpMethod = "GET" | "POST" | "PATCH" | "DELETE";

export type EclairRole = "super_admin" | "compliance_officer" | "auditor" | "training_manager";

export interface EclairUser {
  id: string;
  fullName: string;
  email: string;
  role: EclairRole;
}

export interface AuthSession {
  token: string;
  user: EclairUser;
}

export interface DashboardPayload {
  readinessScore: number;
  riskScore: number;
  openAuditFindings: number;
  trainingPrograms: number;
  roleCoverage: number;
}

export interface AuditItem {
  id: string;
  standard: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  finding: string;
  owner: string;
  dueDate: string;
  status: "Open" | "In Progress" | "Closed";
  createdAt: string;
  createdBy: string;
}

export interface TrainingPlan {
  id: string;
  program: string;
  audience: string;
  mode: "In-person" | "Hybrid" | "Virtual";
  targetCompletion: number;
  objective: string;
  createdAt: string;
  createdBy: string;
}

interface ApiEnvelope<T> {
  data: T;
}

interface ApiErrorEnvelope {
  error: {
    code: string;
    message: string;
  };
}

export async function apiCall<T>(
  path: string,
  options: { method?: HttpMethod; token?: string; body?: unknown } = {}
): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: options.method ?? "GET",
    headers: {
      "Content-Type": "application/json",
      ...(options.token ? { Authorization: `Bearer ${options.token}` } : {})
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const payload = (await response.json()) as ApiEnvelope<T> & ApiErrorEnvelope;

  if (!response.ok) {
    throw payload;
  }

  return payload.data;
}

export async function login(email: string, password: string): Promise<AuthSession> {
  const response = await apiCall<{ accessToken: string; user: EclairUser }>("/auth/login", {
    method: "POST",
    body: { email, password }
  });

  return {
    token: response.accessToken,
    user: response.user
  };
}

export function isApiError(error: unknown): error is ApiErrorEnvelope {
  return Boolean((error as ApiErrorEnvelope)?.error?.message);
}
