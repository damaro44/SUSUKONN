export type Role = "super_admin" | "compliance_officer" | "auditor" | "training_manager";

export interface UserRecord {
  id: string;
  fullName: string;
  email: string;
  password: string;
  role: Role;
}

export interface ComplianceAuditItem {
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
