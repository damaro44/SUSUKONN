import type { ComplianceAuditItem, TrainingPlan, UserRecord } from "../types/domain.js";

const now = () => new Date().toISOString();

export const users: UserRecord[] = [
  {
    id: "u-admin",
    fullName: "Eclair Super Admin",
    email: "admin@eclair.tech",
    password: "Admin@2026",
    role: "super_admin"
  },
  {
    id: "u-compliance",
    fullName: "Compliance Lead",
    email: "compliance@eclair.tech",
    password: "Compliance@2026",
    role: "compliance_officer"
  },
  {
    id: "u-auditor",
    fullName: "Government Auditor",
    email: "auditor@eclair.tech",
    password: "Auditor@2026",
    role: "auditor"
  },
  {
    id: "u-training",
    fullName: "Training Manager",
    email: "training@eclair.tech",
    password: "Training@2026",
    role: "training_manager"
  }
];

export const complianceAudits: ComplianceAuditItem[] = [
  {
    id: "audit-1",
    standard: "PARAE Control P-07",
    severity: "High",
    finding: "AI-assisted decisions are missing centralized evidence references.",
    owner: "ICT Directorate",
    dueDate: "2026-06-30",
    status: "Open",
    createdAt: now(),
    createdBy: "u-compliance"
  },
  {
    id: "audit-2",
    standard: "National Digital Standard NDS-12",
    severity: "Medium",
    finding: "Service-level monitoring is not consistent across digital channels.",
    owner: "Service Operations",
    dueDate: "2026-07-20",
    status: "In Progress",
    createdAt: now(),
    createdBy: "u-auditor"
  }
];

export const trainingPlans: TrainingPlan[] = [
  {
    id: "training-1",
    program: "Responsible AI in Public Service",
    audience: "Policy and service teams",
    mode: "Hybrid",
    targetCompletion: 90,
    objective: "Operationalize compliant AI workflow governance across ministries.",
    createdAt: now(),
    createdBy: "u-training"
  }
];
