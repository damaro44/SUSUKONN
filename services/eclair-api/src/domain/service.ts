import { randomUUID } from "node:crypto";
import { complianceAudits, trainingPlans, users } from "./store.js";
import type { ComplianceAuditItem, TrainingPlan, UserRecord } from "../types/domain.js";

interface CreateAuditInput {
  standard: string;
  severity: ComplianceAuditItem["severity"];
  finding: string;
  owner: string;
  dueDate: string;
}

interface CreateTrainingInput {
  program: string;
  audience: string;
  mode: TrainingPlan["mode"];
  targetCompletion: number;
  objective: string;
}

export const eclairService = {
  login(email: string, password: string): UserRecord | null {
    const user = users.find(item => item.email.toLowerCase() === email.toLowerCase());
    if (!user || user.password !== password) {
      return null;
    }
    return user;
  },

  getProfile(userId: string): UserRecord {
    const user = users.find(item => item.id === userId);
    if (!user) {
      throw new Error("User not found");
    }
    return user;
  },

  listAudits(): ComplianceAuditItem[] {
    return [...complianceAudits].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  },

  createAudit(input: CreateAuditInput, userId: string): ComplianceAuditItem {
    const record: ComplianceAuditItem = {
      id: randomUUID(),
      standard: input.standard,
      severity: input.severity,
      finding: input.finding,
      owner: input.owner,
      dueDate: input.dueDate,
      status: "Open",
      createdAt: new Date().toISOString(),
      createdBy: userId
    };

    complianceAudits.unshift(record);
    return record;
  },

  updateAuditStatus(auditId: string, status: ComplianceAuditItem["status"]): ComplianceAuditItem {
    const target = complianceAudits.find(item => item.id === auditId);
    if (!target) {
      throw new Error("Audit item not found");
    }
    target.status = status;
    return target;
  },

  listTrainingPlans(): TrainingPlan[] {
    return [...trainingPlans].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  },

  createTrainingPlan(input: CreateTrainingInput, userId: string): TrainingPlan {
    const record: TrainingPlan = {
      id: randomUUID(),
      program: input.program,
      audience: input.audience,
      mode: input.mode,
      targetCompletion: input.targetCompletion,
      objective: input.objective,
      createdAt: new Date().toISOString(),
      createdBy: userId
    };

    trainingPlans.unshift(record);
    return record;
  },

  dashboard() {
    const severityWeight: Record<ComplianceAuditItem["severity"], number> = {
      Critical: 20,
      High: 12,
      Medium: 6,
      Low: 3
    };

    const riskScore = Math.min(
      100,
      complianceAudits.reduce((sum, item) => sum + severityWeight[item.severity], 0)
    );

    const readiness = Math.max(8, Math.min(98, 75 - Math.floor(riskScore / 2) + trainingPlans.length * 3));

    return {
      readinessScore: readiness,
      riskScore,
      openAuditFindings: complianceAudits.filter(item => item.status !== "Closed").length,
      trainingPrograms: trainingPlans.length,
      roleCoverage: [...new Set(users.map(user => user.role))].length
    };
  }
};
