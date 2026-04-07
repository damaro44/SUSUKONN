import { randomUUID } from "node:crypto";
import { complianceAudits, documentRecords, trainingPlans, users } from "./store.js";
import type { ComplianceAuditItem, DocumentRecord, Role, TrainingPlan, UserRecord } from "../types/domain.js";

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

interface RegisterInput {
  fullName: string;
  email: string;
  password: string;
  role: Exclude<Role, "super_admin">;
}

interface UploadDocumentInput {
  title: string;
  category: string;
  fileName: string;
  mimeType: string;
  contentBase64: string;
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export const eclairService = {
  login(email: string, password: string): UserRecord | null {
    const user = users.find(item => item.email.toLowerCase() === normalizeEmail(email));
    if (!user || user.password !== password) {
      return null;
    }
    return user;
  },

  register(input: RegisterInput): UserRecord {
    const normalizedEmail = normalizeEmail(input.email);
    const exists = users.some(item => item.email.toLowerCase() === normalizedEmail);
    if (exists) {
      throw new Error("Email is already registered");
    }

    const user: UserRecord = {
      id: randomUUID(),
      fullName: input.fullName.trim(),
      email: normalizedEmail,
      password: input.password,
      role: input.role,
      createdAt: new Date().toISOString()
    };

    users.unshift(user);
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

  listDocuments(): Omit<DocumentRecord, "contentBase64">[] {
    return [...documentRecords]
      .sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt))
      .map(({ contentBase64: _contentBase64, ...rest }) => rest);
  },

  uploadDocument(input: UploadDocumentInput, userId: string): Omit<DocumentRecord, "contentBase64"> {
    const contentBuffer = Buffer.from(input.contentBase64, "base64");
    if (contentBuffer.length === 0) {
      throw new Error("Uploaded document content is empty");
    }

    const maxBytes = 5 * 1024 * 1024;
    if (contentBuffer.length > maxBytes) {
      throw new Error("Document exceeds 5MB upload limit");
    }

    const record: DocumentRecord = {
      id: randomUUID(),
      title: input.title.trim(),
      fileName: input.fileName.trim(),
      mimeType: input.mimeType.trim() || "application/octet-stream",
      sizeBytes: contentBuffer.length,
      category: input.category.trim(),
      uploadedAt: new Date().toISOString(),
      uploadedBy: userId,
      contentBase64: input.contentBase64
    };

    documentRecords.unshift(record);
    const { contentBase64: _contentBase64, ...meta } = record;
    return meta;
  },

  getDocumentForDownload(documentId: string): DocumentRecord {
    const document = documentRecords.find(item => item.id === documentId);
    if (!document) {
      throw new Error("Document not found");
    }
    return document;
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
