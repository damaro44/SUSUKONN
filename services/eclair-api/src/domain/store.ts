import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID
} from "node:crypto";
import type {
  AuditTrailEvent,
  CollaborationComment,
  ComplianceAuditItem,
  Department,
  DocumentProcessingRecord,
  DocumentRecord,
  DocumentVersion,
  EncryptedPayload,
  TrainingPlan,
  UserRecord,
  WorkflowRun,
  WorkflowTemplate
} from "../types/domain.js";

const now = () => new Date().toISOString();

const ENCRYPTION_KEY_VERSION = "v1";
const ENCRYPTION_KEY = createHash("sha256")
  .update(process.env.ECLAIR_STORAGE_SECRET || "change-this-storage-secret-before-production")
  .digest();

export function encryptPlainText(plainText: string): EncryptedPayload {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    cipherTextBase64: encrypted.toString("base64"),
    ivBase64: iv.toString("base64"),
    authTagBase64: authTag.toString("base64"),
    keyVersion: ENCRYPTION_KEY_VERSION
  };
}

export function decryptToPlainText(payload: EncryptedPayload): string {
  const decipher = createDecipheriv("aes-256-gcm", ENCRYPTION_KEY, Buffer.from(payload.ivBase64, "base64"));
  decipher.setAuthTag(Buffer.from(payload.authTagBase64, "base64"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload.cipherTextBase64, "base64")),
    decipher.final()
  ]);
  return decrypted.toString("utf8");
}

function auditEvent(action: string, actorId: string, documentId?: string, metadata?: AuditTrailEvent["metadata"]): AuditTrailEvent {
  return {
    id: randomUUID(),
    action,
    actorId,
    documentId,
    metadata,
    createdAt: now()
  };
}

export const users: UserRecord[] = [
  {
    id: "u-admin",
    fullName: "Eclair Super Admin",
    email: "admin@eclair.tech",
    password: "Admin@2026",
    role: "super_admin",
    createdAt: now()
  },
  {
    id: "u-compliance",
    fullName: "Compliance Lead",
    email: "compliance@eclair.tech",
    password: "Compliance@2026",
    role: "compliance_officer",
    createdAt: now()
  },
  {
    id: "u-auditor",
    fullName: "Government Auditor",
    email: "auditor@eclair.tech",
    password: "Auditor@2026",
    role: "auditor",
    createdAt: now()
  },
  {
    id: "u-training",
    fullName: "Training Manager",
    email: "training@eclair.tech",
    password: "Training@2026",
    role: "training_manager",
    createdAt: now()
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

const sampleDocPayload = encryptPlainText("ETA evidence pack sample content for audits and governance records.");

export const documentRecords: DocumentRecord[] = [
  {
    id: "doc-1",
    title: "Sample Compliance Evidence",
    fileName: "eta-sample-evidence.txt",
    mimeType: "text/plain",
    sizeBytes: 66,
    category: "compliance_evidence",
    uploadedAt: now(),
    uploadedBy: "u-compliance",
    encryptedPayload: sampleDocPayload
  }
];

export const documentProcessingRecords: DocumentProcessingRecord[] = [
  {
    id: "proc-1",
    documentId: "doc-1",
    extractedText: "ETA evidence pack sample content for audits and governance records.",
    ocrConfidence: 99.9,
    routedDepartment: "compliance",
    routeReason: "Detected compliance and evidence terminology",
    processedAt: now(),
    processedBy: "u-compliance"
  }
];

export const workflowTemplates: WorkflowTemplate[] = [
  {
    id: "wf-template-1",
    name: "Compliance Evidence Approval",
    department: "compliance",
    steps: ["Initial Review", "Manager Approval", "Archive"],
    createdAt: now(),
    createdBy: "u-admin"
  }
];

export const workflowRuns: WorkflowRun[] = [];

export const collaborationComments: CollaborationComment[] = [];

export const documentVersions: DocumentVersion[] = [
  {
    id: "docv-1",
    documentId: "doc-1",
    versionNumber: 1,
    fileName: "eta-sample-evidence.txt",
    mimeType: "text/plain",
    sizeBytes: 66,
    encryptedPayload: sampleDocPayload,
    createdAt: now(),
    createdBy: "u-compliance"
  }
];

export const auditTrailEvents: AuditTrailEvent[] = [
  auditEvent("DOCUMENT_UPLOADED", "u-compliance", "doc-1", { category: "compliance_evidence", version: 1 }),
  auditEvent("OCR_PROCESSED", "u-compliance", "doc-1", { confidence: 99.9, department: "compliance" })
];

export const departmentRoutingKeywords: Record<Department, string[]> = {
  compliance: ["compliance", "audit", "parae", "control", "evidence", "regulation", "governance"],
  legal: ["contract", "law", "legal", "policy", "agreement", "terms"],
  finance: ["budget", "invoice", "payment", "procurement", "finance", "cost"],
  it_security: ["security", "cyber", "vulnerability", "access", "encryption", "risk"],
  hr: ["staff", "employee", "training", "recruitment", "human resources", "personnel"],
  operations: ["workflow", "operations", "service", "delivery", "process", "ticket"]
};
