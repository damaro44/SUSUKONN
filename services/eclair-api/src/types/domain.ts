export type Role = "super_admin" | "compliance_officer" | "auditor" | "training_manager";

export interface UserRecord {
  id: string;
  fullName: string;
  email: string;
  password: string;
  role: Role;
  createdAt: string;
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

export interface DocumentRecord {
  id: string;
  title: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  category: string;
  uploadedAt: string;
  uploadedBy: string;
  encryptedPayload: EncryptedPayload;
}

export interface EncryptedPayload {
  cipherTextBase64: string;
  ivBase64: string;
  authTagBase64: string;
  keyVersion: string;
}

export type Department = "compliance" | "legal" | "finance" | "it_security" | "hr" | "operations";

export interface DocumentProcessingRecord {
  id: string;
  documentId: string;
  extractedText: string;
  ocrConfidence: number;
  routedDepartment: Department;
  routeReason: string;
  processedAt: string;
  processedBy: string;
}

export interface WorkflowTemplate {
  id: string;
  name: string;
  department: Department;
  steps: string[];
  createdAt: string;
  createdBy: string;
}

export interface WorkflowStepState {
  name: string;
  status: "Pending" | "Approved" | "Rejected";
  actedBy?: string;
  actedAt?: string;
  comment?: string;
}

export interface WorkflowRun {
  id: string;
  templateId: string;
  documentId: string;
  status: "In Progress" | "Approved" | "Rejected";
  currentStepIndex: number;
  steps: WorkflowStepState[];
  startedAt: string;
  updatedAt: string;
  startedBy: string;
}

export interface CollaborationComment {
  id: string;
  documentId: string;
  authorId: string;
  message: string;
  createdAt: string;
}

export interface DocumentVersion {
  id: string;
  documentId: string;
  versionNumber: number;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  encryptedPayload: EncryptedPayload;
  createdAt: string;
  createdBy: string;
}

export interface AuditTrailEvent {
  id: string;
  action: string;
  actorId: string;
  documentId?: string;
  metadata?: Record<string, string | number | boolean>;
  createdAt: string;
}

export type MigrationIndustry = "government" | "law_enforcement" | "hospitals" | "education";

export interface RecordsMigrationProject {
  id: string;
  name: string;
  industry: MigrationIndustry;
  organization: string;
  description: string;
  retentionYears: number;
  securityClassification: "Standard" | "Restricted" | "Confidential";
  status: "Planning" | "In Progress" | "Completed";
  createdAt: string;
  createdBy: string;
}

export interface RecordsMigrationBatch {
  id: string;
  projectId: string;
  sourceType: "Paper" | "Microfilm" | "Mixed";
  historicalRecordCount: number;
  digitizedRecordCount: number;
  qualityScore: number;
  encryptedAtRest: boolean;
  backupVerifiedAt: string;
  createdAt: string;
  createdBy: string;
}

export interface DirectMessage {
  id: string;
  senderId: string;
  recipientUserId: string;
  subject: string;
  encryptedPayload: EncryptedPayload;
  createdAt: string;
  readAt: string | null;
}
