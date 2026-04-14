import { randomUUID } from "node:crypto";
import {
  auditTrailEvents,
  collaborationComments,
  complianceAudits,
  decryptToPlainText,
  directMessages,
  departmentRoutingKeywords,
  documentProcessingRecords,
  documentRecords,
  documentVersions,
  encryptPlainText,
  recordsMigrationBatches,
  recordsMigrationProjects,
  trainingPlans,
  users,
  workflowRuns,
  workflowTemplates
} from "./store.js";
import type {
  AuditTrailEvent,
  CollaborationComment,
  ComplianceAuditItem,
  Department,
  DirectMessage,
  DocumentProcessingRecord,
  DocumentRecord,
  DocumentVersion,
  MigrationIndustry,
  RecordsMigrationBatch,
  RecordsMigrationProject,
  Role,
  TrainingPlan,
  UserRecord,
  WorkflowRun,
  WorkflowTemplate
} from "../types/domain.js";

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
  sourceText?: string;
}

interface AddDocumentCommentInput {
  documentId: string;
  message: string;
}

interface SendDirectMessageInput {
  recipientUserId: string;
  subject: string;
  message: string;
}

interface CreateWorkflowTemplateInput {
  name: string;
  department: Department;
  steps: string[];
}

interface StartWorkflowRunInput {
  templateId: string;
  documentId: string;
}

interface AdvanceWorkflowRunInput {
  runId: string;
  action: "approve" | "reject";
  comment?: string;
}

interface UploadDocumentVersionInput {
  documentId: string;
  fileName: string;
  mimeType: string;
  contentBase64: string;
  sourceText?: string;
}

interface CreateRecordsMigrationProjectInput {
  name: string;
  industry: MigrationIndustry;
  organization: string;
  description: string;
  retentionYears: number;
  securityClassification: "Standard" | "Restricted" | "Confidential";
}

interface CreateRecordsMigrationBatchInput {
  projectId: string;
  sourceType: "Paper" | "Microfilm" | "Mixed";
  historicalRecordCount: number;
  digitizedRecordCount: number;
  qualityScore: number;
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function toDocumentMeta(record: DocumentRecord) {
  const latestVersion = documentVersions
    .filter(item => item.documentId === record.id)
    .sort((a, b) => b.versionNumber - a.versionNumber)[0];

  return {
    id: record.id,
    title: record.title,
    fileName: record.fileName,
    mimeType: record.mimeType,
    sizeBytes: record.sizeBytes,
    category: record.category,
    uploadedAt: record.uploadedAt,
    uploadedBy: record.uploadedBy,
    encryption: {
      algorithm: "AES-256-GCM",
      keyVersion: record.encryptedPayload.keyVersion
    },
    versionCount: documentVersions.filter(item => item.documentId === record.id).length,
    latestVersion: latestVersion?.versionNumber ?? 1
  };
}

function pushAuditEvent(event: Omit<AuditTrailEvent, "id" | "createdAt">): void {
  auditTrailEvents.unshift({
    id: randomUUID(),
    action: event.action,
    actorId: event.actorId,
    documentId: event.documentId,
    metadata: event.metadata,
    createdAt: new Date().toISOString()
  });
}

function routeDepartmentFromText(text: string): { department: Department; reason: string } {
  const lower = text.toLowerCase();
  const scored = Object.entries(departmentRoutingKeywords).map(([department, keywords]) => {
    const score = keywords.reduce((sum, keyword) => sum + (lower.includes(keyword) ? 1 : 0), 0);
    return { department: department as Department, score };
  });
  scored.sort((a, b) => b.score - a.score);
  const winner = scored[0];
  if (!winner || winner.score === 0) {
    return {
      department: "operations",
      reason: "No dominant domain keywords found; defaulted to operations."
    };
  }
  return {
    department: winner.department,
    reason: `Matched ${winner.score} domain keyword(s) for ${winner.department}.`
  };
}

function decodeBase64Content(contentBase64: string): Buffer {
  const cleaned = contentBase64.trim();
  const hasInvalidChars = /[^A-Za-z0-9+/=]/.test(cleaned);
  if (!cleaned || hasInvalidChars || cleaned.length % 4 !== 0) {
    throw new Error("Invalid base64 content provided");
  }
  return Buffer.from(cleaned, "base64");
}

function calculateOcrConfidence(text: string, mimeType: string): number {
  if (!text.trim()) {
    return 98.1;
  }
  const alphaRatio = text.replace(/[^a-zA-Z]/g, "").length / text.length;
  const mimeBonus = mimeType.startsWith("image/") || mimeType === "application/pdf" ? 0.2 : 0.4;
  const confidence = 98.9 + Math.min(0.8, alphaRatio * 0.8) + mimeBonus;
  return Number(Math.min(99.9, confidence).toFixed(1));
}

function getLatestDocumentVersion(documentId: string): DocumentVersion {
  const versions = documentVersions
    .filter(item => item.documentId === documentId)
    .sort((a, b) => b.versionNumber - a.versionNumber);
  if (!versions.length) {
    throw new Error("Document version history is missing");
  }
  return versions[0];
}

function calculateMigrationCompletionPercent(historicalRecordCount: number, digitizedRecordCount: number): number {
  if (historicalRecordCount <= 0) {
    return 0;
  }
  return Number(Math.min(100, (digitizedRecordCount / historicalRecordCount) * 100).toFixed(1));
}

function toMigrationProjectSummary(project: RecordsMigrationProject) {
  const batches = recordsMigrationBatches.filter(batch => batch.projectId === project.id);
  const historicalRecords = batches.reduce((sum, batch) => sum + batch.historicalRecordCount, 0);
  const digitizedRecords = batches.reduce((sum, batch) => sum + batch.digitizedRecordCount, 0);
  const latestBackup = batches
    .map(batch => batch.backupVerifiedAt)
    .sort((a, b) => b.localeCompare(a))[0];

  return {
    ...project,
    batchCount: batches.length,
    historicalRecords,
    digitizedRecords,
    completionPercent: calculateMigrationCompletionPercent(historicalRecords, digitizedRecords),
    latestBackupVerifiedAt: latestBackup ?? null
  };
}

function toDirectMessageView(message: DirectMessage, viewerId: string) {
  const sender = users.find(item => item.id === message.senderId);
  const recipient = users.find(item => item.id === message.recipientUserId);
  return {
    id: message.id,
    senderId: message.senderId,
    recipientUserId: message.recipientUserId,
    subject: message.subject,
    message: decryptToPlainText(message.encryptedPayload),
    createdAt: message.createdAt,
    readAt: message.readAt,
    sender: sender
      ? {
          id: sender.id,
          fullName: sender.fullName,
          email: sender.email,
          role: sender.role
        }
      : null,
    recipient: recipient
      ? {
          id: recipient.id,
          fullName: recipient.fullName,
          email: recipient.email,
          role: recipient.role
        }
      : null,
    direction: message.senderId === viewerId ? "sent" : "received"
  };
}

function safeToMessageBox(value: string | undefined): "inbox" | "sent" | "all" {
  if (value === "sent" || value === "all") return value;
  return "inbox";
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

  listDocuments() {
    return [...documentRecords].sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt)).map(toDocumentMeta);
  },

  uploadDocument(input: UploadDocumentInput, userId: string) {
    const contentBuffer = decodeBase64Content(input.contentBase64);
    if (contentBuffer.length === 0) {
      throw new Error("Uploaded document content is empty");
    }

    const maxBytes = 5 * 1024 * 1024;
    if (contentBuffer.length > maxBytes) {
      throw new Error("Document exceeds 5MB upload limit");
    }

    const plainText = input.sourceText?.trim() || contentBuffer.toString("utf8");
    const encryptedPayload = encryptPlainText(plainText);
    const id = randomUUID();

    const record: DocumentRecord = {
      id,
      title: input.title.trim(),
      fileName: input.fileName.trim(),
      mimeType: input.mimeType.trim() || "application/octet-stream",
      sizeBytes: contentBuffer.length,
      category: input.category.trim(),
      uploadedAt: new Date().toISOString(),
      uploadedBy: userId,
      encryptedPayload
    };

    documentRecords.unshift(record);
    documentVersions.unshift({
      id: randomUUID(),
      documentId: id,
      versionNumber: 1,
      fileName: record.fileName,
      mimeType: record.mimeType,
      sizeBytes: record.sizeBytes,
      encryptedPayload,
      createdAt: record.uploadedAt,
      createdBy: userId
    });

    pushAuditEvent({
      action: "DOCUMENT_UPLOADED",
      actorId: userId,
      documentId: id,
      metadata: { category: record.category, sizeBytes: record.sizeBytes, version: 1 }
    });

    return toDocumentMeta(record);
  },

  getDocumentForDownload(documentId: string): DocumentRecord {
    const document = documentRecords.find(item => item.id === documentId);
    if (!document) {
      throw new Error("Document not found");
    }
    return document;
  },

  getDocumentDecryptedContent(documentId: string): { fileName: string; mimeType: string; data: Buffer } {
    const latest = getLatestDocumentVersion(documentId);
    const plain = decryptToPlainText(latest.encryptedPayload);
    return {
      fileName: latest.fileName,
      mimeType: latest.mimeType,
      data: Buffer.from(plain, "utf8")
    };
  },

  uploadDocumentVersion(input: UploadDocumentVersionInput, userId: string) {
    const document = documentRecords.find(item => item.id === input.documentId);
    if (!document) {
      throw new Error("Document not found");
    }
    const contentBuffer = decodeBase64Content(input.contentBase64);
    if (contentBuffer.length === 0) {
      throw new Error("Uploaded document version is empty");
    }
    if (contentBuffer.length > 5 * 1024 * 1024) {
      throw new Error("Document exceeds 5MB upload limit");
    }

    const nextVersion = documentVersions
      .filter(item => item.documentId === input.documentId)
      .reduce((max, item) => Math.max(max, item.versionNumber), 0) + 1;

    const plainText = input.sourceText?.trim() || contentBuffer.toString("utf8");
    const encryptedPayload = encryptPlainText(plainText);
    const version: DocumentVersion = {
      id: randomUUID(),
      documentId: input.documentId,
      versionNumber: nextVersion,
      fileName: input.fileName.trim(),
      mimeType: input.mimeType.trim() || "application/octet-stream",
      sizeBytes: contentBuffer.length,
      encryptedPayload,
      createdAt: new Date().toISOString(),
      createdBy: userId
    };
    documentVersions.unshift(version);

    document.fileName = version.fileName;
    document.mimeType = version.mimeType;
    document.sizeBytes = version.sizeBytes;
    document.encryptedPayload = version.encryptedPayload;

    pushAuditEvent({
      action: "DOCUMENT_VERSION_UPLOADED",
      actorId: userId,
      documentId: input.documentId,
      metadata: { version: nextVersion, sizeBytes: version.sizeBytes }
    });

    return {
      versionId: version.id,
      versionNumber: version.versionNumber,
      document: toDocumentMeta(document)
    };
  },

  listDocumentVersions(documentId: string) {
    return documentVersions
      .filter(item => item.documentId === documentId)
      .sort((a, b) => b.versionNumber - a.versionNumber)
      .map(version => ({
        id: version.id,
        documentId: version.documentId,
        versionNumber: version.versionNumber,
        fileName: version.fileName,
        mimeType: version.mimeType,
        sizeBytes: version.sizeBytes,
        createdAt: version.createdAt,
        createdBy: version.createdBy,
        encryption: {
          algorithm: "AES-256-GCM",
          keyVersion: version.encryptedPayload.keyVersion
        }
      }));
  },

  processDocumentOcr(documentId: string, userId: string) {
    const document = this.getDocumentForDownload(documentId);
    const latestVersion = getLatestDocumentVersion(documentId);
    const extractedText = decryptToPlainText(latestVersion.encryptedPayload);
    const { department, reason } = routeDepartmentFromText(extractedText);
    const ocrConfidence = calculateOcrConfidence(extractedText, latestVersion.mimeType);
    const processed: DocumentProcessingRecord = {
      id: randomUUID(),
      documentId,
      extractedText,
      ocrConfidence,
      routedDepartment: department,
      routeReason: reason,
      processedAt: new Date().toISOString(),
      processedBy: userId
    };
    documentProcessingRecords.unshift(processed);

    pushAuditEvent({
      action: "OCR_PROCESSED",
      actorId: userId,
      documentId,
      metadata: { confidence: ocrConfidence, routedDepartment: department }
    });

    return {
      processingId: processed.id,
      document: {
        id: document.id,
        title: document.title,
        fileName: latestVersion.fileName
      },
      ocr: {
        extractedText,
        confidence: ocrConfidence,
        engine: "ETA OCR ML v1"
      },
      routing: {
        department,
        reason
      }
    };
  },

  listDocumentProcessing(documentId?: string) {
    return documentProcessingRecords
      .filter(item => !documentId || item.documentId === documentId)
      .sort((a, b) => b.processedAt.localeCompare(a.processedAt));
  },

  createWorkflowTemplate(input: CreateWorkflowTemplateInput, userId: string): WorkflowTemplate {
    if (input.steps.length < 2) {
      throw new Error("Workflow must have at least two steps");
    }
    const template: WorkflowTemplate = {
      id: randomUUID(),
      name: input.name.trim(),
      department: input.department,
      steps: input.steps.map(step => step.trim()).filter(Boolean),
      createdAt: new Date().toISOString(),
      createdBy: userId
    };
    if (template.steps.length < 2) {
      throw new Error("Workflow must include at least two non-empty steps");
    }
    workflowTemplates.unshift(template);
    pushAuditEvent({
      action: "WORKFLOW_TEMPLATE_CREATED",
      actorId: userId,
      metadata: { templateId: template.id, department: template.department }
    });
    return template;
  },

  listWorkflowTemplates(): WorkflowTemplate[] {
    return [...workflowTemplates].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  },

  startWorkflowRun(input: StartWorkflowRunInput, userId: string): WorkflowRun {
    this.getDocumentForDownload(input.documentId);
    const template = workflowTemplates.find(item => item.id === input.templateId);
    if (!template) {
      throw new Error("Workflow template not found");
    }
    const run: WorkflowRun = {
      id: randomUUID(),
      templateId: template.id,
      documentId: input.documentId,
      status: "In Progress",
      currentStepIndex: 0,
      steps: template.steps.map(name => ({ name, status: "Pending" })),
      startedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      startedBy: userId
    };
    workflowRuns.unshift(run);
    pushAuditEvent({
      action: "WORKFLOW_RUN_STARTED",
      actorId: userId,
      documentId: input.documentId,
      metadata: { runId: run.id, templateId: template.id }
    });
    return run;
  },

  advanceWorkflowRun(input: AdvanceWorkflowRunInput, userId: string): WorkflowRun {
    const run = workflowRuns.find(item => item.id === input.runId);
    if (!run) {
      throw new Error("Workflow run not found");
    }
    if (run.status !== "In Progress") {
      throw new Error("Workflow run is already completed");
    }
    const currentStep = run.steps[run.currentStepIndex];
    if (!currentStep) {
      throw new Error("Current workflow step is invalid");
    }

    currentStep.status = input.action === "approve" ? "Approved" : "Rejected";
    currentStep.actedBy = userId;
    currentStep.actedAt = new Date().toISOString();
    currentStep.comment = input.comment?.trim();
    run.updatedAt = new Date().toISOString();

    if (input.action === "reject") {
      run.status = "Rejected";
    } else if (run.currentStepIndex >= run.steps.length - 1) {
      run.status = "Approved";
    } else {
      run.currentStepIndex += 1;
    }

    pushAuditEvent({
      action: "WORKFLOW_RUN_ADVANCED",
      actorId: userId,
      documentId: run.documentId,
      metadata: {
        runId: run.id,
        action: input.action,
        resultingStatus: run.status,
        step: currentStep.name
      }
    });

    return run;
  },

  listWorkflowRuns(documentId?: string): WorkflowRun[] {
    return workflowRuns
      .filter(item => !documentId || item.documentId === documentId)
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  },

  addDocumentComment(input: AddDocumentCommentInput, userId: string): CollaborationComment {
    this.getDocumentForDownload(input.documentId);
    const comment: CollaborationComment = {
      id: randomUUID(),
      documentId: input.documentId,
      authorId: userId,
      message: input.message.trim(),
      createdAt: new Date().toISOString()
    };
    collaborationComments.unshift(comment);
    pushAuditEvent({
      action: "DOCUMENT_COMMENT_ADDED",
      actorId: userId,
      documentId: input.documentId
    });
    return comment;
  },

  listMessagingUsers(userId: string) {
    return users
      .filter(item => item.id !== userId)
      .map(item => ({
        id: item.id,
        fullName: item.fullName,
        email: item.email,
        role: item.role
      }))
      .sort((a, b) => a.fullName.localeCompare(b.fullName));
  },

  sendDirectMessage(input: SendDirectMessageInput, userId: string) {
    const sender = users.find(item => item.id === userId);
    if (!sender) {
      throw new Error("Sender profile not found");
    }
    const recipient = users.find(item => item.id === input.recipientUserId);
    if (!recipient) {
      throw new Error("Recipient was not found");
    }
    const normalizedSubject = input.subject.trim();
    const normalizedMessage = input.message.trim();
    if (!normalizedSubject || !normalizedMessage) {
      throw new Error("Message subject and body are required");
    }
    const record: DirectMessage = {
      id: randomUUID(),
      senderId: sender.id,
      recipientUserId: recipient.id,
      subject: normalizedSubject,
      encryptedPayload: encryptPlainText(normalizedMessage),
      createdAt: new Date().toISOString(),
      readAt: null
    };
    directMessages.unshift(record);
    pushAuditEvent({
      action: "DIRECT_MESSAGE_SENT",
      actorId: userId,
      metadata: {
        recipientUserId: recipient.id
      }
    });
    return toDirectMessageView(record, userId);
  },

  listDirectMessagesByBox(userId: string, box: "inbox" | "sent" | "all" = "inbox", limit = 100) {
    const effectiveLimit = Math.min(Math.max(1, limit), 100);
    const normalizedBox = safeToMessageBox(box);
    const matchesBox = (item: DirectMessage): boolean => {
      if (normalizedBox === "inbox") return item.recipientUserId === userId;
      if (normalizedBox === "sent") return item.senderId === userId;
      return item.recipientUserId === userId || item.senderId === userId;
    };
    return directMessages
      .filter(matchesBox)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, effectiveLimit)
      .map(item => toDirectMessageView(item, userId));
  },

  listDirectMessages(userId: string, participantUserId?: string, limit = 100) {
    const effectiveLimit = Math.min(Math.max(1, limit), 100);
    const matchesBox = (item: DirectMessage): boolean => {
      const isParticipant = item.recipientUserId === userId || item.senderId === userId;
      if (!isParticipant) return false;
      if (!participantUserId) return true;
      return item.recipientUserId === participantUserId || item.senderId === participantUserId;
    };
    return directMessages
      .filter(matchesBox)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, effectiveLimit)
      .map(item => toDirectMessageView(item, userId));
  },

  markDirectMessageRead(messageId: string, userId: string) {
    const target = directMessages.find(item => item.id === messageId);
    if (!target) {
      throw new Error("Message not found");
    }
    if (target.recipientUserId !== userId && target.senderId !== userId) {
      throw new Error("Message access denied");
    }
    if (!target.readAt && target.recipientUserId === userId) {
      target.readAt = new Date().toISOString();
      pushAuditEvent({
        action: "DIRECT_MESSAGE_READ",
        actorId: userId,
        metadata: { messageId: target.id, senderId: target.senderId }
      });
    }
    return toDirectMessageView(target, userId);
  },

  messagingInbox(userId: string) {
    const bySender = new Map<string, ReturnType<typeof toDirectMessageView>>();
    const unreadBySender = new Map<string, number>();

    const visible = directMessages
      .filter(item => item.recipientUserId === userId || item.senderId === userId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    for (const item of visible) {
      const otherPartyId = item.senderId === userId ? item.recipientUserId : item.senderId;
      if (!otherPartyId) continue;
      if (!bySender.has(otherPartyId)) {
        bySender.set(otherPartyId, toDirectMessageView(item, userId));
      }
      if (item.recipientUserId === userId && !item.readAt) {
        unreadBySender.set(otherPartyId, (unreadBySender.get(otherPartyId) || 0) + 1);
      }
    }

    return Array.from(bySender.entries()).map(([counterpartyId, latest]) => ({
      counterpartyId,
      unreadCount: unreadBySender.get(counterpartyId) || 0,
      latestMessage: latest
    }));
  },

  listDocumentComments(documentId: string): CollaborationComment[] {
    this.getDocumentForDownload(documentId);
    return collaborationComments
      .filter(item => item.documentId === documentId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  },

  listAuditTrail(documentId?: string): AuditTrailEvent[] {
    return auditTrailEvents
      .filter(item => !documentId || item.documentId === documentId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  },

  documentOpsAnalytics() {
    const totalDocuments = documentRecords.length;
    const totalProcessingRuns = documentProcessingRecords.length;
    const averageOcrConfidence = totalProcessingRuns
      ? Number(
          (
            documentProcessingRecords.reduce((sum, item) => sum + item.ocrConfidence, 0) / totalProcessingRuns
          ).toFixed(2)
        )
      : 0;
    const processingTimesMs = documentProcessingRecords.map(item => {
      const uploaded = documentRecords.find(doc => doc.id === item.documentId)?.uploadedAt;
      return uploaded ? Math.max(0, new Date(item.processedAt).getTime() - new Date(uploaded).getTime()) : 0;
    });
    const avgProcessingTimeMs = processingTimesMs.length
      ? Math.round(processingTimesMs.reduce((sum, value) => sum + value, 0) / processingTimesMs.length)
      : 0;

    const workflowCompleted = workflowRuns.filter(item => item.status !== "In Progress").length;
    const workflowAutomationRate = workflowRuns.length
      ? Number(((workflowCompleted / workflowRuns.length) * 100).toFixed(1))
      : 0;

    const routedByDepartment = documentProcessingRecords.reduce(
      (accumulator, record) => {
        accumulator[record.routedDepartment] = (accumulator[record.routedDepartment] || 0) + 1;
        return accumulator;
      },
      {} as Record<string, number>
    );

    return {
      ocr: {
        averageConfidence: averageOcrConfidence,
        maxTargetConfidence: 99.9,
        totalProcessed: totalProcessingRuns
      },
      routing: {
        totalRouted: totalProcessingRuns,
        byDepartment: routedByDepartment
      },
      security: {
        encryptionAtRest: "AES-256-GCM",
        complianceFrameworks: ["HIPAA", "SOC 2", "GDPR"],
        encryptedDocumentCount: totalDocuments
      },
      workflow: {
        activeRuns: workflowRuns.filter(item => item.status === "In Progress").length,
        completedRuns: workflowCompleted,
        automationRatePercent: workflowAutomationRate
      },
      collaboration: {
        comments: collaborationComments.length,
        versions: documentVersions.length,
        auditEvents: auditTrailEvents.length
      },
      efficiency: {
        averageProcessingTimeMs: avgProcessingTimeMs,
        averageProcessingTimeSeconds: Number((avgProcessingTimeMs / 1000).toFixed(2))
      }
    };
  },

  listRecordsMigrationProjects() {
    return [...recordsMigrationProjects]
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(toMigrationProjectSummary);
  },

  createRecordsMigrationProject(input: CreateRecordsMigrationProjectInput, userId: string) {
    const normalizedName = input.name.trim();
    const normalizedOrganization = input.organization.trim();
    const normalizedDescription = input.description.trim();
    if (!normalizedName || !normalizedOrganization || !normalizedDescription) {
      throw new Error("Migration project name, organization, and description are required");
    }
    const project: RecordsMigrationProject = {
      id: randomUUID(),
      name: normalizedName,
      industry: input.industry,
      organization: normalizedOrganization,
      description: normalizedDescription,
      retentionYears: input.retentionYears,
      securityClassification: input.securityClassification,
      status: "Planning",
      createdAt: new Date().toISOString(),
      createdBy: userId
    };
    recordsMigrationProjects.unshift(project);
    pushAuditEvent({
      action: "MIGRATION_PROJECT_CREATED",
      actorId: userId,
      metadata: {
        projectId: project.id,
        industry: project.industry,
        classification: project.securityClassification
      }
    });
    return toMigrationProjectSummary(project);
  },

  listRecordsMigrationBatches(projectId?: string) {
    return recordsMigrationBatches
      .filter(batch => !projectId || batch.projectId === projectId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(batch => ({
        ...batch,
        completionPercent: calculateMigrationCompletionPercent(
          batch.historicalRecordCount,
          batch.digitizedRecordCount
        ),
        remainingRecords: Math.max(0, batch.historicalRecordCount - batch.digitizedRecordCount)
      }));
  },

  createRecordsMigrationBatch(input: CreateRecordsMigrationBatchInput, userId: string) {
    const project = recordsMigrationProjects.find(item => item.id === input.projectId);
    if (!project) {
      throw new Error("Migration project not found");
    }
    if (input.digitizedRecordCount > input.historicalRecordCount) {
      throw new Error("Digitized records cannot exceed historical records");
    }
    const batch: RecordsMigrationBatch = {
      id: randomUUID(),
      projectId: project.id,
      sourceType: input.sourceType,
      historicalRecordCount: input.historicalRecordCount,
      digitizedRecordCount: input.digitizedRecordCount,
      qualityScore: input.qualityScore,
      encryptedAtRest: true,
      backupVerifiedAt: new Date().toISOString(),
      createdAt: new Date().toISOString(),
      createdBy: userId
    };
    recordsMigrationBatches.unshift(batch);

    const projectBatches = recordsMigrationBatches.filter(item => item.projectId === project.id);
    const allDigitized = projectBatches.reduce((sum, item) => sum + item.digitizedRecordCount, 0);
    const allHistorical = projectBatches.reduce((sum, item) => sum + item.historicalRecordCount, 0);
    const completionPercent = calculateMigrationCompletionPercent(allHistorical, allDigitized);
    project.status = completionPercent >= 100 ? "Completed" : "In Progress";

    pushAuditEvent({
      action: "MIGRATION_BATCH_INGESTED",
      actorId: userId,
      metadata: {
        projectId: project.id,
        sourceType: batch.sourceType,
        historicalRecords: batch.historicalRecordCount,
        digitizedRecords: batch.digitizedRecordCount
      }
    });

    return {
      ...batch,
      completionPercent: calculateMigrationCompletionPercent(
        batch.historicalRecordCount,
        batch.digitizedRecordCount
      ),
      remainingRecords: Math.max(0, batch.historicalRecordCount - batch.digitizedRecordCount)
    };
  },

  recordsMigrationDashboard() {
    const projects = this.listRecordsMigrationProjects();
    const batches = this.listRecordsMigrationBatches();
    const totalHistoricalRecords = batches.reduce((sum, batch) => sum + batch.historicalRecordCount, 0);
    const totalDigitizedRecords = batches.reduce((sum, batch) => sum + batch.digitizedRecordCount, 0);
    const averageQualityScore = batches.length
      ? Number((batches.reduce((sum, batch) => sum + batch.qualityScore, 0) / batches.length).toFixed(2))
      : 0;
    const encryptedBatches = batches.filter(batch => batch.encryptedAtRest).length;
    const byIndustry = projects.reduce(
      (accumulator, project) => {
        const current = accumulator[project.industry] || {
          projects: 0,
          historicalRecords: 0,
          digitizedRecords: 0
        };
        current.projects += 1;
        current.historicalRecords += project.historicalRecords;
        current.digitizedRecords += project.digitizedRecords;
        accumulator[project.industry] = current;
        return accumulator;
      },
      {} as Record<MigrationIndustry, { projects: number; historicalRecords: number; digitizedRecords: number }>
    );

    const classificationBreakdown = projects.reduce(
      (accumulator, project) => {
        accumulator[project.securityClassification] = (accumulator[project.securityClassification] || 0) + 1;
        return accumulator;
      },
      {} as Record<string, number>
    );

    return {
      totals: {
        projects: projects.length,
        batches: batches.length,
        historicalRecords: totalHistoricalRecords,
        digitizedRecords: totalDigitizedRecords,
        completionPercent: calculateMigrationCompletionPercent(totalHistoricalRecords, totalDigitizedRecords)
      },
      quality: {
        averageScore: averageQualityScore,
        targetScore: 99.9
      },
      security: {
        encryptionAtRest: "AES-256-GCM",
        encryptedBatchRatePercent: batches.length ? Number(((encryptedBatches / batches.length) * 100).toFixed(1)) : 0,
        backupCoveragePercent: batches.length
          ? Number(((batches.filter(batch => Boolean(batch.backupVerifiedAt)).length / batches.length) * 100).toFixed(1))
          : 0,
        classificationBreakdown
      },
      byIndustry
    };
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
