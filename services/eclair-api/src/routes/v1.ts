import { Router } from "express";
import { z } from "zod";
import { signAccessToken } from "../auth/authService.js";
import { eclairService } from "../domain/service.js";
import { requireAuth, requireRole } from "../middleware/auth.js";
import { buildComplianceCsv } from "../utils/csv.js";
import { buildCompliancePdfBuffer } from "../utils/pdf.js";

export const v1Router = Router();
function pathParam(value: string | string[] | undefined): string {
  if (!value) {
    return "";
  }
  return Array.isArray(value) ? value[0] : value;
}

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8)
});

const registerSchema = z.object({
  fullName: z.string().min(2),
  email: z.string().email(),
  password: z
    .string()
    .min(8)
    .regex(/[A-Z]/, "Password must include at least one uppercase letter")
    .regex(/[a-z]/, "Password must include at least one lowercase letter")
    .regex(/[0-9]/, "Password must include at least one number"),
  role: z.enum(["compliance_officer", "auditor", "training_manager"])
});

const createAuditSchema = z.object({
  standard: z.string().min(2),
  severity: z.enum(["Critical", "High", "Medium", "Low"]),
  finding: z.string().min(4),
  owner: z.string().min(2),
  dueDate: z.string().min(8)
});

const updateAuditStatusSchema = z.object({
  status: z.enum(["Open", "In Progress", "Closed"])
});

const createTrainingSchema = z.object({
  program: z.string().min(2),
  audience: z.string().min(2),
  mode: z.enum(["In-person", "Hybrid", "Virtual"]),
  targetCompletion: z.number().min(1).max(100),
  objective: z.string().min(4)
});

const uploadDocumentSchema = z.object({
  title: z.string().min(2),
  category: z.string().min(2),
  fileName: z.string().min(1),
  mimeType: z.string().min(1),
  contentBase64: z.string().min(4)
});

const uploadDocumentVersionSchema = z.object({
  documentId: z.string().min(1),
  fileName: z.string().min(1),
  mimeType: z.string().min(1),
  contentBase64: z.string().min(4)
});

const workflowTemplateSchema = z.object({
  name: z.string().min(2),
  department: z.enum(["compliance", "legal", "finance", "it_security", "hr", "operations"]),
  steps: z.array(z.string().min(1)).min(2)
});

const workflowRunStartSchema = z.object({
  templateId: z.string().min(1),
  documentId: z.string().min(1)
});

const workflowRunAdvanceSchema = z.object({
  runId: z.string().min(1),
  action: z.enum(["approve", "reject"]),
  comment: z.string().max(500).optional()
});

const workflowRunsQuerySchema = z.object({
  documentId: z.string().min(1).optional()
});

const commentSchema = z.object({
  documentId: z.string().min(1),
  message: z.string().min(2).max(1000)
});

const directMessageSendSchema = z.object({
  recipientUserId: z.string().min(1),
  subject: z.string().min(2).max(160),
  message: z.string().min(1).max(2000)
});

const directMessageListQuerySchema = z.object({
  userId: z.string().min(1).optional(),
  limit: z.coerce.number().int().min(1).max(100).optional()
});

const migrationProjectSchema = z.object({
  name: z.string().min(3),
  industry: z.enum(["government", "law_enforcement", "hospitals", "education"]),
  organization: z.string().min(2),
  description: z.string().min(6),
  retentionYears: z.number().int().min(1).max(100),
  securityClassification: z.enum(["Standard", "Restricted", "Confidential"])
});

const migrationBatchSchema = z.object({
  projectId: z.string().min(1),
  sourceType: z.enum(["Paper", "Microfilm", "Mixed"]),
  historicalRecordCount: z.number().int().min(1),
  digitizedRecordCount: z.number().int().min(0),
  qualityScore: z.number().min(0).max(99.9)
});

const migrationBatchQuerySchema = z.object({
  projectId: z.string().min(1).optional()
});

function toPublicUser(user: { id: string; fullName: string; email: string; role: string }) {
  return {
    id: user.id,
    fullName: user.fullName,
    email: user.email,
    role: user.role
  };
}

v1Router.get("/health", (_request, response) => {
  response.json({
    data: {
      service: "eclair-api",
      status: "ok",
      timestamp: new Date().toISOString()
    }
  });
});

v1Router.post("/auth/login", (request, response) => {
  const payload = loginSchema.parse(request.body);
  const user = eclairService.login(payload.email, payload.password);

  if (!user) {
    response.status(401).json({
      error: {
        code: "INVALID_CREDENTIALS",
        message: "Invalid email or password"
      }
    });
    return;
  }

  const token = signAccessToken({
    id: user.id,
    email: user.email,
    role: user.role,
    fullName: user.fullName
  });

  response.json({
    data: {
      accessToken: token,
      user: toPublicUser(user)
    }
  });
});

v1Router.post("/auth/register", (request, response) => {
  const payload = registerSchema.parse(request.body);
  const user = eclairService.register(payload);

  const token = signAccessToken({
    id: user.id,
    email: user.email,
    role: user.role,
    fullName: user.fullName
  });

  response.status(201).json({
    data: {
      accessToken: token,
      user: toPublicUser(user)
    }
  });
});

v1Router.get("/auth/me", requireAuth, (request, response) => {
  const profile = eclairService.getProfile(request.authUser!.id);
  response.json({
    data: {
      id: profile.id,
      fullName: profile.fullName,
      email: profile.email,
      role: profile.role
    }
  });
});

v1Router.get("/dashboard", requireAuth, (request, response) => {
  response.json({ data: eclairService.dashboard() });
});

v1Router.get("/compliance/audits", requireAuth, (request, response) => {
  response.json({ data: eclairService.listAudits() });
});

v1Router.post(
  "/compliance/audits",
  requireAuth,
  requireRole(["super_admin", "compliance_officer", "auditor"]),
  (request, response) => {
    const payload = createAuditSchema.parse(request.body);
    const data = eclairService.createAudit(payload, request.authUser!.id);
    response.status(201).json({ data });
  }
);

v1Router.patch(
  "/compliance/audits/:auditId/status",
  requireAuth,
  requireRole(["super_admin", "compliance_officer"]),
  (request, response) => {
    const payload = updateAuditStatusSchema.parse(request.body);
    const data = eclairService.updateAuditStatus(pathParam(request.params.auditId), payload.status);
    response.json({ data });
  }
);

v1Router.get("/training/plans", requireAuth, (request, response) => {
  response.json({ data: eclairService.listTrainingPlans() });
});

v1Router.post(
  "/training/plans",
  requireAuth,
  requireRole(["super_admin", "training_manager", "compliance_officer"]),
  (request, response) => {
    const payload = createTrainingSchema.parse(request.body);
    const data = eclairService.createTrainingPlan(payload, request.authUser!.id);
    response.status(201).json({ data });
  }
);

v1Router.get("/documents", requireAuth, (request, response) => {
  response.json({ data: eclairService.listDocuments() });
});

v1Router.post("/documents/upload", requireAuth, (request, response) => {
  const payload = uploadDocumentSchema.parse(request.body);
  const data = eclairService.uploadDocument(payload, request.authUser!.id);
  response.status(201).json({ data });
});

v1Router.post(
  "/documents/:documentId/version",
  requireAuth,
  requireRole(["super_admin", "compliance_officer", "training_manager"]),
  (request, response) => {
    const documentId = pathParam(request.params.documentId);
    const payload = uploadDocumentVersionSchema.parse({
      ...request.body,
      documentId
    });
    const data = eclairService.uploadDocumentVersion(payload, request.authUser!.id);
    response.status(201).json({ data });
  }
);

v1Router.post("/documents/version", requireAuth, (request, response) => {
  const payload = uploadDocumentVersionSchema.parse(request.body);
  const data = eclairService.uploadDocumentVersion(payload, request.authUser!.id);
  response.status(201).json({ data });
});

v1Router.get("/documents/:documentId/versions", requireAuth, (request, response) => {
  const data = eclairService.listDocumentVersions(pathParam(request.params.documentId));
  response.json({ data });
});

v1Router.get("/documents/:documentId/download", requireAuth, (request, response) => {
  const documentId = pathParam(request.params.documentId);
  const document = eclairService.getDocumentForDownload(documentId);
  const decrypted = eclairService.getDocumentDecryptedContent(documentId);

  response.setHeader("Content-Type", decrypted.mimeType || document.mimeType || "application/octet-stream");
  response.setHeader(
    "Content-Disposition",
    `attachment; filename="${encodeURIComponent(decrypted.fileName || document.fileName || `${document.id}.bin`)}"`
  );
  response.status(200).send(decrypted.data);
});

v1Router.post("/documents/:documentId/process", requireAuth, (request, response) => {
  const documentId = pathParam(request.params.documentId);
  const data = eclairService.processDocumentOcr(documentId, request.authUser!.id);
  response.status(201).json({ data });
});

v1Router.get("/documents/processing", requireAuth, (request, response) => {
  const documentId =
    typeof request.query.documentId === "string" && request.query.documentId ? request.query.documentId : undefined;
  const data = eclairService.listDocumentProcessing(documentId);
  response.json({ data });
});

v1Router.get("/documents/:documentId/processing", requireAuth, (request, response) => {
  const documentId = pathParam(request.params.documentId);
  const data = eclairService.listDocumentProcessing(documentId);
  response.json({ data });
});

v1Router.post(
  "/workflows/templates",
  requireAuth,
  requireRole(["super_admin", "compliance_officer", "training_manager"]),
  (request, response) => {
    const payload = workflowTemplateSchema.parse(request.body);
    const data = eclairService.createWorkflowTemplate(payload, request.authUser!.id);
    response.status(201).json({ data });
  }
);

v1Router.get("/workflows/templates", requireAuth, (_request, response) => {
  response.json({ data: eclairService.listWorkflowTemplates() });
});

v1Router.post(
  "/workflows/runs/start",
  requireAuth,
  requireRole(["super_admin", "compliance_officer", "training_manager"]),
  (request, response) => {
    const payload = workflowRunStartSchema.parse(request.body);
    const data = eclairService.startWorkflowRun(payload, request.authUser!.id);
    response.status(201).json({ data });
  }
);

v1Router.post(
  "/workflows/runs/advance",
  requireAuth,
  requireRole(["super_admin", "compliance_officer", "training_manager", "auditor"]),
  (request, response) => {
    const payload = workflowRunAdvanceSchema.parse(request.body);
    const data = eclairService.advanceWorkflowRun(payload, request.authUser!.id);
    response.json({ data });
  }
);

v1Router.get("/workflows/runs", requireAuth, (request, response) => {
  const payload = workflowRunsQuerySchema.parse({
    documentId: typeof request.query.documentId === "string" ? request.query.documentId : undefined
  });
  const data = eclairService.listWorkflowRuns(payload.documentId);
  response.json({ data });
});

v1Router.post("/collaboration/comments", requireAuth, (request, response) => {
  const payload = commentSchema.parse(request.body);
  const data = eclairService.addDocumentComment(payload, request.authUser!.id);
  response.status(201).json({ data });
});

v1Router.get("/collaboration/comments/:documentId", requireAuth, (request, response) => {
  const data = eclairService.listDocumentComments(pathParam(request.params.documentId));
  response.json({ data });
});

v1Router.get("/collaboration/audit-trail", requireAuth, (request, response) => {
  const payload = workflowRunsQuerySchema.parse({
    documentId: typeof request.query.documentId === "string" ? request.query.documentId : undefined
  });
  const data = eclairService.listAuditTrail(payload.documentId);
  response.json({ data });
});

v1Router.get("/messaging/users", requireAuth, (request, response) => {
  const data = eclairService.listMessagingUsers(request.authUser!.id);
  response.json({ data });
});

v1Router.get("/messaging/conversations", requireAuth, (request, response) => {
  const payload = directMessageListQuerySchema.parse({
    userId: typeof request.query.userId === "string" ? request.query.userId : undefined,
    limit: request.query.limit
  });
  const data = eclairService.listDirectMessages(request.authUser!.id, payload.userId, payload.limit);
  response.json({ data });
});

v1Router.post("/messaging/conversations", requireAuth, (request, response) => {
  const payload = directMessageSendSchema.parse(request.body);
  const data = eclairService.sendDirectMessage(payload, request.authUser!.id);
  response.status(201).json({ data });
});

v1Router.patch("/messaging/conversations/:messageId/read", requireAuth, (request, response) => {
  const messageId = pathParam(request.params.messageId);
  const data = eclairService.markDirectMessageRead(messageId, request.authUser!.id);
  response.json({ data });
});

v1Router.get("/messaging/inbox", requireAuth, (request, response) => {
  const data = eclairService.messagingInbox(request.authUser!.id);
  response.json({ data });
});

v1Router.get("/analytics/documents", requireAuth, (request, response) => {
  response.json({ data: eclairService.documentOpsAnalytics() });
});

v1Router.get("/records-migration/projects", requireAuth, (_request, response) => {
  response.json({ data: eclairService.listRecordsMigrationProjects() });
});

v1Router.post(
  "/records-migration/projects",
  requireAuth,
  requireRole(["super_admin", "compliance_officer", "training_manager"]),
  (request, response) => {
    const payload = migrationProjectSchema.parse(request.body);
    const data = eclairService.createRecordsMigrationProject(payload, request.authUser!.id);
    response.status(201).json({ data });
  }
);

v1Router.get("/records-migration/batches", requireAuth, (request, response) => {
  const payload = migrationBatchQuerySchema.parse({
    projectId: typeof request.query.projectId === "string" ? request.query.projectId : undefined
  });
  const data = eclairService.listRecordsMigrationBatches(payload.projectId);
  response.json({ data });
});

v1Router.post(
  "/records-migration/batches",
  requireAuth,
  requireRole(["super_admin", "compliance_officer", "training_manager"]),
  (request, response) => {
    const payload = migrationBatchSchema.parse(request.body);
    const data = eclairService.createRecordsMigrationBatch(payload, request.authUser!.id);
    response.status(201).json({ data });
  }
);

v1Router.get("/records-migration/dashboard", requireAuth, (_request, response) => {
  response.json({ data: eclairService.recordsMigrationDashboard() });
});

v1Router.get(
  "/reports/compliance",
  requireAuth,
  requireRole(["super_admin", "compliance_officer", "auditor"]),
  async (request, response) => {
    const format = z.enum(["csv", "pdf"]).parse(request.query.format ?? "csv");

    const audits = eclairService.listAudits();
    const trainings = eclairService.listTrainingPlans();
    const generatedAt = new Date().toISOString();

    if (format === "csv") {
      const content = buildComplianceCsv(audits, trainings, generatedAt);
      response.setHeader("Content-Type", "text/csv; charset=utf-8");
      response.setHeader("Content-Disposition", "attachment; filename=eclair-compliance-report.csv");
      response.status(200).send(content);
      return;
    }

    const pdfBuffer = await buildCompliancePdfBuffer(audits, trainings, generatedAt);
    response.setHeader("Content-Type", "application/pdf");
    response.setHeader("Content-Disposition", "attachment; filename=eclair-compliance-report.pdf");
    response.status(200).send(pdfBuffer);
  }
);
