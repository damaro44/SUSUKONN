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
      user: {
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        role: user.role
      }
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
