import { describe, expect, it } from "vitest";
import request from "supertest";
import { createApp } from "../src/app.js";

describe("Eclair API smoke", () => {
  const app = createApp();

  async function loginAs(email: string, password: string) {
    const response = await request(app).post("/v1/auth/login").send({ email, password });
    expect(response.status).toBe(200);
    return response.body.data.accessToken as string;
  }

  it("returns health status", async () => {
    const response = await request(app).get("/v1/health");
    expect(response.status).toBe(200);
    expect(response.body.data.status).toBe("ok");
  });

  it("supports protected profile endpoint", async () => {
    const token = await loginAs("admin@eclair.tech", "Admin@2026");

    const me = await request(app).get("/v1/auth/me").set("Authorization", `Bearer ${token}`);
    expect(me.status).toBe(200);
    expect(me.body.data.role).toBe("super_admin");
  });

  it("enforces role-based authorization for audit creation", async () => {
    const token = await loginAs("training@eclair.tech", "Training@2026");

    const createAudit = await request(app)
      .post("/v1/compliance/audits")
      .set("Authorization", `Bearer ${token}`)
      .send({
        standard: "PARAE-X",
        severity: "Low",
        finding: "Test finding",
        owner: "Training Office",
        dueDate: "2026-08-01"
      });

    expect(createAudit.status).toBe(403);
    expect(createAudit.body.error.code).toBe("FORBIDDEN");
  });

  it("exports compliance report as CSV and PDF", async () => {
    const token = await loginAs("compliance@eclair.tech", "Compliance@2026");

    const csvReport = await request(app)
      .get("/v1/reports/compliance?format=csv")
      .set("Authorization", `Bearer ${token}`);

    expect(csvReport.status).toBe(200);
    expect(csvReport.headers["content-type"]).toContain("text/csv");
    expect(csvReport.text).toContain("record_type,id");

    const pdfReport = await request(app)
      .get("/v1/reports/compliance?format=pdf")
      .set("Authorization", `Bearer ${token}`);

    expect(pdfReport.status).toBe(200);
    expect(pdfReport.headers["content-type"]).toContain("application/pdf");
    expect(pdfReport.body.length).toBeGreaterThan(100);
  });

  it("registers a new user and returns auth token", async () => {
    const response = await request(app).post("/v1/auth/register").send({
      fullName: "New Compliance User",
      email: "new.compliance.user@eclair.tech",
      password: "SecurePass123",
      role: "compliance_officer"
    });

    expect(response.status).toBe(201);
    expect(response.body.data.user.email).toBe("new.compliance.user@eclair.tech");
    expect(response.body.data.accessToken).toBeTruthy();
  });

  it("uploads, lists, and downloads documents", async () => {
    const token = await loginAs("compliance@eclair.tech", "Compliance@2026");
    const contentBase64 = Buffer.from("proof-of-compliance", "utf8").toString("base64");

    const upload = await request(app)
      .post("/v1/documents/upload")
      .set("Authorization", `Bearer ${token}`)
      .send({
        title: "Compliance Proof",
        category: "evidence",
        fileName: "proof.txt",
        mimeType: "text/plain",
        contentBase64
      });

    expect(upload.status).toBe(201);
    expect(upload.body.data.title).toBe("Compliance Proof");
    expect(upload.body.data.id).toBeTruthy();

    const list = await request(app).get("/v1/documents").set("Authorization", `Bearer ${token}`);
    expect(list.status).toBe(200);
    expect(Array.isArray(list.body.data)).toBe(true);
    expect(list.body.data.some((item: { id: string }) => item.id === upload.body.data.id)).toBe(true);

    const download = await request(app)
      .get(`/v1/documents/${upload.body.data.id}/download`)
      .set("Authorization", `Bearer ${token}`);
    expect(download.status).toBe(200);
    expect(download.headers["content-type"]).toContain("text/plain");
    expect(download.text).toBe("proof-of-compliance");
  });

  it("runs OCR routing, workflows, collaboration, and analytics", async () => {
    const token = await loginAs("compliance@eclair.tech", "Compliance@2026");
    const contentBase64 = Buffer.from(
      "Compliance policy evidence with audit and governance controls.",
      "utf8"
    ).toString("base64");

    const upload = await request(app)
      .post("/v1/documents/upload")
      .set("Authorization", `Bearer ${token}`)
      .send({
        title: "Routing Source Doc",
        category: "policy",
        fileName: "routing-source.txt",
        mimeType: "text/plain",
        contentBase64
      });
    expect(upload.status).toBe(201);
    const documentId = upload.body.data.id as string;

    const ocr = await request(app)
      .post(`/v1/documents/${documentId}/process`)
      .set("Authorization", `Bearer ${token}`);
    expect(ocr.status).toBe(201);
    expect(ocr.body.data.ocr.confidence).toBeGreaterThan(99);
    expect(ocr.body.data.routing.department).toBe("compliance");

    const template = await request(app)
      .post("/v1/workflows/templates")
      .set("Authorization", `Bearer ${token}`)
      .send({
        name: "Test Approval Flow",
        department: "compliance",
        steps: ["Review", "Approval", "Archive"]
      });
    expect(template.status).toBe(201);
    const templateId = template.body.data.id as string;

    const startRun = await request(app)
      .post("/v1/workflows/runs/start")
      .set("Authorization", `Bearer ${token}`)
      .send({
        templateId,
        documentId
      });
    expect(startRun.status).toBe(201);
    const runId = startRun.body.data.id as string;

    const advance = await request(app)
      .post("/v1/workflows/runs/advance")
      .set("Authorization", `Bearer ${token}`)
      .send({
        runId,
        action: "approve",
        comment: "Looks good"
      });
    expect(advance.status).toBe(200);
    expect(advance.body.data.status).toBe("In Progress");

    const comment = await request(app)
      .post("/v1/collaboration/comments")
      .set("Authorization", `Bearer ${token}`)
      .send({
        documentId,
        message: "Please review this before final approval."
      });
    expect(comment.status).toBe(201);
    expect(comment.body.data.documentId).toBe(documentId);

    const analytics = await request(app)
      .get("/v1/analytics/documents")
      .set("Authorization", `Bearer ${token}`);
    expect(analytics.status).toBe(200);
    expect(analytics.body.data.ocr.totalProcessed).toBeGreaterThan(0);
    expect(analytics.body.data.security.complianceFrameworks).toEqual(["HIPAA", "SOC 2", "GDPR"]);
  });

  it("creates records migration projects and batches with dashboard metrics", async () => {
    const token = await loginAs("compliance@eclair.tech", "Compliance@2026");

    const project = await request(app)
      .post("/v1/records-migration/projects")
      .set("Authorization", `Bearer ${token}`)
      .send({
        name: "Hospital Legacy Archive Program",
        industry: "hospitals",
        organization: "National Referral Hospital",
        description: "Digitize legacy patient paper files and classify retention.",
        retentionYears: 30,
        securityClassification: "Confidential"
      });
    expect(project.status).toBe(201);
    expect(project.body.data.industry).toBe("hospitals");
    expect(project.body.data.status).toBe("Planning");
    const projectId = project.body.data.id as string;

    const batch = await request(app)
      .post("/v1/records-migration/batches")
      .set("Authorization", `Bearer ${token}`)
      .send({
        projectId,
        sourceType: "Paper",
        historicalRecordCount: 500,
        digitizedRecordCount: 320,
        qualityScore: 99.2
      });
    expect(batch.status).toBe(201);
    expect(batch.body.data.projectId).toBe(projectId);
    expect(batch.body.data.completionPercent).toBeGreaterThan(60);

    const projects = await request(app).get("/v1/records-migration/projects").set("Authorization", `Bearer ${token}`);
    expect(projects.status).toBe(200);
    expect(projects.body.data.some((item: { id: string }) => item.id === projectId)).toBe(true);

    const dashboard = await request(app)
      .get("/v1/records-migration/dashboard")
      .set("Authorization", `Bearer ${token}`);
    expect(dashboard.status).toBe(200);
    expect(dashboard.body.data.totals.projects).toBeGreaterThan(0);
    expect(dashboard.body.data.security.encryptionAtRest).toBe("AES-256-GCM");

    const batches = await request(app)
      .get(`/v1/records-migration/batches?projectId=${encodeURIComponent(projectId)}`)
      .set("Authorization", `Bearer ${token}`);
    expect(batches.status).toBe(200);
    expect(Array.isArray(batches.body.data)).toBe(true);
    expect(batches.body.data[0].projectId).toBe(projectId);
  });
});
