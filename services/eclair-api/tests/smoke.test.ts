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
});
