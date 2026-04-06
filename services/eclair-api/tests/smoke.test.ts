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
});
