import { describe, expect, it } from "vitest";
import request from "supertest";
import { createApp } from "../src/app.js";

describe("SusuKonnect API smoke", () => {
  const app = createApp();

  it("returns healthy status", async () => {
    const response = await request(app).get("/v1/health");
    expect(response.status).toBe(200);
    expect(response.body.data.status).toBe("ok");
  });

  it("supports login -> MFA -> dashboard flow", async () => {
    const login = await request(app).post("/v1/auth/login").send({
      email: "admin@susukonnect.app",
      password: "Admin@2026",
      deviceId: "test-device",
    });
    expect(login.status).toBe(428);
    expect(login.body.error.code).toBe("MFA_REQUIRED");
    const challengeId = login.body.data.challengeId as string;
    const code = login.body.data.demoCode as string;
    expect(challengeId).toBeTruthy();
    expect(code).toHaveLength(6);

    const verify = await request(app).post("/v1/auth/mfa/verify").send({
      challengeId,
      code,
      deviceId: "test-device",
    });
    expect(verify.status).toBe(200);
    const accessToken = verify.body.data.tokens.accessToken as string;
    expect(accessToken).toBeTruthy();

    const dashboard = await request(app)
      .get("/v1/dashboard")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(dashboard.status).toBe(200);
    expect(dashboard.body.data.summary).toBeTruthy();
  });
});
