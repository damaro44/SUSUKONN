import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { createApp } from "../src/app.js";
import { resetEngineForTests } from "../src/domain/index.js";

const app = createApp();

describe("high-trust onboarding and biometric entry", () => {
  beforeEach(() => {
    resetEngineForTests();
  });

  it("supports registration with contact verification and biometric enrollment", async () => {
    const email = `new.user.${Date.now()}@susukonnect.app`;
    const password = "Password123";

    const register = await request(app).post("/v1/auth/register").send({
      fullName: "New User",
      email,
      phone: "+15551112222",
      password,
      role: "member",
      acceptTerms: true,
    });
    expect(register.status).toBe(201);
    expect(register.body.data.email).toBe(email.toLowerCase());
    expect(register.body.data.contactVerification.email.challengeId).toBeTruthy();
    expect(register.body.data.contactVerification.phone.challengeId).toBeTruthy();

    const blockedLogin = await request(app).post("/v1/auth/login").send({
      email,
      password,
      deviceId: "new-user-device",
    });
    expect(blockedLogin.status).toBe(403);
    expect(blockedLogin.body.error.code).toBe("CONTACT_UNVERIFIED");

    const verifyEmail = await request(app).post("/v1/auth/verify-contact").send({
      challengeId: register.body.data.contactVerification.email.challengeId,
      code: register.body.data.contactVerification.email.demoCode,
      channel: "email",
    });
    expect(verifyEmail.status).toBe(200);
    expect(verifyEmail.body.data.channel).toBe("email");
    expect(verifyEmail.body.data.contactsVerified).toBe(false);

    const resendPhone = await request(app).post("/v1/auth/contact-verifications/resend").send({
      email,
      channel: "phone",
    });
    expect(resendPhone.status).toBe(201);

    const verifyPhone = await request(app).post("/v1/auth/verify-contact").send({
      challengeId: resendPhone.body.data.challengeId,
      code: resendPhone.body.data.demoCode,
      channel: "phone",
    });
    expect(verifyPhone.status).toBe(200);
    expect(verifyPhone.body.data.contactsVerified).toBe(true);

    const login = await request(app).post("/v1/auth/login").send({
      email,
      password,
      deviceId: "new-user-device",
    });
    expect(login.status).toBe(428);
    expect(login.body.error.code).toBe("MFA_REQUIRED");

    const verifyLoginMfa = await request(app).post("/v1/auth/mfa/verify").send({
      challengeId: login.body.data.challengeId,
      code: login.body.data.demoCode,
      deviceId: "new-user-device",
    });
    expect(verifyLoginMfa.status).toBe(200);
    expect(verifyLoginMfa.body.data.tokens.accessToken).toBeTruthy();

    const enrollAttempt = await request(app).post("/v1/auth/biometric/enroll").send({
      email,
      password,
      deviceId: "new-user-device",
      deviceLabel: "iPhone Face ID",
    });
    expect(enrollAttempt.status).toBe(428);
    expect(enrollAttempt.body.error.code).toBe("MFA_REQUIRED");

    const enrolled = await request(app).post("/v1/auth/biometric/enroll").send({
      email,
      password,
      deviceId: "new-user-device",
      deviceLabel: "iPhone Face ID",
      mfaChallengeId: enrollAttempt.body.data.challengeId,
      mfaCode: enrollAttempt.body.data.demoCode,
    });
    expect(enrolled.status).toBe(200);
    expect(enrolled.body.data.biometricEnabled).toBe(true);
    expect(enrolled.body.data.contactsVerified).toBe(true);

    const biometricLogin = await request(app).post("/v1/auth/biometric-login").send({
      email,
      deviceId: "new-user-device",
    });
    expect(biometricLogin.status).toBe(200);
    expect(biometricLogin.body.data.tokens.accessToken).toBeTruthy();
  });
});
