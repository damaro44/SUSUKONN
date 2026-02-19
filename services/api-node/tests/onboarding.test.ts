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

  it("enforces KYC identity checks and supports authenticator MFA method", async () => {
    const email = `kyc.user.${Date.now()}@susukonnect.app`;
    const password = "Password123";

    const register = await request(app).post("/v1/auth/register").send({
      fullName: "Kyc Verified User",
      email,
      phone: "+15553334444",
      password,
      role: "member",
      acceptTerms: true,
    });
    expect(register.status).toBe(201);

    await request(app).post("/v1/auth/verify-contact").send({
      challengeId: register.body.data.contactVerification.email.challengeId,
      code: register.body.data.contactVerification.email.demoCode,
      channel: "email",
    });
    await request(app).post("/v1/auth/verify-contact").send({
      challengeId: register.body.data.contactVerification.phone.challengeId,
      code: register.body.data.contactVerification.phone.demoCode,
      channel: "phone",
    });

    const login = await request(app).post("/v1/auth/login").send({
      email,
      password,
      deviceId: "kyc-device-1",
    });
    expect(login.status).toBe(428);
    expect(login.body.data.method).toBe("sms");

    const verified = await request(app).post("/v1/auth/mfa/verify").send({
      challengeId: login.body.data.challengeId,
      code: login.body.data.demoCode,
      deviceId: "kyc-device-1",
    });
    expect(verified.status).toBe(200);
    const token = verified.body.data.tokens.accessToken as string;

    const invalidDobKyc = await request(app)
      .post("/v1/me/kyc")
      .set("Authorization", `Bearer ${token}`)
      .send({
        idType: "passport",
        idNumber: "P1234567",
        dob: "07/11/1995",
        selfieToken: "selfie_token",
        livenessToken: "live_123456",
      });
    expect(invalidDobKyc.status).toBe(400);
    expect(invalidDobKyc.body.error.code).toBe("INVALID_DOB");

    const kyc = await request(app)
      .post("/v1/me/kyc")
      .set("Authorization", `Bearer ${token}`)
      .send({
        idType: "passport",
        idNumber: "P1234567",
        dob: "1995-07-11",
        selfieToken: "selfie_token",
        livenessToken: "live_123456",
        address: "123 Main Street, Accra",
      });
    expect(kyc.status).toBe(201);
    expect(kyc.body.data.status).toBe("pending");
    expect(kyc.body.data.checks.livenessVerified).toBe(true);
    expect(kyc.body.data.checks.nameDobVerified).toBe(true);

    const securityAttempt = await request(app)
      .patch("/v1/me/security")
      .set("Authorization", `Bearer ${token}`)
      .send({
        mfaEnabled: true,
        biometricEnabled: false,
        mfaMethod: "authenticator",
      });
    expect(securityAttempt.status).toBe(428);

    const securityUpdated = await request(app)
      .patch("/v1/me/security")
      .set("Authorization", `Bearer ${token}`)
      .send({
        mfaEnabled: true,
        biometricEnabled: false,
        mfaMethod: "authenticator",
        mfaChallengeId: securityAttempt.body.data.challengeId,
        mfaCode: securityAttempt.body.data.demoCode,
      });
    expect(securityUpdated.status).toBe(200);
    expect(securityUpdated.body.data.mfaMethod).toBe("authenticator");

    const loginWithAuthenticator = await request(app).post("/v1/auth/login").send({
      email,
      password,
      deviceId: "kyc-device-2",
    });
    expect(loginWithAuthenticator.status).toBe(428);
    expect(loginWithAuthenticator.body.data.method).toBe("authenticator");
  });
});
