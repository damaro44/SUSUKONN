import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { createApp } from "../src/app.js";
import { resetEngineForTests } from "../src/domain/index.js";

const app = createApp();

describe("role capabilities", () => {
  beforeEach(() => {
    resetEngineForTests();
  });

  it("allows members to join contribution and payout flows", async () => {
    const memberToken = await login("member@susukonnect.app", "Member@2026", "member-capability-device");
    const leaderToken = await login("leader@susukonnect.app", "Leader@2026", "leader-release-device");

    const payAttempt = await request(app)
      .post("/v1/contributions/ctr_fix_member/pay")
      .set("Authorization", `Bearer ${memberToken}`)
      .send({
        methodId: "pm_member_debit",
        enableAutoDebit: false,
      });
    expect(payAttempt.status).toBe(428);
    const payChallenge = payAttempt.body.data;

    const paid = await request(app)
      .post("/v1/contributions/ctr_fix_member/pay")
      .set("Authorization", `Bearer ${memberToken}`)
      .send({
        methodId: "pm_member_debit",
        enableAutoDebit: false,
        mfaChallengeId: payChallenge.challengeId,
        mfaCode: payChallenge.demoCode,
      });
    expect(paid.status).toBe(200);
    expect(paid.body.data.status).toBe("paid");

    const message = await request(app)
      .post("/v1/groups/grp_fixed_001/chat")
      .set("Authorization", `Bearer ${memberToken}`)
      .send({
        content: "Contribution done for this cycle.",
      });
    expect(message.status).toBe(201);

    const confirmAttempt = await request(app)
      .post("/v1/payouts/pay_prio_001/confirm-recipient")
      .set("Authorization", `Bearer ${memberToken}`)
      .send({});
    expect(confirmAttempt.status).toBe(428);
    const confirmChallenge = confirmAttempt.body.data;

    const confirmed = await request(app)
      .post("/v1/payouts/pay_prio_001/confirm-recipient")
      .set("Authorization", `Bearer ${memberToken}`)
      .send({
        mfaChallengeId: confirmChallenge.challengeId,
        mfaCode: confirmChallenge.demoCode,
      });
    expect(confirmed.status).toBe(200);
    expect(confirmed.body.data.recipientMfaConfirmed).toBe(true);

    const releaseAttempt = await request(app)
      .post("/v1/payouts/pay_prio_001/release")
      .set("Authorization", `Bearer ${leaderToken}`)
      .send({});
    expect(releaseAttempt.status).toBe(428);
    const releaseChallenge = releaseAttempt.body.data;

    const released = await request(app)
      .post("/v1/payouts/pay_prio_001/release")
      .set("Authorization", `Bearer ${leaderToken}`)
      .send({
        mfaChallengeId: releaseChallenge.challengeId,
        mfaCode: releaseChallenge.demoCode,
      });
    expect(released.status).toBe(200);
    expect(released.body.data.status).toBe("released");

    const payouts = await request(app)
      .get("/v1/payouts")
      .set("Authorization", `Bearer ${memberToken}`);
    expect(payouts.status).toBe(200);
    const releasedPayout = payouts.body.data.find((entry: { id: string }) => entry.id === "pay_prio_001");
    expect(releasedPayout?.status).toBe("released");
  });

  it("allows leaders to manage groups, payout reasons, and chat moderation", async () => {
    const leaderToken = await login("leader@susukonnect.app", "Leader@2026", "leader-manage-device");
    const memberToken = await login("member@susukonnect.app", "Member@2026", "member-request-device");

    const config = await request(app)
      .patch("/v1/groups/grp_fixed_001/config")
      .set("Authorization", `Bearer ${leaderToken}`)
      .send({
        contributionAmount: 260,
        gracePeriodDays: 5,
        rules: "Contributions are due by the 5th and must be confirmed in app.",
        requiresLeaderApproval: true,
      });
    expect(config.status).toBe(200);
    expect(config.body.data.contributionAmount).toBe(260);
    expect(config.body.data.gracePeriodDays).toBe(5);

    const order = await request(app)
      .put("/v1/groups/grp_fixed_001/payout-order")
      .set("Authorization", `Bearer ${leaderToken}`)
      .send({
        payoutOrder: ["usr_member", "usr_leader"],
      });
    expect(order.status).toBe(200);
    expect(order.body.data.payoutOrder).toEqual(["usr_member", "usr_leader"]);

    const requested = await request(app)
      .post("/v1/groups/grp_vote_001/payouts/request")
      .set("Authorization", `Bearer ${memberToken}`)
      .send({
        reason: "Emergency",
      });
    expect(requested.status).toBe(201);
    const payoutId = requested.body.data.id as string;

    const reasonReviewed = await request(app)
      .post(`/v1/payouts/${payoutId}/reason-review`)
      .set("Authorization", `Bearer ${leaderToken}`)
      .send({
        decision: "approve",
        note: "Reason accepted by group leader.",
      });
    expect(reasonReviewed.status).toBe(200);
    expect(reasonReviewed.body.data.reasonReviewStatus).toBe("approved");

    const archived = await request(app)
      .patch("/v1/groups/grp_fixed_001/chat-moderation")
      .set("Authorization", `Bearer ${leaderToken}`)
      .send({ chatArchived: true });
    expect(archived.status).toBe(200);
    expect(archived.body.data.chatArchived).toBe(true);

    const reopened = await request(app)
      .patch("/v1/groups/grp_fixed_001/chat-moderation")
      .set("Authorization", `Bearer ${leaderToken}`)
      .send({ chatArchived: false });
    expect(reopened.status).toBe(200);
    expect(reopened.body.data.chatArchived).toBe(false);

    const createdMessage = await request(app)
      .post("/v1/groups/grp_fixed_001/chat")
      .set("Authorization", `Bearer ${leaderToken}`)
      .send({
        content: "This will be removed by moderation.",
      });
    expect(createdMessage.status).toBe(201);
    const messageId = createdMessage.body.data.id as string;

    const deleted = await request(app)
      .delete(`/v1/chat/${messageId}`)
      .set("Authorization", `Bearer ${leaderToken}`);
    expect(deleted.status).toBe(200);
    expect(deleted.body.data.deleted).toBe(true);
  });

  it("allows admins to run compliance, fraud, disputes, and audit operations", async () => {
    const adminToken = await login("admin@susukonnect.app", "Admin@2026", "admin-ops-device");
    const memberToken = await login("member@susukonnect.app", "Member@2026", "member-dispute-device");
    const signupEmail = `cleanup.${Date.now()}@susukonnect.app`;

    const signup = await request(app).post("/v1/auth/register").send({
      fullName: "Cleanup User",
      email: signupEmail,
      phone: "+15557778888",
      password: "Cleanup123",
      role: "member",
      acceptTerms: true,
    });
    expect(signup.status).toBe(201);
    const signupUserId = signup.body.data.id as string;

    const fraud = await request(app)
      .post("/v1/admin/fraud-flags")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({
        targetType: "user",
        targetId: "usr_member",
        reason: "Velocity checks triggered for review",
      });
    expect(fraud.status).toBe(201);
    const flagId = fraud.body.data.id as string;
    expect(fraud.body.data.status).toBe("open");

    const flags = await request(app)
      .get("/v1/admin/fraud-flags?status=open")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(flags.status).toBe(200);
    expect(flags.body.data.some((entry: { id: string }) => entry.id === flagId)).toBe(true);

    const resolved = await request(app)
      .post(`/v1/admin/fraud-flags/${flagId}/resolve`)
      .set("Authorization", `Bearer ${adminToken}`)
      .send({
        resolution: "False positive after manual compliance review.",
      });
    expect(resolved.status).toBe(200);
    expect(resolved.body.data.status).toBe("resolved");

    const dispute = await request(app)
      .post("/v1/disputes")
      .set("Authorization", `Bearer ${memberToken}`)
      .send({
        groupId: "grp_fixed_001",
        summary: "Please review contribution reminder behavior.",
      });
    expect(dispute.status).toBe(201);
    const disputeId = dispute.body.data.id as string;

    const disputeResolved = await request(app)
      .post(`/v1/admin/disputes/${disputeId}/resolve`)
      .set("Authorization", `Bearer ${adminToken}`)
      .send({});
    expect(disputeResolved.status).toBe(200);
    expect(disputeResolved.body.data.status).toBe("resolved");

    const reviewedKyc = await request(app)
      .post("/v1/admin/kyc/usr_pending/review")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({ status: "verified" });
    expect(reviewedKyc.status).toBe(200);
    expect(reviewedKyc.body.data.kyc.status).toBe("verified");

    const queue = await request(app)
      .get("/v1/admin/compliance/queue")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(queue.status).toBe(200);
    expect(queue.body.data).toHaveProperty("pendingKyc");
    expect(queue.body.data).toHaveProperty("openFraudFlags");

    const purge = await request(app)
      .post("/v1/admin/users/purge-signups")
      .set("Authorization", `Bearer ${adminToken}`)
      .send({});
    expect(purge.status).toBe(200);
    expect(purge.body.data.deletedCount).toBeGreaterThanOrEqual(1);
    expect(purge.body.data.deletedUserIds).toContain(signupUserId);

    const loginAfterPurge = await request(app).post("/v1/auth/login").send({
      email: signupEmail,
      password: "Cleanup123",
      deviceId: "cleanup-device",
    });
    expect(loginAfterPurge.status).toBe(401);
    expect(loginAfterPurge.body.error.code).toBe("INVALID_CREDENTIALS");

    const auditLogs = await request(app)
      .get("/v1/admin/audit/logs?action=CREATE_FRAUD_FLAG&limit=5")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(auditLogs.status).toBe(200);
    expect(Array.isArray(auditLogs.body.data)).toBe(true);

    const report = await request(app)
      .get("/v1/admin/export?format=json")
      .set("Authorization", `Bearer ${adminToken}`);
    expect(report.status).toBe(200);
    expect(report.body.data.content).toContain("generatedAt");
  });
});

async function login(email: string, password: string, deviceId: string): Promise<string> {
  const loginResponse = await request(app).post("/v1/auth/login").send({
    email,
    password,
    deviceId,
  });
  expect(loginResponse.status).toBe(428);
  const challengeId = loginResponse.body.data.challengeId as string;
  const code = loginResponse.body.data.demoCode as string;
  const verify = await request(app).post("/v1/auth/mfa/verify").send({
    challengeId,
    code,
    deviceId,
  });
  expect(verify.status).toBe(200);
  return verify.body.data.tokens.accessToken as string;
}
