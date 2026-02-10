import { Router } from "express";
import { z } from "zod";
import { CURRENCIES, PAYOUT_REASONS } from "@susukonnect/shared";
import { engine } from "../domain/index.js";
import { requireAuth, requireRole } from "../middleware/auth.js";

export const v1Router = Router();

v1Router.get("/health", (_request, response) => {
  response.json({
    data: {
      service: "susukonnect-api-node",
      status: "ok",
      timestamp: new Date().toISOString(),
    },
  });
});

v1Router.post("/auth/register", (request, response) => {
  const payload = z
    .object({
      fullName: z.string().min(2),
      email: z.string().email(),
      phone: z.string().min(6),
      password: z.string().min(8),
      role: z.enum(["member", "leader"]).default("member"),
      acceptTerms: z.boolean(),
    })
    .parse(request.body);
  const user = engine.register(payload);
  response.status(201).json({ data: user });
});

v1Router.post("/auth/login", (request, response) => {
  const payload = z
    .object({
      email: z.string().email(),
      password: z.string().min(8),
      deviceId: z.string().min(4),
    })
    .parse(request.body);
  const result = engine.login(payload);
  if (result.requiresMfa) {
    response.status(428).json({
      error: {
        code: "MFA_REQUIRED",
        message: "MFA verification is required.",
      },
      data: result.challenge,
    });
    return;
  }
  response.json({ data: result });
});

v1Router.post("/auth/mfa/verify", (request, response) => {
  const payload = z
    .object({
      challengeId: z.string(),
      code: z.string().length(6),
      deviceId: z.string().min(4),
    })
    .parse(request.body);
  const result = engine.verifyLoginMfa(payload);
  response.json({ data: result });
});

v1Router.post("/auth/biometric-login", (request, response) => {
  const payload = z
    .object({
      email: z.string().email(),
      deviceId: z.string().min(4),
    })
    .parse(request.body);
  const result = engine.biometricLogin(payload.email, payload.deviceId);
  response.json({ data: result });
});

v1Router.post("/auth/logout", requireAuth, (request, response) => {
  const user = request.authUser!;
  const token = request.accessToken!;
  engine.logout(user.id, token);
  response.status(204).send();
});

v1Router.get("/auth/me", requireAuth, (request, response) => {
  response.json({ data: request.authUser });
});

v1Router.get("/dashboard", requireAuth, (request, response) => {
  const result = engine.dashboard(request.authUser!.id);
  response.json({ data: result });
});

v1Router.get("/groups", requireAuth, (request, response) => {
  const filters = {
    query: asString(request.query.query),
    community: asString(request.query.community),
    location: asString(request.query.location),
    maxContribution: asString(request.query.maxContribution),
    startDate: asString(request.query.startDate),
  };
  const data = engine.listGroups(request.authUser!.id, filters);
  response.json({ data });
});

v1Router.post("/groups", requireAuth, (request, response) => {
  const payload = z
    .object({
      name: z.string().min(2),
      description: z.string().min(3),
      communityType: z.string().default("General"),
      location: z.string().min(2),
      startDate: z.string(),
      contributionAmount: z.number().positive(),
      currency: z.enum(CURRENCIES),
      totalMembers: z.number().min(2),
      payoutOrderLogic: z.enum(["fixed", "voting", "priority"]),
      gracePeriodDays: z.number().min(0),
      requiresLeaderApproval: z.boolean(),
      rules: z.string().min(3),
    })
    .parse(request.body);
  const data = engine.createGroup(request.authUser!.id, payload);
  response.status(201).json({ data });
});

v1Router.post("/groups/:groupId/join", requireAuth, (request, response) => {
  const data = engine.joinGroup(request.authUser!.id, request.params.groupId);
  response.json({ data });
});

v1Router.post("/groups/:groupId/join-requests/:userId/decision", requireAuth, (request, response) => {
  const payload = z.object({ decision: z.enum(["approve", "reject"]) }).parse(request.body);
  const data = engine.reviewJoinRequest(
    request.authUser!.id,
    request.params.groupId,
    request.params.userId,
    payload.decision
  );
  response.json({ data });
});

v1Router.post("/groups/:groupId/remind", requireAuth, (request, response) => {
  const data = engine.sendGroupReminders(request.authUser!.id, request.params.groupId);
  response.json({ data });
});

v1Router.patch("/groups/:groupId/status", requireAuth, requireRole(["admin"]), (request, response) => {
  const payload = z.object({ status: z.enum(["active", "suspended"]) }).parse(request.body);
  const data = engine.updateGroupStatus(request.authUser!.id, request.params.groupId, payload.status);
  response.json({ data });
});

v1Router.get("/contributions", requireAuth, (request, response) => {
  const data = engine.listContributions(request.authUser!.id, asString(request.query.groupId));
  response.json({ data });
});

v1Router.post("/contributions/:contributionId/pay", requireAuth, async (request, response) => {
  const payload = z
    .object({
      methodId: z.string(),
      enableAutoDebit: z.boolean().default(false),
      mfaChallengeId: z.string().optional(),
      mfaCode: z.string().length(6).optional(),
    })
    .parse(request.body);
  const result = await engine.payContribution(request.authUser!.id, request.params.contributionId, payload);
  if (result.mfaRequired) {
    response.status(428).json({
      error: {
        code: "MFA_REQUIRED",
        message: "MFA verification is required.",
      },
      data: result.challenge,
    });
    return;
  }
  response.json({ data: result.contribution });
});

v1Router.get("/payouts", requireAuth, (request, response) => {
  const data = engine.listPayouts(request.authUser!.id, asString(request.query.groupId));
  response.json({ data });
});

v1Router.post("/groups/:groupId/payouts/request", requireAuth, (request, response) => {
  const payload = z
    .object({
      reason: z.enum(PAYOUT_REASONS),
      customReason: z.string().optional(),
    })
    .parse(request.body);
  const data = engine.requestPayout(
    request.authUser!.id,
    request.params.groupId,
    payload.reason,
    payload.customReason
  );
  response.status(201).json({ data });
});

v1Router.post("/groups/:groupId/votes", requireAuth, (request, response) => {
  const payload = z
    .object({
      candidateId: z.string(),
      note: z.string().optional(),
    })
    .parse(request.body);
  engine.submitVote(request.authUser!.id, request.params.groupId, payload.candidateId, payload.note);
  response.status(201).json({ data: { ok: true } });
});

v1Router.post("/groups/:groupId/priority-claims", requireAuth, (request, response) => {
  const payload = z
    .object({
      reason: z.enum(PAYOUT_REASONS),
      customReason: z.string().optional(),
    })
    .parse(request.body);
  engine.submitPriorityClaim(request.authUser!.id, request.params.groupId, payload.reason, payload.customReason);
  response.status(201).json({ data: { ok: true } });
});

v1Router.post("/payouts/:payoutId/approve", requireAuth, (request, response) => {
  const payload = z
    .object({
      mfaChallengeId: z.string().optional(),
      mfaCode: z.string().length(6).optional(),
    })
    .parse(request.body);
  const result = engine.approvePayout(request.authUser!.id, request.params.payoutId, payload);
  if (result.mfaRequired) {
    response.status(428).json({
      error: { code: "MFA_REQUIRED", message: "MFA verification is required." },
      data: result.challenge,
    });
    return;
  }
  response.json({ data: result.payout });
});

v1Router.post("/payouts/:payoutId/confirm-recipient", requireAuth, (request, response) => {
  const payload = z
    .object({
      mfaChallengeId: z.string().optional(),
      mfaCode: z.string().length(6).optional(),
    })
    .parse(request.body);
  const result = engine.confirmPayoutRecipient(request.authUser!.id, request.params.payoutId, payload);
  if (result.mfaRequired) {
    response.status(428).json({
      error: { code: "MFA_REQUIRED", message: "MFA verification is required." },
      data: result.challenge,
    });
    return;
  }
  response.json({ data: result.payout });
});

v1Router.post("/payouts/:payoutId/release", requireAuth, async (request, response) => {
  const payload = z
    .object({
      mfaChallengeId: z.string().optional(),
      mfaCode: z.string().length(6).optional(),
    })
    .parse(request.body);
  const result = await engine.releasePayout(request.authUser!.id, request.params.payoutId, payload);
  if (result.mfaRequired) {
    response.status(428).json({
      error: { code: "MFA_REQUIRED", message: "MFA verification is required." },
      data: result.challenge,
    });
    return;
  }
  response.json({ data: result.payout });
});

v1Router.get("/groups/:groupId/chat", requireAuth, (request, response) => {
  const data = engine.listChat(request.authUser!.id, request.params.groupId);
  response.json({ data });
});

v1Router.post("/groups/:groupId/chat", requireAuth, (request, response) => {
  const payload = z
    .object({
      content: z.string().min(1),
      announcement: z.boolean().optional(),
      pin: z.boolean().optional(),
    })
    .parse(request.body);
  const data = engine.sendChat(request.authUser!.id, request.params.groupId, payload);
  response.status(201).json({ data });
});

v1Router.post("/chat/:messageId/pin", requireAuth, (request, response) => {
  const data = engine.togglePin(request.authUser!.id, request.params.messageId);
  response.json({ data });
});

v1Router.get("/calendar/events", requireAuth, (request, response) => {
  const data = engine.calendarEvents(request.authUser!.id);
  response.json({ data });
});

v1Router.get("/notifications", requireAuth, (request, response) => {
  const data = engine.userNotifications(request.authUser!.id);
  response.json({ data });
});

v1Router.post("/notifications/:notificationId/read", requireAuth, (request, response) => {
  engine.markNotificationRead(request.authUser!.id, request.params.notificationId);
  response.status(204).send();
});

v1Router.post("/notifications/read-all", requireAuth, (request, response) => {
  engine.markAllNotificationsRead(request.authUser!.id);
  response.status(204).send();
});

v1Router.post("/me/kyc", requireAuth, async (request, response) => {
  const payload = z
    .object({
      idType: z.string().min(2),
      idNumber: z.string().min(2),
      dob: z.string().min(8),
      selfieToken: z.string().min(2),
      address: z.string().optional(),
    })
    .parse(request.body);
  const data = await engine.submitKyc(request.authUser!.id, payload);
  response.status(201).json({ data });
});

v1Router.post("/me/kyc/session", requireAuth, async (request, response) => {
  const data = await engine.createKycSession(request.authUser!.id);
  response.status(201).json({ data });
});

v1Router.patch("/me/security", requireAuth, (request, response) => {
  const payload = z
    .object({
      mfaEnabled: z.boolean(),
      biometricEnabled: z.boolean(),
      mfaChallengeId: z.string().optional(),
      mfaCode: z.string().length(6).optional(),
    })
    .parse(request.body);
  const result = engine.updateSecurity(
    request.authUser!.id,
    {
      mfaEnabled: payload.mfaEnabled,
      biometricEnabled: payload.biometricEnabled,
    },
    payload.mfaChallengeId,
    payload.mfaCode
  );
  if (result.mfaRequired) {
    response.status(428).json({
      error: { code: "MFA_REQUIRED", message: "MFA verification is required." },
      data: result.challenge,
    });
    return;
  }
  response.json({ data: result.user });
});

v1Router.post("/me/payment-methods", requireAuth, (request, response) => {
  const payload = z
    .object({
      type: z.enum(["bank", "debit", "paypal", "cashapp"]),
      label: z.string().min(2),
      identifierTail: z.string().min(2),
      providerToken: z.string().min(1),
      autoDebit: z.boolean().default(false),
      mfaChallengeId: z.string().optional(),
      mfaCode: z.string().length(6).optional(),
    })
    .parse(request.body);
  const result = engine.addPaymentMethod(
    request.authUser!.id,
    {
      type: payload.type,
      label: payload.label,
      identifierTail: payload.identifierTail,
      providerToken: payload.providerToken,
      autoDebit: payload.autoDebit,
    },
    payload.mfaChallengeId,
    payload.mfaCode
  );
  if (result.mfaRequired) {
    response.status(428).json({
      error: { code: "MFA_REQUIRED", message: "MFA verification is required." },
      data: result.challenge,
    });
    return;
  }
  response.status(201).json({ data: result.paymentMethod });
});

v1Router.delete("/me/payment-methods/:methodId", requireAuth, (request, response) => {
  const payload = z
    .object({
      mfaChallengeId: z.string().optional(),
      mfaCode: z.string().length(6).optional(),
    })
    .parse(request.body ?? {});
  const result = engine.removePaymentMethod(
    request.authUser!.id,
    request.params.methodId,
    payload.mfaChallengeId,
    payload.mfaCode
  );
  if (result.mfaRequired) {
    response.status(428).json({
      error: { code: "MFA_REQUIRED", message: "MFA verification is required." },
      data: result.challenge,
    });
    return;
  }
  response.status(204).send();
});

v1Router.delete("/me/devices/:deviceId", requireAuth, (request, response) => {
  engine.removeDevice(request.authUser!.id, request.params.deviceId);
  response.status(204).send();
});

v1Router.post("/disputes", requireAuth, (request, response) => {
  const payload = z
    .object({
      groupId: z.string(),
      summary: z.string().min(3),
    })
    .parse(request.body);
  const data = engine.submitDispute(request.authUser!.id, payload.groupId, payload.summary);
  response.status(201).json({ data });
});

v1Router.get("/admin/overview", requireAuth, requireRole(["admin"]), (request, response) => {
  const data = engine.adminOverview(request.authUser!.id);
  response.json({ data });
});

v1Router.post("/admin/kyc/:userId/review", requireAuth, requireRole(["admin"]), (request, response) => {
  const payload = z.object({ status: z.enum(["verified", "rejected"]) }).parse(request.body);
  const data = engine.reviewKyc(request.authUser!.id, request.params.userId, payload.status);
  response.json({ data });
});

v1Router.post("/admin/fraud-flags", requireAuth, requireRole(["admin"]), (request, response) => {
  const payload = z
    .object({
      targetType: z.enum(["user", "group", "transaction"]),
      targetId: z.string(),
      reason: z.string().min(4),
    })
    .parse(request.body);
  const data = engine.createFraudFlag(request.authUser!.id, payload);
  response.status(201).json({ data });
});

v1Router.post("/admin/disputes/:disputeId/resolve", requireAuth, requireRole(["admin", "leader"]), (request, response) => {
  const data = engine.resolveDispute(request.authUser!.id, request.params.disputeId);
  response.json({ data });
});

v1Router.get("/admin/export", requireAuth, requireRole(["admin"]), (request, response) => {
  const format = z.enum(["json", "csv"]).parse(asString(request.query.format) ?? "json");
  const data = engine.exportReport(request.authUser!.id, format);
  response.json({
    data: {
      format,
      content: data,
    },
  });
});

v1Router.get("/admin/audit", requireAuth, requireRole(["admin"]), (request, response) => {
  const content = engine.exportAudit(request.authUser!.id);
  response.json({
    data: {
      format: "json",
      content,
    },
  });
});

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}
