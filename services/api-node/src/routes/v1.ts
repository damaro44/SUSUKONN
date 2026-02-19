import { Router } from "express";
import { z } from "zod";
import { CURRENCIES, GOVERNMENT_ID_TYPES, MFA_METHODS, PAYOUT_REASONS } from "@susukonnect/shared";
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

v1Router.post("/auth/verify-contact", (request, response) => {
  const payload = z
    .object({
      challengeId: z.string().min(4),
      code: z.string().length(6),
      channel: z.enum(["email", "phone"]).optional(),
    })
    .parse(request.body);
  const data = engine.verifyOnboardingContact(payload);
  response.json({ data });
});

v1Router.post("/auth/contact-verifications/resend", (request, response) => {
  const payload = z
    .object({
      email: z.string().email(),
      channel: z.enum(["email", "phone"]),
    })
    .parse(request.body);
  const data = engine.resendContactVerification(payload.email, payload.channel);
  response.status(201).json({ data });
});

v1Router.post("/auth/biometric/enroll", (request, response) => {
  const payload = z
    .object({
      email: z.string().email(),
      password: z.string().min(8),
      deviceId: z.string().min(4),
      deviceLabel: z.string().min(2).optional(),
      mfaChallengeId: z.string().optional(),
      mfaCode: z.string().length(6).optional(),
    })
    .parse(request.body);
  const result = engine.enrollBiometric(payload);
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
  response.json({ data: result.user });
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
    contributionAmount: asString(request.query.contributionAmount),
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
      payoutFrequency: z.string().default("monthly"),
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
  const data = engine.joinGroup(request.authUser!.id, pathParam(request.params.groupId));
  response.json({ data });
});

v1Router.post("/groups/join-by-invite", requireAuth, (request, response) => {
  const payload = z.object({ inviteCode: z.string().min(6) }).parse(request.body);
  const data = engine.joinGroupByInvite(request.authUser!.id, payload.inviteCode);
  response.json({ data });
});

v1Router.get("/groups/:groupId/invite-link", requireAuth, (request, response) => {
  const data = engine.groupInviteLink(request.authUser!.id, pathParam(request.params.groupId));
  response.json({ data });
});

v1Router.get("/groups/:groupId/trust-indicators", requireAuth, (request, response) => {
  const data = engine.groupTrustIndicators(request.authUser!.id, pathParam(request.params.groupId));
  response.json({ data });
});

v1Router.post("/groups/:groupId/join-requests/:userId/decision", requireAuth, (request, response) => {
  const payload = z.object({ decision: z.enum(["approve", "reject"]) }).parse(request.body);
  const data = engine.reviewJoinRequest(
    request.authUser!.id,
    pathParam(request.params.groupId),
    pathParam(request.params.userId),
    payload.decision
  );
  response.json({ data });
});

v1Router.post("/groups/:groupId/remind", requireAuth, (request, response) => {
  const data = engine.sendGroupReminders(request.authUser!.id, pathParam(request.params.groupId));
  response.json({ data });
});

v1Router.patch("/groups/:groupId/config", requireAuth, (request, response) => {
  const payload = z
    .object({
      contributionAmount: z.number().positive().optional(),
      gracePeriodDays: z.number().int().min(0).optional(),
      rules: z.string().min(3).optional(),
      requiresLeaderApproval: z.boolean().optional(),
      payoutOrderLogic: z.enum(["fixed", "voting", "priority"]).optional(),
      totalMembers: z.number().int().min(2).optional(),
    })
    .refine((value) => Object.keys(value).length > 0, {
      message: "At least one configuration field is required.",
    })
    .parse(request.body);
  const data = engine.updateGroupConfig(request.authUser!.id, pathParam(request.params.groupId), payload);
  response.json({ data });
});

v1Router.put("/groups/:groupId/payout-order", requireAuth, (request, response) => {
  const payload = z
    .object({
      payoutOrder: z.array(z.string().min(1)).min(1),
    })
    .parse(request.body);
  const data = engine.updatePayoutOrder(
    request.authUser!.id,
    pathParam(request.params.groupId),
    payload.payoutOrder
  );
  response.json({ data });
});

v1Router.patch("/groups/:groupId/chat-moderation", requireAuth, (request, response) => {
  const payload = z.object({ chatArchived: z.boolean() }).parse(request.body);
  const data = engine.moderateGroupChat(
    request.authUser!.id,
    pathParam(request.params.groupId),
    payload.chatArchived
  );
  response.json({ data });
});

v1Router.patch("/groups/:groupId/status", requireAuth, requireRole(["admin"]), (request, response) => {
  const payload = z.object({ status: z.enum(["active", "suspended"]) }).parse(request.body);
  const data = engine.updateGroupStatus(
    request.authUser!.id,
    pathParam(request.params.groupId),
    payload.status
  );
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
  const result = await engine.payContribution(
    request.authUser!.id,
    pathParam(request.params.contributionId),
    payload
  );
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
    pathParam(request.params.groupId),
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
  engine.submitVote(
    request.authUser!.id,
    pathParam(request.params.groupId),
    payload.candidateId,
    payload.note
  );
  response.status(201).json({ data: { ok: true } });
});

v1Router.post("/groups/:groupId/priority-claims", requireAuth, (request, response) => {
  const payload = z
    .object({
      reason: z.enum(PAYOUT_REASONS),
      customReason: z.string().optional(),
    })
    .parse(request.body);
  engine.submitPriorityClaim(
    request.authUser!.id,
    pathParam(request.params.groupId),
    payload.reason,
    payload.customReason
  );
  response.status(201).json({ data: { ok: true } });
});

v1Router.post("/payouts/:payoutId/approve", requireAuth, (request, response) => {
  const payload = z
    .object({
      mfaChallengeId: z.string().optional(),
      mfaCode: z.string().length(6).optional(),
    })
    .parse(request.body);
  const result = engine.approvePayout(request.authUser!.id, pathParam(request.params.payoutId), payload);
  if (result.mfaRequired) {
    response.status(428).json({
      error: { code: "MFA_REQUIRED", message: "MFA verification is required." },
      data: result.challenge,
    });
    return;
  }
  response.json({ data: result.payout });
});

v1Router.post("/payouts/:payoutId/reason-review", requireAuth, (request, response) => {
  const payload = z
    .object({
      decision: z.enum(["approve", "reject"]),
      reason: z.enum(PAYOUT_REASONS).optional(),
      customReason: z.string().optional(),
      note: z.string().optional(),
    })
    .parse(request.body);
  const data = engine.reviewPayoutReason(request.authUser!.id, pathParam(request.params.payoutId), payload);
  response.json({ data });
});

v1Router.post("/payouts/:payoutId/confirm-recipient", requireAuth, (request, response) => {
  const payload = z
    .object({
      mfaChallengeId: z.string().optional(),
      mfaCode: z.string().length(6).optional(),
    })
    .parse(request.body);
  const result = engine.confirmPayoutRecipient(
    request.authUser!.id,
    pathParam(request.params.payoutId),
    payload
  );
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
  const result = await engine.releasePayout(
    request.authUser!.id,
    pathParam(request.params.payoutId),
    payload
  );
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
  const data = engine.listChat(request.authUser!.id, pathParam(request.params.groupId));
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
  const data = engine.sendChat(request.authUser!.id, pathParam(request.params.groupId), payload);
  response.status(201).json({ data });
});

v1Router.post("/chat/:messageId/pin", requireAuth, (request, response) => {
  const data = engine.togglePin(request.authUser!.id, pathParam(request.params.messageId));
  response.json({ data });
});

v1Router.delete("/chat/:messageId", requireAuth, (request, response) => {
  const data = engine.deleteChatMessage(request.authUser!.id, pathParam(request.params.messageId));
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
  engine.markNotificationRead(request.authUser!.id, pathParam(request.params.notificationId));
  response.status(204).send();
});

v1Router.post("/notifications/read-all", requireAuth, (request, response) => {
  engine.markAllNotificationsRead(request.authUser!.id);
  response.status(204).send();
});

v1Router.post("/me/kyc", requireAuth, async (request, response) => {
  const payload = z
    .object({
      idType: z.enum(GOVERNMENT_ID_TYPES),
      idNumber: z.string().min(2),
      dob: z.string().min(8),
      selfieToken: z.string().min(2),
      livenessToken: z.string().min(6),
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
      mfaMethod: z.enum(MFA_METHODS).optional(),
      mfaChallengeId: z.string().optional(),
      mfaCode: z.string().length(6).optional(),
    })
    .parse(request.body);
  const result = engine.updateSecurity(
    request.authUser!.id,
    {
      mfaEnabled: payload.mfaEnabled,
      biometricEnabled: payload.biometricEnabled,
      mfaMethod: payload.mfaMethod,
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
    pathParam(request.params.methodId),
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
  engine.removeDevice(request.authUser!.id, pathParam(request.params.deviceId));
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

v1Router.post("/admin/users/purge-signups", requireAuth, requireRole(["admin"]), (request, response) => {
  const data = engine.purgeSignupAccounts(request.authUser!.id);
  response.json({ data });
});

v1Router.post("/admin/kyc/:userId/review", requireAuth, requireRole(["admin"]), (request, response) => {
  const payload = z.object({ status: z.enum(["verified", "rejected"]) }).parse(request.body);
  const data = engine.reviewKyc(request.authUser!.id, pathParam(request.params.userId), payload.status);
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

v1Router.get("/admin/fraud-flags", requireAuth, requireRole(["admin"]), (request, response) => {
  const data = engine.listFraudFlags(request.authUser!.id, {
    targetType: asString(request.query.targetType),
    status: asString(request.query.status),
    query: asString(request.query.query),
  });
  response.json({ data });
});

v1Router.post("/admin/fraud-flags/:flagId/resolve", requireAuth, requireRole(["admin"]), (request, response) => {
  const payload = z.object({ resolution: z.string().min(3) }).parse(request.body);
  const data = engine.resolveFraudFlag(
    request.authUser!.id,
    pathParam(request.params.flagId),
    payload.resolution
  );
  response.json({ data });
});

v1Router.get("/admin/compliance/queue", requireAuth, requireRole(["admin"]), (request, response) => {
  const data = engine.complianceQueue(request.authUser!.id);
  response.json({ data });
});

v1Router.post("/admin/disputes/:disputeId/resolve", requireAuth, requireRole(["admin", "leader"]), (request, response) => {
  const data = engine.resolveDispute(request.authUser!.id, pathParam(request.params.disputeId));
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

v1Router.get("/admin/audit/logs", requireAuth, requireRole(["admin"]), (request, response) => {
  const data = engine.listAuditLogs(request.authUser!.id, {
    actorId: asString(request.query.actorId),
    action: asString(request.query.action),
    targetType: asString(request.query.targetType),
    from: asString(request.query.from),
    to: asString(request.query.to),
    limit: Number(asString(request.query.limit) ?? 100),
  });
  response.json({ data });
});

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function pathParam(value: string | string[]): string {
  return Array.isArray(value) ? value[0] : value;
}
