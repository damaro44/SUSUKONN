import {
  CURRENCIES,
  DomainState,
  Group,
  Notification,
  PAYOUT_REASONS,
  PayoutReason,
  PaymentMethodType,
  User,
  UserRole,
} from "@susukonnect/shared";
import { env } from "../config/env.js";
import { KycProvider } from "../providers/kycProvider.js";
import { PaymentProvider } from "../providers/paymentProvider.js";
import { hashPassword, hashValue, tokenRef, uid, generateMfaCode } from "../utils/crypto.js";
import { HttpError, assert } from "../utils/errors.js";
import { addHours, addMinutes, cycleDueDate, cycleGraceDate, nowIso } from "../utils/time.js";

const PRIORITY_WEIGHTS: Record<string, number> = {
  Emergency: 100,
  "Medical procedure": 90,
  "Rent / Housing": 80,
  "College tuition": 70,
  "Business investment": 60,
  Wedding: 50,
  "Custom reason": 45,
  "Family vacation": 40,
};

const MFA_REQUIRED_ACTIONS = new Set([
  "contribution_pay",
  "payout_approve",
  "payout_release",
  "payment_method_update",
  "security_change",
  "login",
]);

interface MfaCheckResult {
  verified: boolean;
  challengeId?: string;
  expiresAt?: string;
  demoCode?: string;
}

interface RegisterInput {
  fullName: string;
  email: string;
  phone: string;
  password: string;
  role: UserRole;
  acceptTerms: boolean;
}

interface LoginInput {
  email: string;
  password: string;
  deviceId: string;
}

interface LoginMfaInput {
  challengeId: string;
  code: string;
  deviceId: string;
}

interface CreateGroupInput {
  name: string;
  description: string;
  communityType: string;
  location: string;
  startDate: string;
  contributionAmount: number;
  currency: string;
  totalMembers: number;
  payoutOrderLogic: "fixed" | "voting" | "priority";
  gracePeriodDays: number;
  requiresLeaderApproval: boolean;
  rules: string;
}

interface KycSubmitInput {
  idType: string;
  idNumber: string;
  dob: string;
  selfieToken: string;
  address?: string;
}

interface SecurityUpdateInput {
  mfaEnabled: boolean;
  biometricEnabled: boolean;
}

interface AddPaymentMethodInput {
  type: PaymentMethodType;
  label: string;
  identifierTail: string;
  providerToken: string;
  autoDebit: boolean;
}

export interface AuthTokens {
  accessToken: string;
  expiresAt: string;
}

export class DomainEngine {
  private state: DomainState;
  private paymentProvider: PaymentProvider;
  private kycProvider: KycProvider;

  constructor() {
    this.state = seedState();
    this.paymentProvider = new PaymentProvider();
    this.kycProvider = new KycProvider();
    this.reconcile();
  }

  getStateSnapshot(): DomainState {
    return JSON.parse(JSON.stringify(this.state)) as DomainState;
  }

  register(input: RegisterInput): Pick<User, "id" | "email" | "role" | "fullName"> {
    const email = normalizeEmail(input.email);
    const phone = normalizePhone(input.phone);
    const role: UserRole = input.role === "leader" ? "leader" : "member";

    assert(input.acceptTerms, 400, "TERMS_REQUIRED", "Terms must be accepted.");
    assert(
      input.password.length >= 8 && /[A-Za-z]/.test(input.password) && /\d/.test(input.password),
      400,
      "WEAK_PASSWORD",
      "Password must be 8+ chars and include letters + numbers."
    );
    assert(
      !this.state.users.some((user) => user.email === email),
      409,
      "EMAIL_EXISTS",
      "Email already exists."
    );
    assert(
      !this.state.users.some((user) => user.phone === phone),
      409,
      "PHONE_EXISTS",
      "Phone already exists."
    );

    const salt = uid("salt");
    const user: User = {
      id: uid("usr"),
      fullName: input.fullName.trim(),
      email,
      phone,
      role,
      passwordHash: hashPassword(input.password, salt),
      salt,
      acceptedTerms: true,
      verifiedBadge: false,
      biometricEnabled: false,
      mfaEnabled: true,
      status: "active",
      knownDevices: [],
      paymentMethods: [],
      metrics: {
        paidContributions: 0,
        completedGroups: 0,
        internalTrustScore: 50,
      },
      kyc: {
        status: "unverified",
        idType: "",
        idNumberToken: "",
        dob: "",
        selfieToken: "",
      },
      createdAt: nowIso(),
    };

    this.state.users.push(user);
    this.notify(
      user.id,
      "Welcome to SusuKonnect",
      "Complete KYC verification before joining groups and receiving payouts.",
      "onboarding",
      `welcome-${user.id}`
    );
    this.logAudit(user.id, "REGISTER_ACCOUNT", "user", user.id, {});
    return { id: user.id, email: user.email, role: user.role, fullName: user.fullName };
  }

  login(input: LoginInput): { requiresMfa: boolean; challenge?: MfaCheckResult; tokens?: AuthTokens; user?: AuthUserView } {
    const email = normalizeEmail(input.email);
    const user = this.state.users.find((candidate) => candidate.email === email);
    assert(user, 401, "INVALID_CREDENTIALS", "Invalid credentials.");
    assert(user.status === "active", 403, "USER_SUSPENDED", "User account is suspended.");

    const control = this.state.authControls.loginAttempts[email] ?? { count: 0 };
    if (control.lockedUntil && new Date(control.lockedUntil) > new Date()) {
      throw new HttpError(429, "ACCOUNT_LOCKED", "Too many failed attempts. Try later.");
    }

    const expectedHash = hashPassword(input.password, user.salt);
    if (expectedHash !== user.passwordHash) {
      const failed = this.state.authControls.loginAttempts[email] ?? { count: 0 };
      failed.count += 1;
      if (failed.count >= 5) {
        failed.count = 0;
        failed.lockedUntil = addMinutes(new Date(), 15);
      }
      this.state.authControls.loginAttempts[email] = failed;
      throw new HttpError(401, "INVALID_CREDENTIALS", "Invalid credentials.");
    }
    this.state.authControls.loginAttempts[email] = { count: 0 };

    const knownDevice = user.knownDevices.some((device) => device.id === input.deviceId);
    if (!knownDevice || user.mfaEnabled) {
      const challenge = this.createMfaChallenge(user.id, "login");
      return { requiresMfa: true, challenge };
    }

    this.touchDevice(user.id, input.deviceId, "Trusted device");
    const tokens = this.issueSession(user.id, input.deviceId);
    this.logAudit(user.id, "LOGIN_SUCCESS", "user", user.id, { deviceId: input.deviceId });
    return { requiresMfa: false, tokens, user: this.publicUser(user.id) };
  }

  verifyLoginMfa(input: LoginMfaInput): { tokens: AuthTokens; user: AuthUserView } {
    const challenge = this.verifyMfaChallenge(input.challengeId, input.code, "login");
    const user = this.requireUser(challenge.userId);
    this.touchDevice(user.id, input.deviceId, "Trusted device");
    const tokens = this.issueSession(user.id, input.deviceId);
    this.logAudit(user.id, "LOGIN_MFA_VERIFIED", "user", user.id, { deviceId: input.deviceId });
    return { tokens, user: this.publicUser(user.id) };
  }

  biometricLogin(emailRaw: string, deviceId: string): { tokens: AuthTokens; user: AuthUserView } {
    const email = normalizeEmail(emailRaw);
    const user = this.state.users.find((candidate) => candidate.email === email);
    assert(user, 404, "NOT_FOUND", "User not found.");
    assert(user.biometricEnabled, 400, "BIOMETRIC_DISABLED", "Biometric login not enabled.");
    assert(
      user.knownDevices.some((device) => device.id === deviceId),
      401,
      "UNKNOWN_DEVICE",
      "Device is not trusted."
    );

    const tokens = this.issueSession(user.id, deviceId);
    this.logAudit(user.id, "BIOMETRIC_LOGIN_SUCCESS", "user", user.id, { deviceId });
    return { tokens, user: this.publicUser(user.id) };
  }

  logout(userId: string, sessionToken: string): void {
    this.state.sessions = this.state.sessions.filter(
      (session) => !(session.userId === userId && session.token === sessionToken)
    );
    this.logAudit(userId, "LOGOUT", "user", userId, {});
  }

  authenticate(accessToken: string): AuthUserView {
    const session = this.state.sessions.find((candidate) => candidate.token === accessToken);
    assert(session, 401, "UNAUTHORIZED", "Invalid token.");
    assert(new Date(session.expiresAt) > new Date(), 401, "TOKEN_EXPIRED", "Session expired.");
    return this.publicUser(session.userId);
  }

  dashboard(userId: string) {
    const groups = this.groupsForUser(userId);
    const notifications = this.userNotifications(userId);
    const pendingContributions = this.state.contributions.filter(
      (entry) =>
        entry.userId === userId &&
        (entry.status === "pending" || entry.status === "late") &&
        this.groupById(entry.groupId)?.cycle === entry.cycle
    );
    const receivedPayouts = this.state.payouts.filter(
      (payout) => payout.recipientId === userId && payout.status === "released"
    );

    return {
      summary: {
        activeGroups: groups.filter((group) => group.status === "active").length,
        pendingContributions: pendingContributions.length,
        receivedPayouts: receivedPayouts.length,
        unreadNotifications: notifications.filter((item) => !item.read).length,
      },
      upcomingEvents: this.calendarEvents(userId).slice(0, 10),
      recentAudit: this.state.auditLogs
        .filter((item) => item.actorId === userId || item.metadata?.targetUserId === userId)
        .slice(-10)
        .reverse(),
      user: this.publicUser(userId),
    };
  }

  listGroups(userId: string, filters: Record<string, string | undefined>): Group[] {
    const query = (filters.query ?? "").toLowerCase();
    const community = (filters.community ?? "").toLowerCase();
    const location = (filters.location ?? "").toLowerCase();
    const maxContribution = Number(filters.maxContribution ?? 0);
    const startDate = filters.startDate ? new Date(filters.startDate) : null;

    return this.state.groups.filter((group) => {
      if (query && !group.name.toLowerCase().includes(query)) {
        return false;
      }
      if (community && !group.communityType.toLowerCase().includes(community)) {
        return false;
      }
      if (location && !group.location.toLowerCase().includes(location)) {
        return false;
      }
      if (maxContribution && group.contributionAmount > maxContribution) {
        return false;
      }
      if (startDate && new Date(group.startDate) < startDate) {
        return false;
      }
      return true;
    });
  }

  createGroup(userId: string, input: CreateGroupInput): Group {
    const actor = this.requireUser(userId);
    assert(actor.kyc.status === "verified", 403, "KYC_REQUIRED", "KYC verification is required.");
    assert(input.totalMembers >= 2, 400, "INVALID_GROUP_SIZE", "Group requires at least 2 members.");
    assert(CURRENCIES.includes(input.currency as never), 400, "INVALID_CURRENCY", "Unsupported currency.");

    if (actor.role === "member") {
      actor.role = "leader";
    }

    const group: Group = {
      id: uid("grp"),
      inviteCode: uid("join"),
      name: input.name.trim(),
      description: input.description.trim(),
      communityType: input.communityType.trim(),
      location: input.location.trim(),
      startDate: input.startDate,
      contributionAmount: Number(input.contributionAmount),
      currency: input.currency as Group["currency"],
      totalMembers: Number(input.totalMembers),
      payoutFrequency: "monthly",
      payoutOrderLogic: input.payoutOrderLogic,
      gracePeriodDays: Number(input.gracePeriodDays),
      requiresLeaderApproval: Boolean(input.requiresLeaderApproval),
      rules: input.rules.trim(),
      leaderId: userId,
      memberIds: [userId],
      joinRequests: [],
      payoutOrder: [userId],
      cycle: 1,
      status: "active",
      chatArchived: false,
      createdAt: nowIso(),
    };

    this.state.groups.push(group);
    this.ensureCycleContributions(group);
    this.logAudit(userId, "CREATE_GROUP", "group", group.id, {
      amount: group.contributionAmount,
      currency: group.currency,
    });
    return group;
  }

  joinGroup(userId: string, groupId: string): Group {
    const user = this.requireUser(userId);
    const group = this.requireGroup(groupId);
    assert(user.kyc.status === "verified", 403, "KYC_REQUIRED", "KYC must be verified to join groups.");
    assert(group.status === "active", 409, "GROUP_NOT_ACTIVE", "Group is not active.");
    assert(!group.memberIds.includes(userId), 409, "ALREADY_MEMBER", "Already in group.");
    assert(group.memberIds.length < group.totalMembers, 409, "GROUP_FULL", "Group is full.");

    if (group.requiresLeaderApproval) {
      if (!group.joinRequests.includes(userId)) {
        group.joinRequests.push(userId);
      }
      this.notify(
        group.leaderId,
        "Join request pending",
        `${user.fullName} requested to join ${group.name}.`,
        "group",
        `join-request-${group.id}-${userId}`
      );
      this.logAudit(userId, "REQUEST_JOIN_GROUP", "group", group.id, { targetUserId: userId });
      return group;
    }

    this.addMember(group, userId);
    this.logAudit(userId, "JOIN_GROUP", "group", group.id, { targetUserId: userId });
    return group;
  }

  reviewJoinRequest(actorId: string, groupId: string, targetUserId: string, decision: "approve" | "reject"): Group {
    const actor = this.requireUser(actorId);
    const group = this.requireGroup(groupId);
    this.assertGroupManager(actor, group);
    assert(group.joinRequests.includes(targetUserId), 404, "REQUEST_NOT_FOUND", "No pending request.");

    group.joinRequests = group.joinRequests.filter((candidate) => candidate !== targetUserId);
    if (decision === "approve") {
      this.addMember(group, targetUserId);
      this.notify(
        targetUserId,
        "Join request approved",
        `You were added to ${group.name}.`,
        "group",
        `join-approved-${group.id}-${targetUserId}`
      );
      this.logAudit(actorId, "APPROVE_JOIN_REQUEST", "group", group.id, { targetUserId });
    } else {
      this.notify(
        targetUserId,
        "Join request rejected",
        `Your request for ${group.name} was declined.`,
        "group",
        `join-rejected-${group.id}-${targetUserId}`
      );
      this.logAudit(actorId, "REJECT_JOIN_REQUEST", "group", group.id, { targetUserId });
    }
    return group;
  }

  sendGroupReminders(actorId: string, groupId: string): { reminded: number } {
    const actor = this.requireUser(actorId);
    const group = this.requireGroup(groupId);
    this.assertGroupManager(actor, group);
    const pending = this.cycleContributions(group.id, group.cycle).filter(
      (entry) => entry.status === "pending" || entry.status === "late"
    );
    pending.forEach((entry) => {
      this.notify(
        entry.userId,
        "Contribution reminder",
        `Your contribution is due for ${group.name}.`,
        "reminder",
        `manual-reminder-${group.id}-${group.cycle}-${entry.userId}-${new Date().toISOString().slice(0, 10)}`
      );
    });
    this.logAudit(actorId, "SEND_GROUP_REMINDER", "group", group.id, { pendingCount: pending.length });
    return { reminded: pending.length };
  }

  listContributions(userId: string, groupId?: string) {
    const groups = this.groupsForUser(userId).map((group) => group.id);
    return this.state.contributions.filter((entry) => {
      if (!groups.includes(entry.groupId)) {
        return false;
      }
      if (groupId && entry.groupId !== groupId) {
        return false;
      }
      return true;
    });
  }

  async payContribution(
    userId: string,
    contributionId: string,
    payload: {
      methodId: string;
      enableAutoDebit: boolean;
      mfaChallengeId?: string;
      mfaCode?: string;
    }
  ) {
    const user = this.requireUser(userId);
    const contribution = this.state.contributions.find((entry) => entry.id === contributionId);
    assert(contribution, 404, "NOT_FOUND", "Contribution not found.");
    assert(contribution.userId === userId, 403, "FORBIDDEN", "Cannot pay another user's contribution.");
    assert(contribution.status !== "paid", 409, "ALREADY_PAID", "Contribution already paid.");

    const method = user.paymentMethods.find((item) => item.id === payload.methodId);
    assert(method, 404, "METHOD_NOT_FOUND", "Payment method not found.");
    const group = this.requireGroup(contribution.groupId);
    assert(group.status === "active", 409, "GROUP_NOT_ACTIVE", "Group is not active.");

    const mfa = this.assertMfa(userId, "contribution_pay", payload.mfaChallengeId, payload.mfaCode);
    if (!mfa.verified) {
      return { mfaRequired: true, challenge: mfa };
    }

    const providerResult = await this.paymentProvider.chargeContribution({
      amount: contribution.amount,
      currency: group.currency,
      paymentMethodType: method.type,
      paymentTokenRef: method.tokenRef,
      metadata: {
        userId,
        groupId: group.id,
        contributionId: contribution.id,
      },
    });
    assert(providerResult.ok, 422, "PAYMENT_FAILED", "Contribution payment failed.");

    contribution.status = "paid";
    contribution.methodId = method.id;
    contribution.methodType = method.type;
    contribution.providerReference = providerResult.reference;
    contribution.paidAt = nowIso();
    contribution.autoDebit = payload.enableAutoDebit;
    if (payload.enableAutoDebit) {
      method.autoDebit = true;
    }

    this.notify(
      group.leaderId,
      "Contribution paid",
      `${user.fullName} paid ${formatMoney(contribution.amount, group.currency)} in ${group.name}.`,
      "payment",
      `contribution-paid-${contribution.id}`
    );
    this.logAudit(userId, "PAY_CONTRIBUTION", "contribution", contribution.id, {
      groupId: group.id,
      providerReference: providerResult.reference,
    });
    this.reconcile();
    return { mfaRequired: false, contribution };
  }

  listPayouts(userId: string, groupId?: string) {
    const groups = this.groupsForUser(userId).map((group) => group.id);
    return this.state.payouts.filter((payout) => {
      if (!groups.includes(payout.groupId)) {
        return false;
      }
      if (groupId && payout.groupId !== groupId) {
        return false;
      }
      return true;
    });
  }

  submitVote(userId: string, groupId: string, candidateId: string, note?: string) {
    const group = this.requireGroup(groupId);
    assert(group.memberIds.includes(userId), 403, "FORBIDDEN", "Only members can vote.");
    assert(group.memberIds.includes(candidateId), 400, "INVALID_CANDIDATE", "Candidate is not in group.");
    assert(group.payoutOrderLogic === "voting", 400, "INVALID_LOGIC", "Group is not voting-based.");
    assert(
      !this.state.payoutVotes.some(
        (vote) => vote.groupId === groupId && vote.cycle === group.cycle && vote.voterId === userId
      ),
      409,
      "ALREADY_VOTED",
      "You already voted this cycle."
    );
    this.state.payoutVotes.push({
      id: uid("vote"),
      groupId,
      cycle: group.cycle,
      voterId: userId,
      candidateId,
      note,
      createdAt: nowIso(),
    });
    this.logAudit(userId, "SUBMIT_PAYOUT_VOTE", "group", groupId, { targetUserId: candidateId });
  }

  submitPriorityClaim(userId: string, groupId: string, reason: PayoutReason, customReason?: string) {
    const group = this.requireGroup(groupId);
    assert(group.memberIds.includes(userId), 403, "FORBIDDEN", "Only members can submit claims.");
    assert(group.payoutOrderLogic === "priority", 400, "INVALID_LOGIC", "Group is not priority-based.");
    assert(PAYOUT_REASONS.includes(reason), 400, "INVALID_REASON", "Unsupported reason.");
    assert(
      !this.state.priorityClaims.some(
        (claim) => claim.groupId === groupId && claim.cycle === group.cycle && claim.userId === userId
      ),
      409,
      "ALREADY_SUBMITTED",
      "Priority claim already submitted this cycle."
    );
    this.state.priorityClaims.push({
      id: uid("claim"),
      groupId,
      cycle: group.cycle,
      userId,
      reason,
      customReason,
      weight: PRIORITY_WEIGHTS[reason] ?? PRIORITY_WEIGHTS["Custom reason"],
      createdAt: nowIso(),
    });
    this.logAudit(userId, "SUBMIT_PRIORITY_CLAIM", "group", groupId, { reason, customReason });
  }

  requestPayout(
    userId: string,
    groupId: string,
    reason: PayoutReason,
    customReason?: string
  ) {
    const group = this.requireGroup(groupId);
    assert(group.memberIds.includes(userId), 403, "FORBIDDEN", "Only members can request payouts.");
    assert(PAYOUT_REASONS.includes(reason), 400, "INVALID_REASON", "Unsupported reason.");
    assert(this.allContributionsPaid(group.id, group.cycle), 409, "CONTRIBUTIONS_PENDING", "Contributions pending.");
    assert(!this.currentPayout(group.id, group.cycle), 409, "PAYOUT_EXISTS", "Payout already requested.");

    const recipientId = this.eligibleRecipient(group, group.cycle);
    assert(recipientId === userId, 403, "NOT_ELIGIBLE", "You are not eligible this cycle.");
    const recipient = this.requireUser(userId);
    assert(recipient.kyc.status === "verified", 403, "KYC_REQUIRED", "KYC required for payouts.");

    const amount = this.cycleContributions(group.id, group.cycle).reduce(
      (sum, entry) => sum + Number(entry.amount),
      0
    );
    const payout = {
      id: uid("pay"),
      groupId: group.id,
      cycle: group.cycle,
      recipientId: userId,
      amount,
      currency: group.currency,
      reason,
      customReason,
      status: "requested" as const,
      requestedAt: nowIso(),
      recipientMfaConfirmed: false,
      platformFee: 0,
      netAmount: 0,
    };
    this.state.payouts.push(payout);

    this.notify(
      group.leaderId,
      "Payout request submitted",
      `${recipient.fullName} requested payout in ${group.name}.`,
      "payout",
      `payout-request-${payout.id}`
    );
    this.adminUsers().forEach((admin) => {
      this.notify(
        admin.id,
        "Payout review required",
        `Payout request in ${group.name} cycle ${group.cycle} needs review.`,
        "compliance",
        `payout-review-${payout.id}-${admin.id}`
      );
    });
    this.logAudit(userId, "REQUEST_PAYOUT", "payout", payout.id, { groupId: group.id });
    return payout;
  }

  approvePayout(
    actorId: string,
    payoutId: string,
    payload: { mfaChallengeId?: string; mfaCode?: string }
  ) {
    const actor = this.requireUser(actorId);
    const payout = this.requirePayout(payoutId);
    const group = this.requireGroup(payout.groupId);
    assert(
      actor.role === "admin" || group.leaderId === actorId,
      403,
      "FORBIDDEN",
      "Only admin or group leader can approve payouts."
    );

    const mfa = this.assertMfa(actorId, "payout_approve", payload.mfaChallengeId, payload.mfaCode);
    if (!mfa.verified) {
      return { mfaRequired: true, challenge: mfa };
    }

    if (actor.role === "admin") {
      payout.adminApprovedBy = actorId;
    } else {
      payout.leaderApprovedBy = actorId;
    }
    this.refreshPayoutStatus(group, payout);
    this.logAudit(actorId, "APPROVE_PAYOUT", "payout", payout.id, {});
    return { mfaRequired: false, payout };
  }

  confirmPayoutRecipient(userId: string, payoutId: string, payload: { mfaChallengeId?: string; mfaCode?: string }) {
    const payout = this.requirePayout(payoutId);
    assert(payout.recipientId === userId, 403, "FORBIDDEN", "Only recipient can confirm.");
    const mfa = this.assertMfa(userId, "payout_approve", payload.mfaChallengeId, payload.mfaCode);
    if (!mfa.verified) {
      return { mfaRequired: true, challenge: mfa };
    }
    payout.recipientMfaConfirmed = true;
    this.logAudit(userId, "CONFIRM_PAYOUT_MFA", "payout", payout.id, {});
    return { mfaRequired: false, payout };
  }

  async releasePayout(
    actorId: string,
    payoutId: string,
    payload: { mfaChallengeId?: string; mfaCode?: string }
  ) {
    const actor = this.requireUser(actorId);
    const payout = this.requirePayout(payoutId);
    const group = this.requireGroup(payout.groupId);
    assert(actor.role === "admin" || group.leaderId === actorId, 403, "FORBIDDEN", "Only manager can release.");
    assert(this.allContributionsPaid(group.id, group.cycle), 409, "CONTRIBUTIONS_PENDING", "Contributions pending.");
    this.refreshPayoutStatus(group, payout);
    assert(payout.status === "approved", 409, "PAYOUT_NOT_APPROVED", "Payout is not approved.");
    assert(payout.recipientMfaConfirmed, 409, "RECIPIENT_MFA_PENDING", "Recipient MFA pending.");

    const mfa = this.assertMfa(actorId, "payout_release", payload.mfaChallengeId, payload.mfaCode);
    if (!mfa.verified) {
      return { mfaRequired: true, challenge: mfa };
    }

    const recipient = this.requireUser(payout.recipientId);
    const preferredMethod = recipient.paymentMethods[0];
    const channel = preferredMethod?.type === "paypal" ? "paypal" : "stripe";
    const destinationTokenRef = preferredMethod?.tokenRef ?? "manual_destination";

    const fee = roundTwo(payout.amount * env.PLATFORM_FEE_RATE);
    const netAmount = roundTwo(payout.amount - fee);

    const provider = await this.paymentProvider.releasePayout({
      amount: netAmount,
      currency: payout.currency,
      payoutChannel: channel,
      destinationTokenRef,
      recipientEmail: recipient.email,
      metadata: {
        payoutId: payout.id,
        groupId: group.id,
      },
    });
    assert(provider.ok, 422, "PAYOUT_RELEASE_FAILED", "Provider payout release failed.");

    payout.status = "released";
    payout.platformFee = fee;
    payout.netAmount = netAmount;
    payout.providerReference = provider.reference;
    payout.releasedAt = nowIso();

    this.notify(
      payout.recipientId,
      "Payout released",
      `${formatMoney(netAmount, payout.currency)} released from ${group.name}.`,
      "payout",
      `payout-released-${payout.id}`
    );
    group.memberIds.forEach((memberId) => {
      if (memberId !== payout.recipientId) {
        this.notify(
          memberId,
          "Payout completed",
          `${recipient.fullName} received payout in ${group.name}.`,
          "payout",
          `payout-complete-${payout.id}-${memberId}`
        );
      }
    });

    this.logAudit(actorId, "RELEASE_PAYOUT", "payout", payout.id, {
      providerReference: provider.reference,
      netAmount,
      fee,
    });
    this.rollCycle(group);
    this.reconcile();
    return { mfaRequired: false, payout };
  }

  listChat(userId: string, groupId: string) {
    const group = this.requireGroup(groupId);
    assert(group.memberIds.includes(userId), 403, "FORBIDDEN", "Only members can access group chat.");
    return this.state.chats
      .filter((item) => item.groupId === group.id)
      .sort((a, b) => {
        if (a.pinned !== b.pinned) {
          return a.pinned ? -1 : 1;
        }
        return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
      });
  }

  sendChat(
    userId: string,
    groupId: string,
    input: { content: string; announcement?: boolean; pin?: boolean }
  ) {
    const group = this.requireGroup(groupId);
    const actor = this.requireUser(userId);
    assert(group.memberIds.includes(userId), 403, "FORBIDDEN", "Only members can send messages.");
    assert(!group.chatArchived && group.status !== "completed", 409, "CHAT_ARCHIVED", "Chat is archived.");
    assert(input.content.trim().length > 0, 400, "EMPTY_MESSAGE", "Message cannot be empty.");

    const canModerate = actor.role === "admin" || group.leaderId === userId;
    const message = {
      id: uid("msg"),
      groupId,
      userId,
      content: input.content.trim(),
      type: (canModerate && input.announcement ? "announcement" : "message") as
        | "announcement"
        | "message",
      pinned: canModerate && Boolean(input.pin),
      createdAt: nowIso(),
    };
    this.state.chats.push(message);
    this.logAudit(userId, "SEND_CHAT_MESSAGE", "chat", message.id, { groupId });
    if (message.type === "announcement") {
      group.memberIds
        .filter((memberId) => memberId !== userId)
        .forEach((memberId) => {
          this.notify(
            memberId,
            `Announcement in ${group.name}`,
            message.content.slice(0, 150),
            "chat",
            `chat-announce-${message.id}-${memberId}`
          );
        });
    }
    return message;
  }

  togglePin(actorId: string, messageId: string) {
    const actor = this.requireUser(actorId);
    const message = this.state.chats.find((item) => item.id === messageId);
    assert(message, 404, "NOT_FOUND", "Message not found.");
    const group = this.requireGroup(message.groupId);
    assert(
      actor.role === "admin" || group.leaderId === actorId,
      403,
      "FORBIDDEN",
      "Only admin/leader can pin."
    );
    message.pinned = !message.pinned;
    this.logAudit(actorId, "TOGGLE_CHAT_PIN", "chat", message.id, { pinned: message.pinned });
    return message;
  }

  calendarEvents(userId: string) {
    const groups = this.groupsForUser(userId);
    const events = groups.flatMap((group) => {
      const dueDate = cycleDueDate(group.startDate, group.cycle);
      const graceDate = cycleGraceDate(group.startDate, group.cycle, group.gracePeriodDays);
      const payout = this.currentPayout(group.id, group.cycle);
      return [
        {
          id: `due-${group.id}-${group.cycle}`,
          date: dueDate,
          title: "Monthly contribution due",
          type: "contribution_due",
          groupId: group.id,
          groupName: group.name,
        },
        {
          id: `grace-${group.id}-${group.cycle}`,
          date: graceDate,
          title: "Grace deadline",
          type: "grace_deadline",
          groupId: group.id,
          groupName: group.name,
        },
        {
          id: `payout-${group.id}-${group.cycle}`,
          date: dueDate,
          title: payout ? `Payout ${payout.status}` : "Payout checkpoint",
          type: "payout_checkpoint",
          groupId: group.id,
          groupName: group.name,
        },
      ];
    });
    return events.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
  }

  userNotifications(userId: string): Notification[] {
    return this.state.notifications
      .filter((item) => item.userId === userId)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  markNotificationRead(userId: string, notificationId: string) {
    const note = this.state.notifications.find((item) => item.id === notificationId);
    assert(note, 404, "NOT_FOUND", "Notification not found.");
    assert(note.userId === userId, 403, "FORBIDDEN", "Cannot update another user's notification.");
    note.read = true;
  }

  markAllNotificationsRead(userId: string) {
    this.state.notifications.forEach((note) => {
      if (note.userId === userId) {
        note.read = true;
      }
    });
  }

  async submitKyc(userId: string, input: KycSubmitInput) {
    const user = this.requireUser(userId);
    assert(input.idType && input.idNumber && input.selfieToken && input.dob, 400, "INVALID_INPUT", "Missing KYC data.");

    const kycCase = await this.kycProvider.createCase({
      userId,
      fullName: user.fullName,
      email: user.email,
    });

    user.kyc = {
      status: "pending",
      idType: input.idType,
      idNumberToken: tokenRef(`id:${input.idNumber}`),
      dob: input.dob,
      selfieToken: tokenRef(`selfie:${input.selfieToken}`),
      addressToken: input.address ? tokenRef(`address:${input.address}`) : undefined,
      providerCaseId: kycCase.caseId,
      submittedAt: nowIso(),
    };

    this.adminUsers().forEach((admin) => {
      this.notify(
        admin.id,
        "KYC review required",
        `${user.fullName} submitted KYC documents.`,
        "compliance",
        `kyc-review-${user.id}-${admin.id}`
      );
    });
    this.logAudit(userId, "SUBMIT_KYC", "user", userId, { providerCaseId: kycCase.caseId });
    return {
      status: user.kyc.status,
      providerCaseId: kycCase.caseId,
      providerClientSecret: kycCase.clientSecret,
      mode: kycCase.mode,
    };
  }

  async createKycSession(userId: string) {
    const user = this.requireUser(userId);
    const result = await this.kycProvider.createCase({
      userId,
      fullName: user.fullName,
      email: user.email,
    });
    return result;
  }

  updateSecurity(userId: string, input: SecurityUpdateInput, mfaChallengeId?: string, mfaCode?: string) {
    const mfa = this.assertMfa(userId, "security_change", mfaChallengeId, mfaCode);
    if (!mfa.verified) {
      return { mfaRequired: true, challenge: mfa };
    }
    const user = this.requireUser(userId);
    user.mfaEnabled = Boolean(input.mfaEnabled);
    user.biometricEnabled = Boolean(input.biometricEnabled);
    this.logAudit(userId, "UPDATE_SECURITY_SETTINGS", "user", userId, {
      mfaEnabled: input.mfaEnabled,
      biometricEnabled: input.biometricEnabled,
    });
    return { mfaRequired: false, user: this.publicUser(userId) };
  }

  addPaymentMethod(
    userId: string,
    input: AddPaymentMethodInput,
    mfaChallengeId?: string,
    mfaCode?: string
  ) {
    const mfa = this.assertMfa(userId, "payment_method_update", mfaChallengeId, mfaCode);
    if (!mfa.verified) {
      return { mfaRequired: true, challenge: mfa };
    }

    const user = this.requireUser(userId);
    assert(input.identifierTail.length >= 2, 400, "INVALID_IDENTIFIER", "Invalid identifier.");
    const method = {
      id: uid("pm"),
      type: input.type,
      label: input.label.trim(),
      last4: input.identifierTail.slice(-4),
      tokenRef: input.providerToken.trim() || tokenRef(`${input.type}:${input.label}:${input.identifierTail}`),
      autoDebit: Boolean(input.autoDebit),
      createdAt: nowIso(),
    };
    user.paymentMethods.push(method);
    this.logAudit(userId, "ADD_PAYMENT_METHOD", "payment_method", method.id, { type: method.type });
    return { mfaRequired: false, paymentMethod: method };
  }

  removePaymentMethod(userId: string, methodId: string, mfaChallengeId?: string, mfaCode?: string) {
    const mfa = this.assertMfa(userId, "payment_method_update", mfaChallengeId, mfaCode);
    if (!mfa.verified) {
      return { mfaRequired: true, challenge: mfa };
    }
    const user = this.requireUser(userId);
    const before = user.paymentMethods.length;
    user.paymentMethods = user.paymentMethods.filter((entry) => entry.id !== methodId);
    assert(before !== user.paymentMethods.length, 404, "NOT_FOUND", "Payment method not found.");
    this.logAudit(userId, "REMOVE_PAYMENT_METHOD", "payment_method", methodId, {});
    return { mfaRequired: false };
  }

  removeDevice(userId: string, deviceId: string) {
    const user = this.requireUser(userId);
    user.knownDevices = user.knownDevices.filter((entry) => entry.id !== deviceId);
    this.logAudit(userId, "REMOVE_TRUSTED_DEVICE", "device", deviceId, {});
  }

  submitDispute(userId: string, groupId: string, summary: string) {
    const group = this.requireGroup(groupId);
    assert(group.memberIds.includes(userId), 403, "FORBIDDEN", "Only members can submit disputes.");
    assert(summary.trim().length > 0, 400, "INVALID_INPUT", "Summary cannot be empty.");
    const dispute = {
      id: uid("dispute"),
      groupId,
      reporterId: userId,
      summary: summary.trim(),
      status: "open" as const,
      createdAt: nowIso(),
    };
    this.state.disputes.push(dispute);
    this.notify(
      group.leaderId,
      "Dispute filed",
      `${this.requireUser(userId).fullName} filed a dispute in ${group.name}.`,
      "dispute",
      `dispute-${dispute.id}-leader`
    );
    this.adminUsers().forEach((admin) => {
      this.notify(
        admin.id,
        "Dispute requires review",
        `Dispute created in ${group.name}.`,
        "dispute",
        `dispute-${dispute.id}-${admin.id}`
      );
    });
    this.logAudit(userId, "FILE_DISPUTE", "dispute", dispute.id, {});
    return dispute;
  }

  adminOverview(userId: string) {
    const user = this.requireUser(userId);
    assert(user.role === "admin", 403, "FORBIDDEN", "Admin role required.");
    return {
      pendingKyc: this.state.users.filter((candidate) => candidate.kyc.status === "pending"),
      lateContributions: this.state.contributions.filter((entry) => entry.status === "late"),
      openDisputes: this.state.disputes.filter((entry) => entry.status === "open"),
      fraudFlags: this.state.fraudFlags,
      groups: this.state.groups,
      recentAuditLogs: [...this.state.auditLogs].slice(-50).reverse(),
    };
  }

  reviewKyc(adminId: string, targetUserId: string, status: "verified" | "rejected") {
    const admin = this.requireUser(adminId);
    assert(admin.role === "admin", 403, "FORBIDDEN", "Admin role required.");
    const user = this.requireUser(targetUserId);
    user.kyc.status = status;
    user.verifiedBadge = status === "verified";
    this.notify(
      user.id,
      "KYC status updated",
      `Your KYC status is now ${status}.`,
      "compliance",
      `kyc-status-${user.id}-${status}-${Date.now()}`
    );
    this.logAudit(adminId, "REVIEW_KYC", "user", user.id, { status });
    this.reconcile();
    return user;
  }

  createFraudFlag(adminId: string, input: { targetType: "user" | "group" | "transaction"; targetId: string; reason: string }) {
    const admin = this.requireUser(adminId);
    assert(admin.role === "admin", 403, "FORBIDDEN", "Admin role required.");
    const flag = {
      id: uid("flag"),
      targetType: input.targetType,
      targetId: input.targetId,
      reason: input.reason,
      createdBy: adminId,
      createdAt: nowIso(),
    };
    this.state.fraudFlags.push(flag);
    this.logAudit(adminId, "CREATE_FRAUD_FLAG", "flag", flag.id, input);
    return flag;
  }

  resolveDispute(actorId: string, disputeId: string) {
    const actor = this.requireUser(actorId);
    const dispute = this.state.disputes.find((entry) => entry.id === disputeId);
    assert(dispute, 404, "NOT_FOUND", "Dispute not found.");
    const group = this.requireGroup(dispute.groupId);
    assert(
      actor.role === "admin" || group.leaderId === actorId,
      403,
      "FORBIDDEN",
      "Only admin or group leader can resolve disputes."
    );
    dispute.status = "resolved";
    dispute.resolvedAt = nowIso();
    dispute.resolution = `Resolved by ${actor.fullName}`;
    this.notify(
      dispute.reporterId,
      "Dispute resolved",
      `Your dispute in ${group.name} has been resolved.`,
      "dispute",
      `dispute-resolved-${dispute.id}`
    );
    this.logAudit(actorId, "RESOLVE_DISPUTE", "dispute", dispute.id, {});
    return dispute;
  }

  updateGroupStatus(adminId: string, groupId: string, status: "active" | "suspended") {
    const admin = this.requireUser(adminId);
    assert(admin.role === "admin", 403, "FORBIDDEN", "Admin role required.");
    const group = this.requireGroup(groupId);
    group.status = status;
    this.notifyGroup(
      group,
      status === "active" ? "Group reactivated" : "Group suspended",
      status === "active"
        ? `${group.name} is active again.`
        : `${group.name} is suspended pending compliance review.`,
      "compliance",
      `${status}-${group.id}-${Date.now()}`
    );
    this.logAudit(adminId, "UPDATE_GROUP_STATUS", "group", group.id, { status });
    return group;
  }

  exportReport(adminId: string, format: "json" | "csv") {
    const admin = this.requireUser(adminId);
    assert(admin.role === "admin", 403, "FORBIDDEN", "Admin role required.");
    const payload = {
      generatedAt: nowIso(),
      users: this.state.users.map((user) => ({
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        role: user.role,
        kycStatus: user.kyc.status,
        trustScoreInternal: user.metrics.internalTrustScore,
      })),
      groups: this.state.groups.map((group) => ({
        id: group.id,
        name: group.name,
        status: group.status,
        members: group.memberIds.length,
        cycle: group.cycle,
      })),
      contributions: this.state.contributions.length,
      payouts: this.state.payouts.length,
      disputes: this.state.disputes.length,
      fraudFlags: this.state.fraudFlags.length,
    };
    if (format === "json") {
      return JSON.stringify(payload, null, 2);
    }
    const lines = [
      "type,id,name,status,metricA,metricB",
      ...payload.users.map(
        (item) =>
          `user,${item.id},"${escapeCsv(item.fullName)}",${item.kycStatus},${item.trustScoreInternal},${item.role}`
      ),
      ...payload.groups.map(
        (item) => `group,${item.id},"${escapeCsv(item.name)}",${item.status},${item.members},${item.cycle}`
      ),
    ];
    return lines.join("\n");
  }

  exportAudit(adminId: string) {
    const admin = this.requireUser(adminId);
    assert(admin.role === "admin", 403, "FORBIDDEN", "Admin role required.");
    return JSON.stringify(
      {
        generatedAt: nowIso(),
        entries: this.state.auditLogs,
      },
      null,
      2
    );
  }

  mfaPreview(challengeId: string) {
    const challenge = this.state.mfaChallenges.find((item) => item.id === challengeId);
    return challenge?.code;
  }

  private assertMfa(userId: string, purpose: string, challengeId?: string, code?: string): MfaCheckResult {
    const user = this.requireUser(userId);
    if (!MFA_REQUIRED_ACTIONS.has(purpose) || !user.mfaEnabled) {
      return { verified: true };
    }
    if (!challengeId || !code) {
      return this.createMfaChallenge(userId, purpose);
    }
    this.verifyMfaChallenge(challengeId, code, purpose);
    return { verified: true };
  }

  private createMfaChallenge(userId: string, purpose: string): MfaCheckResult {
    const challenge = {
      id: uid("mfa"),
      userId,
      purpose,
      code: generateMfaCode(),
      expiresAt: addMinutes(new Date(), env.MFA_TTL_MINUTES),
    };
    this.state.mfaChallenges.push(challenge);
    return {
      verified: false,
      challengeId: challenge.id,
      expiresAt: challenge.expiresAt,
      demoCode: env.EXPOSE_MFA_CODES ? challenge.code : undefined,
    };
  }

  private verifyMfaChallenge(challengeId: string, code: string, expectedPurpose: string) {
    const challenge = this.state.mfaChallenges.find((entry) => entry.id === challengeId);
    assert(challenge, 401, "INVALID_MFA_CHALLENGE", "MFA challenge not found.");
    assert(challenge.purpose === expectedPurpose, 401, "INVALID_MFA_PURPOSE", "MFA challenge purpose mismatch.");
    assert(new Date(challenge.expiresAt) > new Date(), 401, "MFA_EXPIRED", "MFA challenge expired.");
    assert(challenge.code === code, 401, "INVALID_MFA_CODE", "Invalid MFA code.");
    this.state.mfaChallenges = this.state.mfaChallenges.filter((entry) => entry.id !== challengeId);
    return challenge;
  }

  private issueSession(userId: string, deviceId: string): AuthTokens {
    const token = uid("sess");
    const now = new Date();
    const expiresAt = addHours(now, env.SESSION_TTL_HOURS);
    this.state.sessions = this.state.sessions.filter((session) => session.userId !== userId);
    this.state.sessions.push({
      token,
      userId,
      deviceId,
      createdAt: now.toISOString(),
      expiresAt,
    });
    const user = this.requireUser(userId);
    user.lastLoginAt = nowIso();
    return { accessToken: token, expiresAt };
  }

  private touchDevice(userId: string, deviceId: string, label: string) {
    const user = this.requireUser(userId);
    const existing = user.knownDevices.find((entry) => entry.id === deviceId);
    if (existing) {
      existing.lastSeenAt = nowIso();
      return;
    }
    user.knownDevices.push({ id: deviceId, label, lastSeenAt: nowIso() });
  }

  private requireUser(userId: string): User {
    const user = this.state.users.find((candidate) => candidate.id === userId);
    assert(user, 404, "NOT_FOUND", "User not found.");
    return user;
  }

  private publicUser(userId: string): AuthUserView {
    const user = this.requireUser(userId);
    return {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      phone: user.phone,
      role: user.role,
      status: user.status,
      verifiedBadge: user.verifiedBadge,
      biometricEnabled: user.biometricEnabled,
      mfaEnabled: user.mfaEnabled,
      kyc: user.kyc,
      metrics: user.metrics,
      paymentMethods: user.paymentMethods,
      knownDevices: user.knownDevices,
    };
  }

  private requireGroup(groupId: string): Group {
    const group = this.groupById(groupId);
    assert(group, 404, "NOT_FOUND", "Group not found.");
    return group;
  }

  private requirePayout(payoutId: string) {
    const payout = this.state.payouts.find((entry) => entry.id === payoutId);
    assert(payout, 404, "NOT_FOUND", "Payout not found.");
    return payout;
  }

  private groupById(groupId: string): Group | undefined {
    return this.state.groups.find((group) => group.id === groupId);
  }

  private groupsForUser(userId: string): Group[] {
    return this.state.groups.filter((group) => group.memberIds.includes(userId));
  }

  private cycleContributions(groupId: string, cycle: number) {
    return this.state.contributions.filter((entry) => entry.groupId === groupId && entry.cycle === cycle);
  }

  private allContributionsPaid(groupId: string, cycle: number): boolean {
    const entries = this.cycleContributions(groupId, cycle);
    return entries.length > 0 && entries.every((entry) => entry.status === "paid");
  }

  private currentPayout(groupId: string, cycle: number) {
    return this.state.payouts.find((entry) => entry.groupId === groupId && entry.cycle === cycle);
  }

  private eligibleRecipient(group: Group, cycle: number): string {
    const rotation = group.payoutOrder.length
      ? group.payoutOrder[(cycle - 1) % group.payoutOrder.length]
      : group.memberIds[(cycle - 1) % group.memberIds.length];
    if (group.payoutOrderLogic === "fixed") {
      return rotation;
    }
    if (group.payoutOrderLogic === "voting") {
      const votes = this.state.payoutVotes
        .filter((vote) => vote.groupId === group.id && vote.cycle === cycle)
        .reduce<Record<string, number>>((acc, vote) => {
          acc[vote.candidateId] = (acc[vote.candidateId] || 0) + 1;
          return acc;
        }, {});
      const winner = Object.entries(votes).sort((a, b) => b[1] - a[1])[0]?.[0];
      return winner ?? rotation;
    }
    if (group.payoutOrderLogic === "priority") {
      const claim = this.state.priorityClaims
        .filter((item) => item.groupId === group.id && item.cycle === cycle)
        .sort((a, b) => b.weight - a.weight || new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime())[0];
      return claim?.userId ?? rotation;
    }
    return rotation;
  }

  private refreshPayoutStatus(group: Group, payout: (typeof this.state.payouts)[number]) {
    const leaderApproved = group.requiresLeaderApproval ? Boolean(payout.leaderApprovedBy) : true;
    const adminRequired = payout.amount >= env.ADMIN_PAYOUT_APPROVAL_THRESHOLD;
    const adminApproved = adminRequired ? Boolean(payout.adminApprovedBy) : true;
    payout.status = leaderApproved && adminApproved ? "approved" : "requested";
  }

  private rollCycle(group: Group) {
    group.cycle += 1;
    if (group.cycle > group.totalMembers) {
      group.status = "completed";
      group.chatArchived = true;
      this.notifyGroup(
        group,
        "Group cycle completed",
        `${group.name} completed all payout cycles.`,
        "milestone",
        `group-complete-${group.id}`
      );
      return;
    }
    this.ensureCycleContributions(group);
    this.notifyGroup(
      group,
      "New cycle started",
      `${group.name} moved to cycle ${group.cycle}.`,
      "milestone",
      `group-cycle-${group.id}-${group.cycle}`
    );
  }

  private ensureCycleContributions(group: Group) {
    const dueDate = cycleDueDate(group.startDate, group.cycle);
    group.memberIds.forEach((memberId) => {
      const exists = this.state.contributions.some(
        (entry) => entry.groupId === group.id && entry.cycle === group.cycle && entry.userId === memberId
      );
      if (!exists) {
        this.state.contributions.push({
          id: uid("ctr"),
          groupId: group.id,
          cycle: group.cycle,
          userId: memberId,
          amount: group.contributionAmount,
          dueDate,
          status: "pending",
          autoDebit: false,
          createdAt: nowIso(),
        });
      }
    });
  }

  private addMember(group: Group, userId: string) {
    if (!group.memberIds.includes(userId)) {
      group.memberIds.push(userId);
    }
    if (!group.payoutOrder.includes(userId)) {
      group.payoutOrder.push(userId);
    }
    this.ensureCycleContributions(group);
    this.notify(userId, "Added to group", `You joined ${group.name}.`, "group", `group-join-${group.id}-${userId}`);
  }

  private notify(userId: string, title: string, body: string, type: string, dedupeKey?: string) {
    if (
      dedupeKey &&
      this.state.notifications.some((note) => note.userId === userId && note.dedupeKey === dedupeKey)
    ) {
      return;
    }
    this.state.notifications.push({
      id: uid("note"),
      userId,
      title,
      body,
      type,
      dedupeKey,
      read: false,
      createdAt: nowIso(),
    });
  }

  private notifyGroup(group: Group, title: string, body: string, type: string, dedupeBase: string) {
    group.memberIds.forEach((memberId) => {
      this.notify(memberId, title, body, type, `${dedupeBase}-${memberId}`);
    });
  }

  private logAudit(
    actorId: string,
    action: string,
    targetType: string,
    targetId: string,
    metadata: Record<string, unknown>
  ) {
    const previousHash = this.state.auditLogs.at(-1)?.entryHash ?? "GENESIS";
    const timestamp = nowIso();
    const hashPayload = `${previousHash}|${timestamp}|${actorId}|${action}|${targetType}|${targetId}|${JSON.stringify(metadata)}`;
    const entryHash = hashValue(hashPayload);
    this.state.auditLogs.push({
      id: uid("audit"),
      actorId,
      action,
      targetType,
      targetId,
      metadata,
      timestamp,
      previousHash,
      entryHash,
    });
  }

  private assertGroupManager(actor: User, group: Group) {
    assert(actor.role === "admin" || actor.id === group.leaderId, 403, "FORBIDDEN", "Group manager role required.");
  }

  private adminUsers() {
    return this.state.users.filter((user) => user.role === "admin");
  }

  private reconcile() {
    this.state.groups.forEach((group) => {
      group.payoutOrder = group.payoutOrder.filter((memberId) => group.memberIds.includes(memberId));
      group.memberIds.forEach((memberId) => {
        if (!group.payoutOrder.includes(memberId)) {
          group.payoutOrder.push(memberId);
        }
      });
      this.ensureCycleContributions(group);
      if (group.status === "completed") {
        group.chatArchived = true;
      }
    });
    this.state.contributions.forEach((entry) => {
      if (entry.status === "paid") {
        return;
      }
      const group = this.groupById(entry.groupId);
      if (!group || group.status !== "active") {
        return;
      }
      const graceDate = cycleGraceDate(group.startDate, entry.cycle, group.gracePeriodDays);
      if (new Date() > new Date(graceDate) && entry.status !== "late") {
        entry.status = "late";
        this.notify(
          group.leaderId,
          "Late contribution alert",
          `${this.requireUser(entry.userId).fullName} is late for ${group.name}.`,
          "compliance",
          `late-${entry.id}`
        );
      }
      const due = new Date(entry.dueDate);
      const daysToDue = Math.floor((due.getTime() - Date.now()) / 86_400_000);
      if (!entry.reminderSentAt && daysToDue <= 3 && daysToDue >= 0) {
        this.notify(
          entry.userId,
          "Contribution due reminder",
          `Your contribution is due soon in ${group.name}.`,
          "reminder",
          `auto-reminder-${entry.id}`
        );
        entry.reminderSentAt = nowIso();
      }
    });

    this.state.users.forEach((user) => {
      const paidCount = this.state.contributions.filter(
        (entry) => entry.userId === user.id && entry.status === "paid"
      ).length;
      const lateCount = this.state.contributions.filter(
        (entry) => entry.userId === user.id && entry.status === "late"
      ).length;
      const completedGroups = this.state.groups.filter(
        (group) => group.status === "completed" && group.memberIds.includes(user.id)
      ).length;
      user.metrics.paidContributions = paidCount;
      user.metrics.completedGroups = completedGroups;
      user.metrics.internalTrustScore = Math.max(
        0,
        Math.min(
          100,
          45 +
            Math.min(20, paidCount * 2) +
            (user.kyc.status === "verified" ? 15 : 0) +
            Math.min(12, completedGroups * 3) -
            Math.min(20, lateCount * 4)
        )
      );
    });
  }
}

export interface AuthUserView {
  id: string;
  fullName: string;
  email: string;
  phone: string;
  role: UserRole;
  status: "active" | "suspended";
  verifiedBadge: boolean;
  biometricEnabled: boolean;
  mfaEnabled: boolean;
  kyc: User["kyc"];
  metrics: User["metrics"];
  paymentMethods: User["paymentMethods"];
  knownDevices: User["knownDevices"];
}

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

function normalizePhone(value: string): string {
  return value.replace(/[^\d+]/g, "").trim();
}

function formatMoney(amount: number, currency: string): string {
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency,
      maximumFractionDigits: 2,
    }).format(amount);
  } catch {
    return `${currency} ${amount.toFixed(2)}`;
  }
}

function roundTwo(value: number): number {
  return Math.round((value + Number.EPSILON) * 100) / 100;
}

function escapeCsv(value: string): string {
  return value.replaceAll('"', '""');
}

function seedState(): DomainState {
  const now = new Date();
  const startDate = new Date(now.getFullYear(), now.getMonth(), 5).toISOString().slice(0, 10);
  const dueDate = new Date(now.getFullYear(), now.getMonth(), 5).toISOString();

  const adminSalt = uid("salt");
  const leaderSalt = uid("salt");
  const memberSalt = uid("salt");
  const pendingSalt = uid("salt");

  const admin: User = {
    id: "usr_admin",
    fullName: "Platform Admin",
    email: "admin@susukonnect.app",
    phone: "+15550000001",
    role: "admin",
    passwordHash: hashPassword("Admin@2026", adminSalt),
    salt: adminSalt,
    acceptedTerms: true,
    verifiedBadge: true,
    biometricEnabled: false,
    mfaEnabled: true,
    status: "active",
    knownDevices: [],
    paymentMethods: [],
    metrics: { paidContributions: 0, completedGroups: 0, internalTrustScore: 82 },
    kyc: {
      status: "verified",
      idType: "Passport",
      idNumberToken: tokenRef("admin-id"),
      dob: "1990-01-01",
      selfieToken: tokenRef("admin-selfie"),
      addressToken: tokenRef("admin-address"),
      submittedAt: nowIso(),
    },
    createdAt: nowIso(),
  };

  const leader: User = {
    id: "usr_leader",
    fullName: "Aisha Leader",
    email: "leader@susukonnect.app",
    phone: "+15550000002",
    role: "leader",
    passwordHash: hashPassword("Leader@2026", leaderSalt),
    salt: leaderSalt,
    acceptedTerms: true,
    verifiedBadge: true,
    biometricEnabled: true,
    mfaEnabled: true,
    status: "active",
    knownDevices: [],
    paymentMethods: [
      {
        id: "pm_leader_main",
        type: "bank",
        label: "Primary ACH",
        last4: "1008",
        tokenRef: "pm_1Q0000000000LeaderACH",
        autoDebit: true,
        createdAt: nowIso(),
      },
    ],
    metrics: { paidContributions: 4, completedGroups: 1, internalTrustScore: 88 },
    kyc: {
      status: "verified",
      idType: "Driver's License",
      idNumberToken: tokenRef("leader-id"),
      dob: "1993-03-20",
      selfieToken: tokenRef("leader-selfie"),
      addressToken: tokenRef("leader-address"),
      submittedAt: nowIso(),
    },
    createdAt: nowIso(),
  };

  const member: User = {
    id: "usr_member",
    fullName: "Samuel Member",
    email: "member@susukonnect.app",
    phone: "+15550000003",
    role: "member",
    passwordHash: hashPassword("Member@2026", memberSalt),
    salt: memberSalt,
    acceptedTerms: true,
    verifiedBadge: true,
    biometricEnabled: false,
    mfaEnabled: true,
    status: "active",
    knownDevices: [],
    paymentMethods: [
      {
        id: "pm_member_debit",
        type: "debit",
        label: "Family Debit",
        last4: "4455",
        tokenRef: "pm_1Q0000000000MemberDebit",
        autoDebit: false,
        createdAt: nowIso(),
      },
    ],
    metrics: { paidContributions: 3, completedGroups: 1, internalTrustScore: 79 },
    kyc: {
      status: "verified",
      idType: "Passport",
      idNumberToken: tokenRef("member-id"),
      dob: "1995-07-11",
      selfieToken: tokenRef("member-selfie"),
      addressToken: tokenRef("member-address"),
      submittedAt: nowIso(),
    },
    createdAt: nowIso(),
  };

  const pendingUser: User = {
    id: "usr_pending",
    fullName: "New Applicant",
    email: "applicant@susukonnect.app",
    phone: "+15550000004",
    role: "member",
    passwordHash: hashPassword("Member@2026", pendingSalt),
    salt: pendingSalt,
    acceptedTerms: true,
    verifiedBadge: false,
    biometricEnabled: false,
    mfaEnabled: true,
    status: "active",
    knownDevices: [],
    paymentMethods: [],
    metrics: { paidContributions: 0, completedGroups: 0, internalTrustScore: 52 },
    kyc: {
      status: "pending",
      idType: "National ID",
      idNumberToken: tokenRef("pending-id"),
      dob: "1999-10-10",
      selfieToken: tokenRef("pending-selfie"),
      addressToken: tokenRef("pending-address"),
      submittedAt: nowIso(),
    },
    createdAt: nowIso(),
  };

  const fixedGroup: Group = {
    id: "grp_fixed_001",
    inviteCode: "JOINFIXED01",
    name: "Diaspora Family Circle",
    description: "Monthly fixed-rotation savings circle.",
    communityType: "West African Diaspora",
    location: "New York",
    startDate,
    contributionAmount: 200,
    currency: "USD",
    totalMembers: 5,
    payoutFrequency: "monthly",
    payoutOrderLogic: "fixed",
    gracePeriodDays: 3,
    requiresLeaderApproval: true,
    rules: "Contributions due by the 5th each month.",
    leaderId: leader.id,
    memberIds: [leader.id, member.id],
    joinRequests: [pendingUser.id],
    payoutOrder: [leader.id, member.id],
    cycle: 1,
    status: "active",
    chatArchived: false,
    createdAt: nowIso(),
  };

  const votingGroup: Group = {
    id: "grp_vote_001",
    inviteCode: "JOINVOTE01",
    name: "Community Growth Pot",
    description: "Voting-based payout circle.",
    communityType: "Caribbean Entrepreneurs",
    location: "Toronto",
    startDate,
    contributionAmount: 150,
    currency: "USD",
    totalMembers: 4,
    payoutFrequency: "monthly",
    payoutOrderLogic: "voting",
    gracePeriodDays: 4,
    requiresLeaderApproval: false,
    rules: "One vote per member each cycle.",
    leaderId: leader.id,
    memberIds: [leader.id, member.id],
    joinRequests: [],
    payoutOrder: [leader.id, member.id],
    cycle: 1,
    status: "active",
    chatArchived: false,
    createdAt: nowIso(),
  };

  const priorityGroup: Group = {
    id: "grp_priority_001",
    inviteCode: "JOINPRIO01",
    name: "Emergency Shield Circle",
    description: "Priority-weighted payout circle.",
    communityType: "General",
    location: "London",
    startDate,
    contributionAmount: 180,
    currency: "GBP",
    totalMembers: 3,
    payoutFrequency: "monthly",
    payoutOrderLogic: "priority",
    gracePeriodDays: 2,
    requiresLeaderApproval: true,
    rules: "Priority reasons score recipient eligibility.",
    leaderId: leader.id,
    memberIds: [leader.id, member.id],
    joinRequests: [],
    payoutOrder: [member.id, leader.id],
    cycle: 1,
    status: "active",
    chatArchived: false,
    createdAt: nowIso(),
  };

  const state: DomainState = {
    users: [admin, leader, member, pendingUser],
    groups: [fixedGroup, votingGroup, priorityGroup],
    contributions: [
      {
        id: "ctr_fix_leader",
        groupId: fixedGroup.id,
        cycle: 1,
        userId: leader.id,
        amount: 200,
        dueDate,
        status: "paid",
        methodId: "pm_leader_main",
        methodType: "bank",
        autoDebit: true,
        providerReference: "seed_ref_leader_fixed",
        paidAt: nowIso(),
        createdAt: nowIso(),
      },
      {
        id: "ctr_fix_member",
        groupId: fixedGroup.id,
        cycle: 1,
        userId: member.id,
        amount: 200,
        dueDate,
        status: "pending",
        autoDebit: false,
        createdAt: nowIso(),
      },
      {
        id: "ctr_vote_leader",
        groupId: votingGroup.id,
        cycle: 1,
        userId: leader.id,
        amount: 150,
        dueDate,
        status: "paid",
        methodId: "pm_leader_main",
        methodType: "bank",
        autoDebit: true,
        providerReference: "seed_ref_leader_vote",
        paidAt: nowIso(),
        createdAt: nowIso(),
      },
      {
        id: "ctr_vote_member",
        groupId: votingGroup.id,
        cycle: 1,
        userId: member.id,
        amount: 150,
        dueDate,
        status: "paid",
        methodId: "pm_member_debit",
        methodType: "debit",
        autoDebit: false,
        providerReference: "seed_ref_member_vote",
        paidAt: nowIso(),
        createdAt: nowIso(),
      },
      {
        id: "ctr_prio_leader",
        groupId: priorityGroup.id,
        cycle: 1,
        userId: leader.id,
        amount: 180,
        dueDate,
        status: "paid",
        methodId: "pm_leader_main",
        methodType: "bank",
        autoDebit: true,
        providerReference: "seed_ref_leader_prio",
        paidAt: nowIso(),
        createdAt: nowIso(),
      },
      {
        id: "ctr_prio_member",
        groupId: priorityGroup.id,
        cycle: 1,
        userId: member.id,
        amount: 180,
        dueDate,
        status: "paid",
        methodId: "pm_member_debit",
        methodType: "debit",
        autoDebit: false,
        providerReference: "seed_ref_member_prio",
        paidAt: nowIso(),
        createdAt: nowIso(),
      },
    ],
    payouts: [
      {
        id: "pay_prio_001",
        groupId: priorityGroup.id,
        cycle: 1,
        recipientId: member.id,
        amount: 360,
        currency: "GBP",
        reason: "Medical procedure",
        status: "requested",
        requestedAt: nowIso(),
        leaderApprovedBy: leader.id,
        recipientMfaConfirmed: false,
        platformFee: 0,
        netAmount: 0,
      },
    ],
    payoutVotes: [
      {
        id: "vote_seed_001",
        groupId: votingGroup.id,
        cycle: 1,
        voterId: leader.id,
        candidateId: member.id,
        note: "Business investment priority",
        createdAt: nowIso(),
      },
    ],
    priorityClaims: [
      {
        id: "claim_seed_001",
        groupId: priorityGroup.id,
        cycle: 1,
        userId: member.id,
        reason: "Medical procedure",
        customReason: "Surgery co-pay",
        weight: PRIORITY_WEIGHTS["Medical procedure"],
        createdAt: nowIso(),
      },
    ],
    chats: [
      {
        id: "msg_seed_001",
        groupId: fixedGroup.id,
        userId: leader.id,
        content: "Welcome to the circle. Contributions are due on the 5th.",
        type: "announcement",
        pinned: true,
        createdAt: nowIso(),
      },
      {
        id: "msg_seed_002",
        groupId: fixedGroup.id,
        userId: member.id,
        content: "Thanks. I will pay before grace deadline.",
        type: "message",
        pinned: false,
        createdAt: nowIso(),
      },
    ],
    notifications: [
      {
        id: "note_seed_001",
        userId: member.id,
        title: "Contribution reminder",
        body: "Your contribution for Diaspora Family Circle is pending.",
        type: "reminder",
        dedupeKey: "seed-reminder",
        read: false,
        createdAt: nowIso(),
      },
    ],
    disputes: [],
    fraudFlags: [],
    auditLogs: [
      {
        id: uid("audit"),
        actorId: admin.id,
        action: "SEED_PLATFORM_READY",
        targetType: "system",
        targetId: "seed",
        metadata: {},
        timestamp: nowIso(),
        previousHash: "GENESIS",
        entryHash: hashValue(`GENESIS|${nowIso()}|${admin.id}|SEED_PLATFORM_READY|system|seed|{}`),
      },
    ],
    sessions: [],
    mfaChallenges: [],
    authControls: {
      loginAttempts: {},
    },
  };

  return state;
}
