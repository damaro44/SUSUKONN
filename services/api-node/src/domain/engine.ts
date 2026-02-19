import {
  CURRENCIES,
  DomainState,
  GOVERNMENT_ID_TYPES,
  Group,
  MfaMethod,
  MFA_METHODS,
  Notification,
  PAYOUT_REASONS,
  PayoutReason,
  PaymentMethodType,
  GovernmentIdType,
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

const SYSTEM_USER_IDS = new Set(["usr_admin", "usr_leader", "usr_member", "usr_pending"]);

interface MfaCheckResult {
  verified: boolean;
  challengeId?: string;
  expiresAt?: string;
  demoCode?: string;
  method?: MfaMethod;
  destinationHint?: string;
}

interface RegisterInput {
  fullName: string;
  email: string;
  phone: string;
  password: string;
  role: UserRole;
  acceptTerms: boolean;
}

interface RegisterResult extends Pick<User, "id" | "email" | "role" | "fullName"> {
  contactVerification: {
    email: ContactChallengeResult;
    phone: ContactChallengeResult;
  };
}

interface ContactChallengeResult {
  channel: "email" | "phone";
  challengeId: string;
  expiresAt: string;
  demoCode?: string;
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

interface VerifyContactInput {
  challengeId: string;
  code: string;
  channel?: "email" | "phone";
}

interface EnrollBiometricInput {
  email: string;
  password: string;
  deviceId: string;
  deviceLabel?: string;
  mfaChallengeId?: string;
  mfaCode?: string;
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

interface UpdateGroupConfigInput {
  contributionAmount?: number;
  gracePeriodDays?: number;
  rules?: string;
  requiresLeaderApproval?: boolean;
  payoutOrderLogic?: "fixed" | "voting" | "priority";
  totalMembers?: number;
}

interface KycSubmitInput {
  idType: GovernmentIdType;
  idNumber: string;
  dob: string;
  selfieToken: string;
  livenessToken: string;
  address?: string;
}

interface SecurityUpdateInput {
  mfaEnabled: boolean;
  biometricEnabled: boolean;
  mfaMethod?: MfaMethod;
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

  resetStateForTests(): void {
    this.state = seedState();
    this.reconcile();
  }

  register(input: RegisterInput): RegisterResult {
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
      mfaMethod: "sms",
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
        livenessVerified: false,
        nameDobVerified: false,
        addressVerified: false,
      },
      emailVerifiedAt: undefined,
      phoneVerifiedAt: undefined,
      createdAt: nowIso(),
    };

    this.state.users.push(user);
    const emailVerification = this.createContactVerification(user.id, "email");
    const phoneVerification = this.createContactVerification(user.id, "phone");
    this.notify(
      user.id,
      "Welcome to SusuKonnect",
      "Verify your email and phone, then complete KYC before joining groups and receiving payouts.",
      "onboarding",
      `welcome-${user.id}`
    );
    this.logAudit(user.id, "REGISTER_ACCOUNT", "user", user.id, { requiresContactVerification: true });
    return {
      id: user.id,
      email: user.email,
      role: user.role,
      fullName: user.fullName,
      contactVerification: {
        email: emailVerification,
        phone: phoneVerification,
      },
    };
  }

  login(input: LoginInput): { requiresMfa: boolean; challenge?: MfaCheckResult; tokens?: AuthTokens; user?: AuthUserView } {
    const email = normalizeEmail(input.email);
    const user = this.state.users.find((candidate) => candidate.email === email);
    assert(user, 401, "INVALID_CREDENTIALS", "Invalid credentials.");
    assert(user.status === "active", 403, "USER_SUSPENDED", "User account is suspended.");
    assert(this.contactsVerified(user), 403, "CONTACT_UNVERIFIED", "Verify your email and phone before login.");

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
    assert(this.contactsVerified(user), 403, "CONTACT_UNVERIFIED", "Verify your email and phone before login.");
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

  verifyOnboardingContact(input: VerifyContactInput) {
    const challenge = this.verifyContactChallenge(input.challengeId, input.code, input.channel);
    const user = this.requireUser(challenge.userId);
    const verifiedAt = nowIso();
    if (challenge.channel === "email") {
      user.emailVerifiedAt = verifiedAt;
    } else {
      user.phoneVerifiedAt = verifiedAt;
    }
    this.logAudit(user.id, "VERIFY_CONTACT", "user", user.id, { channel: challenge.channel });
    return {
      userId: user.id,
      channel: challenge.channel,
      verifiedAt,
      contactsVerified: this.contactsVerified(user),
    };
  }

  resendContactVerification(emailRaw: string, channel: "email" | "phone"): ContactChallengeResult {
    const email = normalizeEmail(emailRaw);
    const user = this.state.users.find((candidate) => candidate.email === email);
    assert(user, 404, "NOT_FOUND", "User not found.");
    if (channel === "email" && user.emailVerifiedAt) {
      throw new HttpError(409, "ALREADY_VERIFIED", "Email is already verified.");
    }
    if (channel === "phone" && user.phoneVerifiedAt) {
      throw new HttpError(409, "ALREADY_VERIFIED", "Phone is already verified.");
    }
    const challenge = this.createContactVerification(user.id, channel);
    this.logAudit(user.id, "RESEND_CONTACT_VERIFICATION", "user", user.id, { channel });
    return challenge;
  }

  enrollBiometric(input: EnrollBiometricInput) {
    const email = normalizeEmail(input.email);
    const user = this.state.users.find((candidate) => candidate.email === email);
    assert(user, 404, "NOT_FOUND", "User not found.");
    assert(user.status === "active", 403, "USER_SUSPENDED", "User account is suspended.");
    assert(this.contactsVerified(user), 403, "CONTACT_UNVERIFIED", "Verify your email and phone before enabling biometric login.");
    const expectedHash = hashPassword(input.password, user.salt);
    assert(expectedHash === user.passwordHash, 401, "INVALID_CREDENTIALS", "Invalid credentials.");

    const mfa = this.assertMfa(user.id, "security_change", input.mfaChallengeId, input.mfaCode);
    if (!mfa.verified) {
      return { mfaRequired: true, challenge: mfa };
    }

    this.touchDevice(user.id, input.deviceId, input.deviceLabel?.trim() || "Biometric device");
    user.biometricEnabled = true;
    this.logAudit(user.id, "ENROLL_BIOMETRIC", "user", user.id, { deviceId: input.deviceId });
    return { mfaRequired: false, user: this.publicUser(user.id) };
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

  updateGroupConfig(actorId: string, groupId: string, input: UpdateGroupConfigInput): Group {
    const actor = this.requireUser(actorId);
    const group = this.requireGroup(groupId);
    this.assertGroupManager(actor, group);
    assert(group.status !== "completed", 409, "GROUP_COMPLETED", "Completed groups cannot be modified.");

    if (typeof input.totalMembers === "number") {
      assert(
        Number.isInteger(input.totalMembers) && input.totalMembers >= group.memberIds.length,
        400,
        "INVALID_GROUP_SIZE",
        "Total members must be >= current member count."
      );
      group.totalMembers = input.totalMembers;
    }
    if (typeof input.contributionAmount === "number") {
      assert(input.contributionAmount > 0, 400, "INVALID_AMOUNT", "Contribution amount must be positive.");
      group.contributionAmount = roundTwo(input.contributionAmount);
      this.state.contributions.forEach((entry) => {
        if (entry.groupId !== group.id || entry.cycle !== group.cycle || entry.status === "paid") {
          return;
        }
        entry.amount = group.contributionAmount;
      });
    }
    if (typeof input.gracePeriodDays === "number") {
      assert(
        Number.isInteger(input.gracePeriodDays) && input.gracePeriodDays >= 0,
        400,
        "INVALID_GRACE_PERIOD",
        "Grace period must be a non-negative integer."
      );
      group.gracePeriodDays = input.gracePeriodDays;
    }
    if (typeof input.rules === "string") {
      assert(input.rules.trim().length >= 3, 400, "INVALID_RULES", "Group rules are required.");
      group.rules = input.rules.trim();
    }
    if (typeof input.requiresLeaderApproval === "boolean") {
      group.requiresLeaderApproval = input.requiresLeaderApproval;
    }
    if (input.payoutOrderLogic) {
      group.payoutOrderLogic = input.payoutOrderLogic;
    }

    this.logAudit(actorId, "UPDATE_GROUP_CONFIG", "group", group.id, {
      contributionAmount: group.contributionAmount,
      gracePeriodDays: group.gracePeriodDays,
      requiresLeaderApproval: group.requiresLeaderApproval,
      payoutOrderLogic: group.payoutOrderLogic,
      totalMembers: group.totalMembers,
    });
    this.reconcile();
    return group;
  }

  updatePayoutOrder(actorId: string, groupId: string, payoutOrder: string[]): Group {
    const actor = this.requireUser(actorId);
    const group = this.requireGroup(groupId);
    this.assertGroupManager(actor, group);
    assert(group.status !== "completed", 409, "GROUP_COMPLETED", "Completed groups cannot be modified.");
    assert(payoutOrder.length === group.memberIds.length, 400, "INVALID_PAYOUT_ORDER", "Payout order must include all members.");

    const orderSet = new Set(payoutOrder);
    assert(orderSet.size === payoutOrder.length, 400, "INVALID_PAYOUT_ORDER", "Payout order cannot contain duplicates.");
    payoutOrder.forEach((memberId) => {
      assert(group.memberIds.includes(memberId), 400, "INVALID_PAYOUT_ORDER", "Payout order contains non-member.");
    });

    group.payoutOrder = [...payoutOrder];
    this.logAudit(actorId, "UPDATE_PAYOUT_ORDER", "group", group.id, { payoutOrder: [...group.payoutOrder] });
    this.reconcile();
    return group;
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
      reasonReviewStatus: "pending" as const,
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

  reviewPayoutReason(
    actorId: string,
    payoutId: string,
    payload: {
      decision: "approve" | "reject";
      reason?: PayoutReason;
      customReason?: string;
      note?: string;
    }
  ) {
    const actor = this.requireUser(actorId);
    const payout = this.requirePayout(payoutId);
    const group = this.requireGroup(payout.groupId);
    assert(
      actor.role === "admin" || group.leaderId === actorId,
      403,
      "FORBIDDEN",
      "Only admin or group leader can review payout reasons."
    );
    assert(payout.status !== "released", 409, "PAYOUT_RELEASED", "Released payouts cannot be modified.");

    if (payload.reason) {
      assert(PAYOUT_REASONS.includes(payload.reason), 400, "INVALID_REASON", "Unsupported reason.");
      payout.reason = payload.reason;
      if (payload.reason !== "Custom reason") {
        payout.customReason = undefined;
      }
    }
    if (payload.reason === "Custom reason" || payout.reason === "Custom reason") {
      assert(
        Boolean((payload.customReason ?? payout.customReason ?? "").trim()),
        400,
        "CUSTOM_REASON_REQUIRED",
        "Custom reason details are required."
      );
    }
    if (typeof payload.customReason === "string") {
      payout.customReason = payload.customReason.trim();
    }

    if (payload.decision === "reject") {
      payout.reasonReviewStatus = "rejected";
      payout.reasonReviewedBy = actorId;
      payout.reasonReviewedAt = nowIso();
      payout.reasonReviewNote = payload.note?.trim();
      payout.status = "rejected";
      this.notify(
        payout.recipientId,
        "Payout reason rejected",
        `Your payout reason for ${group.name} was rejected. ${payload.note?.trim() ?? ""}`.trim(),
        "payout",
        `payout-reason-rejected-${payout.id}`
      );
      this.logAudit(actorId, "REJECT_PAYOUT_REASON", "payout", payout.id, {
        note: payload.note?.trim(),
        reason: payout.reason,
      });
      return payout;
    }

    payout.reasonReviewStatus = "approved";
    payout.reasonReviewedBy = actorId;
    payout.reasonReviewedAt = nowIso();
    payout.reasonReviewNote = payload.note?.trim();
    this.refreshPayoutStatus(group, payout);
    this.notify(
      payout.recipientId,
      "Payout reason approved",
      `Your payout reason for ${group.name} was approved.`,
      "payout",
      `payout-reason-approved-${payout.id}`
    );
    this.logAudit(actorId, "APPROVE_PAYOUT_REASON", "payout", payout.id, {
      note: payload.note?.trim(),
      reason: payout.reason,
    });
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
    assert(payout.status !== "rejected", 409, "PAYOUT_REJECTED", "Rejected payouts cannot be approved.");
    assert(
      (payout.reasonReviewStatus ?? "approved") === "approved",
      409,
      "PAYOUT_REASON_PENDING",
      "Payout reason approval is pending."
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

  moderateGroupChat(actorId: string, groupId: string, chatArchived: boolean): Group {
    const actor = this.requireUser(actorId);
    const group = this.requireGroup(groupId);
    this.assertGroupManager(actor, group);
    assert(
      !(group.status === "completed" && chatArchived === false),
      409,
      "GROUP_COMPLETED",
      "Completed groups cannot be unarchived."
    );
    group.chatArchived = chatArchived;
    this.logAudit(actorId, chatArchived ? "ARCHIVE_GROUP_CHAT" : "UNARCHIVE_GROUP_CHAT", "group", group.id, {});
    this.notifyGroup(
      group,
      chatArchived ? "Group chat archived" : "Group chat reopened",
      chatArchived
        ? `Chat in ${group.name} has been archived by moderators.`
        : `Chat in ${group.name} has been reopened by moderators.`,
      "chat",
      `chat-moderation-${group.id}-${chatArchived ? "archived" : "active"}-${Date.now()}`
    );
    return group;
  }

  deleteChatMessage(actorId: string, messageId: string): { deleted: true; messageId: string } {
    const actor = this.requireUser(actorId);
    const message = this.state.chats.find((item) => item.id === messageId);
    assert(message, 404, "NOT_FOUND", "Message not found.");
    const group = this.requireGroup(message.groupId);
    this.assertGroupManager(actor, group);
    this.state.chats = this.state.chats.filter((item) => item.id !== messageId);
    this.logAudit(actorId, "DELETE_CHAT_MESSAGE", "chat", messageId, { groupId: group.id, originalUserId: message.userId });
    return { deleted: true, messageId };
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
    assert(
      input.idType && input.idNumber && input.selfieToken && input.livenessToken && input.dob,
      400,
      "INVALID_INPUT",
      "Missing KYC data."
    );
    assert(
      GOVERNMENT_ID_TYPES.includes(input.idType),
      400,
      "INVALID_ID_TYPE",
      "Government-issued ID must be passport, national_id, or drivers_license."
    );
    assert(isIsoDate(input.dob), 400, "INVALID_DOB", "Date of birth must be in YYYY-MM-DD format.");

    const kycCase = await this.kycProvider.createCase({
      userId,
      fullName: user.fullName,
      email: user.email,
    });
    const verification = await this.kycProvider.verifyIdentity({
      userId,
      fullName: user.fullName,
      dob: input.dob,
      idType: input.idType,
      idNumber: input.idNumber,
      selfieToken: input.selfieToken,
      livenessToken: input.livenessToken,
      address: input.address,
    });
    assert(verification.idDocumentVerified, 422, "KYC_ID_REJECTED", "Government ID verification failed.");
    assert(verification.livenessVerified, 422, "KYC_LIVENESS_FAILED", "Live selfie verification failed.");
    assert(verification.nameDobVerified, 422, "KYC_NAME_DOB_MISMATCH", "Name and DOB cross-verification failed.");

    user.kyc = {
      status: "pending",
      idType: input.idType,
      idNumberToken: tokenRef(`id:${input.idNumber}`),
      dob: input.dob,
      selfieToken: tokenRef(`selfie:${input.selfieToken}`),
      livenessToken: tokenRef(`liveness:${input.livenessToken}`),
      livenessVerified: verification.livenessVerified,
      nameDobVerified: verification.nameDobVerified,
      addressToken: input.address ? tokenRef(`address:${input.address}`) : undefined,
      addressVerified: verification.addressVerified,
      providerCaseId: kycCase.caseId,
      submittedAt: nowIso(),
    };

    if (!input.address) {
      this.notify(
        user.id,
        "Address verification recommended",
        "Address verification is optional, but recommended before payout release.",
        "compliance",
        `kyc-address-recommendation-${user.id}`
      );
    }

    this.adminUsers().forEach((admin) => {
      this.notify(
        admin.id,
        "KYC review required",
        `${user.fullName} submitted KYC documents.`,
        "compliance",
        `kyc-review-${user.id}-${admin.id}`
      );
    });
    this.logAudit(userId, "SUBMIT_KYC", "user", userId, {
      providerCaseId: kycCase.caseId,
      verificationReference: verification.referenceId,
      idDocumentVerified: verification.idDocumentVerified,
      livenessVerified: verification.livenessVerified,
      nameDobVerified: verification.nameDobVerified,
      addressVerified: verification.addressVerified,
    });
    return {
      status: user.kyc.status,
      providerCaseId: kycCase.caseId,
      providerClientSecret: kycCase.clientSecret,
      mode: kycCase.mode,
      checks: {
        idDocumentVerified: verification.idDocumentVerified,
        livenessVerified: verification.livenessVerified,
        nameDobVerified: verification.nameDobVerified,
        addressVerified: verification.addressVerified,
      },
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
    const mfaMethod = input.mfaMethod ?? user.mfaMethod;
    assert(MFA_METHODS.includes(mfaMethod), 400, "INVALID_MFA_METHOD", "MFA method must be sms or authenticator.");
    user.mfaEnabled = Boolean(input.mfaEnabled);
    user.biometricEnabled = Boolean(input.biometricEnabled);
    user.mfaMethod = mfaMethod;
    this.logAudit(userId, "UPDATE_SECURITY_SETTINGS", "user", userId, {
      mfaEnabled: input.mfaEnabled,
      biometricEnabled: input.biometricEnabled,
      mfaMethod,
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

  purgeSignupAccounts(adminId: string) {
    const admin = this.requireUser(adminId);
    assert(admin.role === "admin", 403, "FORBIDDEN", "Admin role required.");

    const deletedUsers = this.state.users.filter((user) => !SYSTEM_USER_IDS.has(user.id));
    const deletedUserIds = deletedUsers.map((user) => user.id);
    const deletedEmails = deletedUsers.map((user) => user.email);
    if (deletedUserIds.length === 0) {
      this.logAudit(adminId, "PURGE_SIGNUP_ACCOUNTS", "system", "signup_accounts", {
        deletedCount: 0,
      });
      return {
        deletedCount: 0,
        deletedUserIds: [] as string[],
        deletedGroupIds: [] as string[],
      };
    }

    const deletedGroupIds = this.removeUsersCascade(deletedUserIds);
    deletedEmails.forEach((email) => {
      delete this.state.authControls.loginAttempts[email];
    });

    this.logAudit(adminId, "PURGE_SIGNUP_ACCOUNTS", "system", "signup_accounts", {
      deletedCount: deletedUserIds.length,
      deletedUserIds,
      deletedGroupIds,
    });
    this.reconcile();
    return {
      deletedCount: deletedUserIds.length,
      deletedUserIds,
      deletedGroupIds,
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
      status: "open" as const,
      createdBy: adminId,
      createdAt: nowIso(),
    };
    this.state.fraudFlags.push(flag);
    this.logAudit(adminId, "CREATE_FRAUD_FLAG", "flag", flag.id, input);
    return flag;
  }

  listFraudFlags(adminId: string, filters: { targetType?: string; status?: string; query?: string }) {
    const admin = this.requireUser(adminId);
    assert(admin.role === "admin", 403, "FORBIDDEN", "Admin role required.");
    const targetType = (filters.targetType ?? "").toLowerCase();
    const status = (filters.status ?? "").toLowerCase();
    const query = (filters.query ?? "").toLowerCase();

    return this.state.fraudFlags
      .filter((flag) => {
        if (targetType && flag.targetType.toLowerCase() !== targetType) {
          return false;
        }
        if (status && (flag.status ?? "open").toLowerCase() !== status) {
          return false;
        }
        if (query) {
          const haystack = `${flag.targetId} ${flag.reason}`.toLowerCase();
          if (!haystack.includes(query)) {
            return false;
          }
        }
        return true;
      })
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  resolveFraudFlag(adminId: string, flagId: string, resolution: string) {
    const admin = this.requireUser(adminId);
    assert(admin.role === "admin", 403, "FORBIDDEN", "Admin role required.");
    const flag = this.state.fraudFlags.find((entry) => entry.id === flagId);
    assert(flag, 404, "NOT_FOUND", "Fraud flag not found.");
    assert((flag.status ?? "open") === "open", 409, "FLAG_ALREADY_RESOLVED", "Fraud flag already resolved.");
    assert(resolution.trim().length >= 3, 400, "INVALID_RESOLUTION", "Resolution details are required.");
    flag.status = "resolved";
    flag.resolvedBy = adminId;
    flag.resolvedAt = nowIso();
    flag.resolution = resolution.trim();
    this.logAudit(adminId, "RESOLVE_FRAUD_FLAG", "flag", flag.id, { resolution: flag.resolution });
    return flag;
  }

  complianceQueue(adminId: string) {
    const admin = this.requireUser(adminId);
    assert(admin.role === "admin", 403, "FORBIDDEN", "Admin role required.");
    return {
      pendingKyc: this.state.users.filter((candidate) => candidate.kyc.status === "pending"),
      openFraudFlags: this.state.fraudFlags.filter((flag) => (flag.status ?? "open") === "open"),
      suspendedGroups: this.state.groups.filter((group) => group.status === "suspended"),
      openDisputes: this.state.disputes.filter((dispute) => dispute.status === "open"),
    };
  }

  listAuditLogs(
    adminId: string,
    filters: {
      actorId?: string;
      action?: string;
      targetType?: string;
      from?: string;
      to?: string;
      limit?: number;
    }
  ) {
    const admin = this.requireUser(adminId);
    assert(admin.role === "admin", 403, "FORBIDDEN", "Admin role required.");
    const parsedLimit = Number(filters.limit ?? 100);
    const limit = Math.max(1, Math.min(500, Number.isFinite(parsedLimit) ? parsedLimit : 100));
    const from = filters.from ? new Date(filters.from).getTime() : null;
    const to = filters.to ? new Date(filters.to).getTime() : null;

    return this.state.auditLogs
      .filter((entry) => {
        if (filters.actorId && entry.actorId !== filters.actorId) {
          return false;
        }
        if (filters.action && entry.action !== filters.action) {
          return false;
        }
        if (filters.targetType && entry.targetType !== filters.targetType) {
          return false;
        }
        const ts = new Date(entry.timestamp).getTime();
        if (from !== null && ts < from) {
          return false;
        }
        if (to !== null && ts > to) {
          return false;
        }
        return true;
      })
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
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
    const user = this.requireUser(userId);
    const method = user.mfaMethod ?? "sms";
    const challenge = {
      id: uid("mfa"),
      userId,
      purpose,
      method,
      code: generateMfaCode(),
      expiresAt: addMinutes(new Date(), env.MFA_TTL_MINUTES),
    };
    this.state.mfaChallenges.push(challenge);
    return {
      verified: false,
      challengeId: challenge.id,
      expiresAt: challenge.expiresAt,
      demoCode: env.EXPOSE_MFA_CODES ? challenge.code : undefined,
      method,
      destinationHint: method === "authenticator" ? "Authenticator app code" : "SMS code sent to phone",
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

  private createContactVerification(userId: string, channel: "email" | "phone"): ContactChallengeResult {
    const challenge = {
      id: uid("verify"),
      userId,
      channel,
      code: generateMfaCode(),
      expiresAt: addMinutes(new Date(), env.MFA_TTL_MINUTES),
    };
    this.state.contactVerifications.push(challenge);
    return {
      channel,
      challengeId: challenge.id,
      expiresAt: challenge.expiresAt,
      demoCode: env.EXPOSE_MFA_CODES ? challenge.code : undefined,
    };
  }

  private verifyContactChallenge(challengeId: string, code: string, expectedChannel?: "email" | "phone") {
    const challenge = this.state.contactVerifications.find((entry) => entry.id === challengeId);
    assert(challenge, 401, "INVALID_VERIFICATION_CHALLENGE", "Contact verification challenge not found.");
    if (expectedChannel) {
      assert(challenge.channel === expectedChannel, 401, "INVALID_VERIFICATION_CHANNEL", "Verification channel mismatch.");
    }
    assert(new Date(challenge.expiresAt) > new Date(), 401, "VERIFICATION_EXPIRED", "Verification challenge expired.");
    assert(challenge.code === code, 401, "INVALID_VERIFICATION_CODE", "Invalid verification code.");
    this.state.contactVerifications = this.state.contactVerifications.filter((entry) => entry.id !== challengeId);
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
      emailVerifiedAt: user.emailVerifiedAt,
      phoneVerifiedAt: user.phoneVerifiedAt,
      contactsVerified: this.contactsVerified(user),
      role: user.role,
      status: user.status,
      verifiedBadge: user.verifiedBadge,
      biometricEnabled: user.biometricEnabled,
      mfaEnabled: user.mfaEnabled,
      mfaMethod: user.mfaMethod,
      kyc: user.kyc,
      metrics: user.metrics,
      paymentMethods: user.paymentMethods,
      knownDevices: user.knownDevices,
    };
  }

  private contactsVerified(user: User): boolean {
    return Boolean(user.emailVerifiedAt && user.phoneVerifiedAt);
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
    if (payout.reasonReviewStatus === "rejected") {
      payout.status = "rejected";
      return;
    }
    const reasonApproved = (payout.reasonReviewStatus ?? "approved") === "approved";
    const leaderApproved = group.requiresLeaderApproval ? Boolean(payout.leaderApprovedBy) : true;
    const adminRequired = payout.amount >= env.ADMIN_PAYOUT_APPROVAL_THRESHOLD;
    const adminApproved = adminRequired ? Boolean(payout.adminApprovedBy) : true;
    payout.status = reasonApproved && leaderApproved && adminApproved ? "approved" : "requested";
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

  private removeUsersCascade(userIds: string[]): string[] {
    const userSet = new Set(userIds);

    this.state.users = this.state.users.filter((user) => !userSet.has(user.id));
    this.state.sessions = this.state.sessions.filter((session) => !userSet.has(session.userId));
    this.state.mfaChallenges = this.state.mfaChallenges.filter((challenge) => !userSet.has(challenge.userId));
    this.state.contactVerifications = this.state.contactVerifications.filter(
      (challenge) => !userSet.has(challenge.userId)
    );
    this.state.notifications = this.state.notifications.filter((note) => !userSet.has(note.userId));
    this.state.fraudFlags = this.state.fraudFlags.filter(
      (flag) => !(flag.targetType === "user" && userSet.has(flag.targetId))
    );

    const deletedGroupIds = new Set<string>();
    this.state.groups.forEach((group) => {
      group.joinRequests = group.joinRequests.filter((userId) => !userSet.has(userId));
      group.memberIds = group.memberIds.filter((userId) => !userSet.has(userId));
      group.payoutOrder = group.payoutOrder.filter((userId) => !userSet.has(userId));
      if (userSet.has(group.leaderId) || group.memberIds.length === 0) {
        deletedGroupIds.add(group.id);
      }
    });
    this.state.groups = this.state.groups.filter((group) => !deletedGroupIds.has(group.id));

    this.state.contributions = this.state.contributions.filter(
      (entry) => !userSet.has(entry.userId) && !deletedGroupIds.has(entry.groupId)
    );
    this.state.payoutVotes = this.state.payoutVotes.filter(
      (entry) =>
        !deletedGroupIds.has(entry.groupId) && !userSet.has(entry.voterId) && !userSet.has(entry.candidateId)
    );
    this.state.priorityClaims = this.state.priorityClaims.filter(
      (entry) => !deletedGroupIds.has(entry.groupId) && !userSet.has(entry.userId)
    );
    this.state.payouts = this.state.payouts.filter((entry) => {
      if (deletedGroupIds.has(entry.groupId) || userSet.has(entry.recipientId)) {
        return false;
      }
      if (entry.leaderApprovedBy && userSet.has(entry.leaderApprovedBy)) {
        return false;
      }
      if (entry.adminApprovedBy && userSet.has(entry.adminApprovedBy)) {
        return false;
      }
      if (entry.reasonReviewedBy && userSet.has(entry.reasonReviewedBy)) {
        return false;
      }
      return true;
    });
    this.state.chats = this.state.chats.filter(
      (entry) => !deletedGroupIds.has(entry.groupId) && !userSet.has(entry.userId)
    );
    this.state.disputes = this.state.disputes.filter(
      (entry) => !deletedGroupIds.has(entry.groupId) && !userSet.has(entry.reporterId)
    );

    return [...deletedGroupIds];
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
  emailVerifiedAt?: string;
  phoneVerifiedAt?: string;
  contactsVerified: boolean;
  role: UserRole;
  status: "active" | "suspended";
  verifiedBadge: boolean;
  biometricEnabled: boolean;
  mfaEnabled: boolean;
  mfaMethod: MfaMethod;
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

function isIsoDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value.trim())) {
    return false;
  }
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime());
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
    mfaMethod: "sms",
    status: "active",
    knownDevices: [],
    paymentMethods: [],
    metrics: { paidContributions: 0, completedGroups: 0, internalTrustScore: 82 },
    kyc: {
      status: "verified",
      idType: "passport",
      idNumberToken: tokenRef("admin-id"),
      dob: "1990-01-01",
      selfieToken: tokenRef("admin-selfie"),
      livenessToken: tokenRef("admin-liveness"),
      livenessVerified: true,
      nameDobVerified: true,
      addressToken: tokenRef("admin-address"),
      addressVerified: true,
      submittedAt: nowIso(),
    },
    emailVerifiedAt: nowIso(),
    phoneVerifiedAt: nowIso(),
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
    mfaMethod: "authenticator",
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
      idType: "drivers_license",
      idNumberToken: tokenRef("leader-id"),
      dob: "1993-03-20",
      selfieToken: tokenRef("leader-selfie"),
      livenessToken: tokenRef("leader-liveness"),
      livenessVerified: true,
      nameDobVerified: true,
      addressToken: tokenRef("leader-address"),
      addressVerified: true,
      submittedAt: nowIso(),
    },
    emailVerifiedAt: nowIso(),
    phoneVerifiedAt: nowIso(),
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
    mfaMethod: "sms",
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
      idType: "passport",
      idNumberToken: tokenRef("member-id"),
      dob: "1995-07-11",
      selfieToken: tokenRef("member-selfie"),
      livenessToken: tokenRef("member-liveness"),
      livenessVerified: true,
      nameDobVerified: true,
      addressToken: tokenRef("member-address"),
      addressVerified: true,
      submittedAt: nowIso(),
    },
    emailVerifiedAt: nowIso(),
    phoneVerifiedAt: nowIso(),
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
    mfaMethod: "sms",
    status: "active",
    knownDevices: [],
    paymentMethods: [],
    metrics: { paidContributions: 0, completedGroups: 0, internalTrustScore: 52 },
    kyc: {
      status: "pending",
      idType: "national_id",
      idNumberToken: tokenRef("pending-id"),
      dob: "1999-10-10",
      selfieToken: tokenRef("pending-selfie"),
      livenessToken: tokenRef("pending-liveness"),
      livenessVerified: true,
      nameDobVerified: true,
      addressToken: tokenRef("pending-address"),
      addressVerified: true,
      submittedAt: nowIso(),
    },
    emailVerifiedAt: nowIso(),
    phoneVerifiedAt: nowIso(),
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
        reasonReviewStatus: "approved",
        reasonReviewedBy: leader.id,
        reasonReviewedAt: nowIso(),
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
    contactVerifications: [],
    authControls: {
      loginAttempts: {},
    },
  };

  return state;
}
