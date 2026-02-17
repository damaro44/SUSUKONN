export const APP_NAME = "SusuKonnect";
export const TAGLINE = "Saving Together, Growing Together";

export const CURRENCIES = ["USD", "GHS", "NGN", "XOF", "EUR", "GBP", "CFA"] as const;
export type Currency = (typeof CURRENCIES)[number];

export const PAYOUT_REASONS = [
  "College tuition",
  "Wedding",
  "Rent / Housing",
  "Medical procedure",
  "Family vacation",
  "Business investment",
  "Emergency",
  "Custom reason",
] as const;
export type PayoutReason = (typeof PAYOUT_REASONS)[number];

export const ROLE_VALUES = ["member", "leader", "admin"] as const;
export type UserRole = (typeof ROLE_VALUES)[number];

export type KycStatus = "unverified" | "pending" | "verified" | "rejected";
export type GroupStatus = "active" | "suspended" | "completed";
export type ContributionStatus = "pending" | "late" | "paid";
export type PayoutStatus = "requested" | "approved" | "released" | "rejected";
export type PayoutOrderLogic = "fixed" | "voting" | "priority";
export type PaymentMethodType = "bank" | "debit" | "paypal" | "cashapp";

export interface KycProfile {
  status: KycStatus;
  idType: string;
  idNumberToken: string;
  dob: string;
  selfieToken: string;
  addressToken?: string;
  providerCaseId?: string;
  submittedAt?: string;
}

export interface DeviceRecord {
  id: string;
  label: string;
  lastSeenAt: string;
}

export interface PaymentMethod {
  id: string;
  type: PaymentMethodType;
  label: string;
  last4: string;
  tokenRef: string;
  autoDebit: boolean;
  createdAt: string;
}

export interface UserMetrics {
  paidContributions: number;
  completedGroups: number;
  internalTrustScore: number;
}

export interface User {
  id: string;
  fullName: string;
  email: string;
  phone: string;
  role: UserRole;
  passwordHash: string;
  salt: string;
  acceptedTerms: boolean;
  verifiedBadge: boolean;
  biometricEnabled: boolean;
  mfaEnabled: boolean;
  status: "active" | "suspended";
  knownDevices: DeviceRecord[];
  paymentMethods: PaymentMethod[];
  kyc: KycProfile;
  metrics: UserMetrics;
  emailVerifiedAt?: string;
  phoneVerifiedAt?: string;
  createdAt: string;
  lastLoginAt?: string;
}

export interface Group {
  id: string;
  inviteCode: string;
  name: string;
  description: string;
  communityType: string;
  location: string;
  startDate: string;
  contributionAmount: number;
  currency: Currency;
  totalMembers: number;
  payoutFrequency: "monthly";
  payoutOrderLogic: PayoutOrderLogic;
  gracePeriodDays: number;
  requiresLeaderApproval: boolean;
  rules: string;
  leaderId: string;
  memberIds: string[];
  joinRequests: string[];
  payoutOrder: string[];
  cycle: number;
  status: GroupStatus;
  chatArchived: boolean;
  createdAt: string;
}

export interface Contribution {
  id: string;
  groupId: string;
  cycle: number;
  userId: string;
  amount: number;
  dueDate: string;
  status: ContributionStatus;
  methodId?: string;
  methodType?: PaymentMethodType;
  autoDebit: boolean;
  providerReference?: string;
  paidAt?: string;
  reminderSentAt?: string;
  createdAt: string;
}

export interface PayoutVote {
  id: string;
  groupId: string;
  cycle: number;
  voterId: string;
  candidateId: string;
  note?: string;
  createdAt: string;
}

export interface PriorityClaim {
  id: string;
  groupId: string;
  cycle: number;
  userId: string;
  reason: PayoutReason;
  customReason?: string;
  weight: number;
  createdAt: string;
}

export interface Payout {
  id: string;
  groupId: string;
  cycle: number;
  recipientId: string;
  amount: number;
  currency: Currency;
  reason: PayoutReason;
  customReason?: string;
  status: PayoutStatus;
  requestedAt: string;
  reasonReviewStatus?: "pending" | "approved" | "rejected";
  reasonReviewedBy?: string;
  reasonReviewedAt?: string;
  reasonReviewNote?: string;
  leaderApprovedBy?: string;
  adminApprovedBy?: string;
  recipientMfaConfirmed: boolean;
  releasedAt?: string;
  providerReference?: string;
  platformFee: number;
  netAmount: number;
}

export interface ChatMessage {
  id: string;
  groupId: string;
  userId: string;
  content: string;
  type: "message" | "announcement";
  pinned: boolean;
  createdAt: string;
}

export interface Notification {
  id: string;
  userId: string;
  title: string;
  body: string;
  type: string;
  dedupeKey?: string;
  read: boolean;
  createdAt: string;
}

export interface Dispute {
  id: string;
  groupId: string;
  reporterId: string;
  summary: string;
  status: "open" | "resolved";
  createdAt: string;
  resolvedAt?: string;
  resolution?: string;
}

export interface FraudFlag {
  id: string;
  targetType: "user" | "group" | "transaction";
  targetId: string;
  reason: string;
  status?: "open" | "resolved";
  resolvedBy?: string;
  resolvedAt?: string;
  resolution?: string;
  createdBy: string;
  createdAt: string;
}

export interface AuditLog {
  id: string;
  actorId: string;
  action: string;
  targetType: string;
  targetId: string;
  metadata?: Record<string, unknown>;
  timestamp: string;
  previousHash: string;
  entryHash: string;
}

export interface MfaChallenge {
  id: string;
  userId: string;
  purpose: string;
  code: string;
  expiresAt: string;
}

export interface ContactVerificationChallenge {
  id: string;
  userId: string;
  channel: "email" | "phone";
  code: string;
  expiresAt: string;
}

export interface Session {
  token: string;
  userId: string;
  deviceId: string;
  createdAt: string;
  expiresAt: string;
}

export interface DomainState {
  users: User[];
  groups: Group[];
  contributions: Contribution[];
  payouts: Payout[];
  payoutVotes: PayoutVote[];
  priorityClaims: PriorityClaim[];
  chats: ChatMessage[];
  notifications: Notification[];
  disputes: Dispute[];
  fraudFlags: FraudFlag[];
  auditLogs: AuditLog[];
  sessions: Session[];
  mfaChallenges: MfaChallenge[];
  contactVerifications: ContactVerificationChallenge[];
  authControls: {
    loginAttempts: Record<string, { count: number; lockedUntil?: string }>;
  };
}

export interface AuthTokenPayload {
  sub: string;
  role: UserRole;
  sessionId: string;
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
  kyc: KycProfile;
  metrics: UserMetrics;
  paymentMethods: PaymentMethod[];
  knownDevices: DeviceRecord[];
}

export interface ApiResponse<T> {
  data: T;
  meta?: Record<string, unknown>;
}
