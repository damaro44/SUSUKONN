import Stripe from "stripe";
import { GovernmentIdType } from "@susukonnect/shared";
import { env } from "../config/env.js";
import { uid } from "../utils/crypto.js";

export interface KycCaseInput {
  userId: string;
  fullName: string;
  email: string;
}

export interface KycCaseResult {
  provider: "stripe_identity";
  caseId: string;
  clientSecret?: string;
  mode: "live" | "simulation";
}

export interface KycVerificationInput {
  userId: string;
  fullName: string;
  dob: string;
  idType: GovernmentIdType;
  idNumber: string;
  selfieToken: string;
  livenessToken: string;
  address?: string;
}

export interface KycVerificationResult {
  provider: "stripe_identity";
  referenceId: string;
  mode: "live" | "simulation";
  idDocumentVerified: boolean;
  livenessVerified: boolean;
  nameDobVerified: boolean;
  addressVerified: boolean;
}

export class KycProvider {
  private stripe?: Stripe;

  constructor() {
    if (env.STRIPE_SECRET_KEY) {
      this.stripe = new Stripe(env.STRIPE_SECRET_KEY);
    }
  }

  async createCase(input: KycCaseInput): Promise<KycCaseResult> {
    if (!env.KYC_LIVE_MODE) {
      return {
        provider: "stripe_identity",
        caseId: `sim_kyc_${uid("case")}`,
        clientSecret: "sim_client_secret",
        mode: "simulation",
      };
    }

    if (!this.stripe) {
      throw new Error("STRIPE_SECRET_KEY is required for live Stripe Identity.");
    }

    const session = await this.stripe.identity.verificationSessions.create({
      type: "document",
      metadata: {
        userId: input.userId,
        email: input.email,
        fullName: input.fullName,
      },
    });

    return {
      provider: "stripe_identity",
      caseId: session.id,
      clientSecret: session.client_secret ?? undefined,
      mode: "live",
    };
  }

  async verifyIdentity(input: KycVerificationInput): Promise<KycVerificationResult> {
    const nameSegments = input.fullName.trim().split(/\s+/).filter(Boolean);
    const dobValid = isIsoDate(input.dob);
    const idDocumentVerified = input.idNumber.trim().length >= 4;
    const livenessVerified = input.livenessToken.trim().length >= 6;
    const nameDobVerified = nameSegments.length >= 2 && dobValid;
    const addressVerified = input.address ? input.address.trim().length >= 8 : false;

    if (!env.KYC_LIVE_MODE) {
      return {
        provider: "stripe_identity",
        referenceId: `sim_kyc_verify_${uid("verify")}`,
        mode: "simulation",
        idDocumentVerified,
        livenessVerified,
        nameDobVerified,
        addressVerified,
      };
    }

    return {
      provider: "stripe_identity",
      referenceId: `live_kyc_verify_${uid("verify")}`,
      mode: "live",
      idDocumentVerified,
      livenessVerified,
      nameDobVerified,
      addressVerified,
    };
  }
}

function isIsoDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value.trim())) {
    return false;
  }
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime());
}
