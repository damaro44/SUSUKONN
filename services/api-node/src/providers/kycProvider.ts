import Stripe from "stripe";
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
}
