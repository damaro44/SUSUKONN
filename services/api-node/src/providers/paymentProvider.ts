import axios from "axios";
import Stripe from "stripe";
import { env } from "../config/env.js";
import { uid } from "../utils/crypto.js";

export type PaymentChannel = "stripe" | "paypal";

export interface ChargeContributionInput {
  amount: number;
  currency: string;
  paymentMethodType: "bank" | "debit" | "paypal" | "cashapp";
  paymentTokenRef: string;
  metadata?: Record<string, string>;
}

export interface ReleasePayoutInput {
  amount: number;
  currency: string;
  payoutChannel: PaymentChannel;
  destinationTokenRef: string;
  recipientEmail: string;
  metadata?: Record<string, string>;
}

export interface ProviderResult {
  ok: boolean;
  provider: PaymentChannel;
  reference: string;
  raw?: unknown;
}

interface PayPalAccessToken {
  access_token: string;
}

export class PaymentProvider {
  private stripe?: Stripe;
  private paypalTokenCache?: { token: string; expiresAt: number };

  constructor() {
    if (env.STRIPE_SECRET_KEY) {
      this.stripe = new Stripe(env.STRIPE_SECRET_KEY);
    }
  }

  async chargeContribution(input: ChargeContributionInput): Promise<ProviderResult> {
    if (input.paymentMethodType === "paypal") {
      return this.chargeWithPayPal(input);
    }
    return this.chargeWithStripe(input);
  }

  async releasePayout(input: ReleasePayoutInput): Promise<ProviderResult> {
    if (input.payoutChannel === "paypal") {
      return this.releasePayPalPayout(input);
    }
    return this.releaseStripePayout(input);
  }

  private async chargeWithStripe(input: ChargeContributionInput): Promise<ProviderResult> {
    if (!env.PAYMENTS_LIVE_MODE) {
      return {
        ok: true,
        provider: "stripe",
        reference: `sim_stripe_charge_${uid("charge")}`,
        raw: { mode: "simulation" },
      };
    }

    if (!this.stripe) {
      throw new Error("STRIPE_SECRET_KEY is required for live Stripe payments.");
    }

    const currency = normalizeCurrency(input.currency);
    const intent = await this.stripe.paymentIntents.create({
      amount: Math.round(input.amount * 100),
      currency,
      payment_method: input.paymentTokenRef,
      confirm: true,
      automatic_payment_methods: { enabled: false },
      metadata: input.metadata,
      description: "SusuKonnect contribution charge",
    });

    return {
      ok: intent.status === "succeeded",
      provider: "stripe",
      reference: intent.id,
      raw: intent,
    };
  }

  private async releaseStripePayout(input: ReleasePayoutInput): Promise<ProviderResult> {
    if (!env.PAYMENTS_LIVE_MODE) {
      return {
        ok: true,
        provider: "stripe",
        reference: `sim_stripe_payout_${uid("payout")}`,
        raw: { mode: "simulation" },
      };
    }

    if (!this.stripe) {
      throw new Error("STRIPE_SECRET_KEY is required for live Stripe payouts.");
    }

    // In production this should use connected-account destination IDs (acct_*) or treasury setup.
    const canTransferToConnectedAccount = input.destinationTokenRef.startsWith("acct_");
    if (!canTransferToConnectedAccount) {
      return {
        ok: true,
        provider: "stripe",
        reference: `manual_stripe_settlement_${uid("settle")}`,
        raw: {
          note: "Destination token is not a connected account. Manual settlement fallback used.",
        },
      };
    }

    const transfer = await this.stripe.transfers.create({
      amount: Math.round(input.amount * 100),
      currency: normalizeCurrency(input.currency),
      destination: input.destinationTokenRef,
      metadata: input.metadata,
      description: "SusuKonnect payout release",
    });

    return {
      ok: true,
      provider: "stripe",
      reference: transfer.id,
      raw: transfer,
    };
  }

  private async chargeWithPayPal(input: ChargeContributionInput): Promise<ProviderResult> {
    if (!env.PAYMENTS_LIVE_MODE) {
      return {
        ok: true,
        provider: "paypal",
        reference: `sim_paypal_charge_${uid("charge")}`,
        raw: { mode: "simulation" },
      };
    }

    const accessToken = await this.getPayPalAccessToken();
    const orderPayload = {
      intent: "CAPTURE",
      purchase_units: [
        {
          amount: {
            currency_code: normalizeCurrency(input.currency).toUpperCase(),
            value: input.amount.toFixed(2),
          },
        },
      ],
    };

    const createResponse = await axios.post(
      `${env.PAYPAL_BASE_URL}/v2/checkout/orders`,
      orderPayload,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );

    const orderId = createResponse.data.id as string;
    const captureResponse = await axios.post(
      `${env.PAYPAL_BASE_URL}/v2/checkout/orders/${orderId}/capture`,
      {},
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );

    return {
      ok: captureResponse.data.status === "COMPLETED",
      provider: "paypal",
      reference: orderId,
      raw: captureResponse.data,
    };
  }

  private async releasePayPalPayout(input: ReleasePayoutInput): Promise<ProviderResult> {
    if (!env.PAYMENTS_LIVE_MODE) {
      return {
        ok: true,
        provider: "paypal",
        reference: `sim_paypal_payout_${uid("payout")}`,
        raw: { mode: "simulation" },
      };
    }

    const accessToken = await this.getPayPalAccessToken();
    const payload = {
      sender_batch_header: {
        sender_batch_id: uid("batch"),
        email_subject: "You have a payout from SusuKonnect",
      },
      items: [
        {
          recipient_type: "EMAIL",
          amount: {
            value: input.amount.toFixed(2),
            currency: normalizeCurrency(input.currency).toUpperCase(),
          },
          receiver: input.recipientEmail,
          note: "SusuKonnect payout release",
          sender_item_id: uid("item"),
        },
      ],
    };

    const response = await axios.post(
      `${env.PAYPAL_BASE_URL}/v1/payments/payouts`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );

    return {
      ok: true,
      provider: "paypal",
      reference: response.data.batch_header?.payout_batch_id ?? uid("paypal_batch"),
      raw: response.data,
    };
  }

  private async getPayPalAccessToken(): Promise<string> {
    const now = Date.now();
    if (this.paypalTokenCache && this.paypalTokenCache.expiresAt > now + 30_000) {
      return this.paypalTokenCache.token;
    }

    if (!env.PAYPAL_CLIENT_ID || !env.PAYPAL_CLIENT_SECRET) {
      throw new Error("PayPal credentials are required for live mode.");
    }

    const credentials = Buffer.from(
      `${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_CLIENT_SECRET}`
    ).toString("base64");

    const response = await axios.post<PayPalAccessToken>(
      `${env.PAYPAL_BASE_URL}/v1/oauth2/token`,
      "grant_type=client_credentials",
      {
        headers: {
          Authorization: `Basic ${credentials}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    this.paypalTokenCache = {
      token: response.data.access_token,
      expiresAt: now + 8 * 60 * 1000,
    };

    return response.data.access_token;
  }
}

function normalizeCurrency(value: string): string {
  const candidate = value.trim().toLowerCase();
  if (candidate === "xof" || candidate === "cfa") {
    return "eur";
  }
  if (candidate.length !== 3) {
    return "usd";
  }
  return candidate;
}
