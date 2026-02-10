import { config as loadEnv } from "dotenv";
import { z } from "zod";

loadEnv();

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_PORT: z.coerce.number().default(4000),
  JWT_SECRET: z.string().min(16).default("change-this-in-production-please"),
  TOKEN_TTL_MINUTES: z.coerce.number().default(60),
  SESSION_TTL_HOURS: z.coerce.number().default(24),
  MFA_TTL_MINUTES: z.coerce.number().default(10),
  EXPOSE_MFA_CODES: z
    .string()
    .optional()
    .transform((value) => value === "true"),
  PAYMENTS_LIVE_MODE: z
    .string()
    .optional()
    .transform((value) => value === "true"),
  KYC_LIVE_MODE: z
    .string()
    .optional()
    .transform((value) => value === "true"),
  PLATFORM_FEE_RATE: z.coerce.number().default(0.015),
  ADMIN_PAYOUT_APPROVAL_THRESHOLD: z.coerce.number().default(2000),
  STRIPE_SECRET_KEY: z.string().optional(),
  STRIPE_WEBHOOK_SECRET: z.string().optional(),
  PAYPAL_CLIENT_ID: z.string().optional(),
  PAYPAL_CLIENT_SECRET: z.string().optional(),
  PAYPAL_BASE_URL: z.string().default("https://api-m.sandbox.paypal.com"),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  throw new Error(`Invalid env configuration: ${parsed.error.message}`);
}

export const env = parsed.data;
