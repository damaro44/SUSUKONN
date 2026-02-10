import crypto from "node:crypto";

export function uid(prefix: string): string {
  return `${prefix}_${crypto.randomBytes(6).toString("hex")}_${Date.now().toString(36)}`;
}

export function hashValue(value: string): string {
  const hash = crypto.createHash("sha256");
  hash.update(value);
  return hash.digest("hex");
}

export function hashPassword(password: string, salt: string): string {
  return hashValue(`${salt}:${password}`);
}

export function tokenRef(value: string): string {
  return `tok_${hashValue(value).slice(0, 28)}`;
}

export function generateMfaCode(): string {
  return `${Math.floor(100000 + Math.random() * 900000)}`;
}
