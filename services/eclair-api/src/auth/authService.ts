import jwt from "jsonwebtoken";
import { env } from "../config/env.js";
import type { Role } from "../types/domain.js";

export interface JwtUser {
  id: string;
  email: string;
  role: Role;
  fullName: string;
}

interface TokenPayload {
  sub: string;
  email: string;
  role: Role;
  fullName: string;
}

export function signAccessToken(user: JwtUser): string {
  const payload: TokenPayload = {
    sub: user.id,
    email: user.email,
    role: user.role,
    fullName: user.fullName
  };

  return jwt.sign(payload, env.ECLAIR_JWT_SECRET, {
    expiresIn: env.ECLAIR_TOKEN_TTL as jwt.SignOptions["expiresIn"],
    audience: "eclair-api",
    issuer: "eclair-tech-assistance"
  });
}

export function verifyAccessToken(token: string): JwtUser {
  const decoded = jwt.verify(token, env.ECLAIR_JWT_SECRET, {
    audience: "eclair-api",
    issuer: "eclair-tech-assistance"
  }) as TokenPayload;

  return {
    id: decoded.sub,
    email: decoded.email,
    role: decoded.role,
    fullName: decoded.fullName
  };
}
