import type { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../auth/authService.js";
import type { Role } from "../types/domain.js";

export function requireAuth(request: Request, response: Response, next: NextFunction): void {
  const header = request.headers.authorization;
  const token = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";

  if (!token) {
    response.status(401).json({
      error: {
        code: "UNAUTHORIZED",
        message: "Missing Bearer token"
      }
    });
    return;
  }

  try {
    request.authUser = verifyAccessToken(token);
    next();
  } catch {
    response.status(401).json({
      error: {
        code: "UNAUTHORIZED",
        message: "Invalid or expired access token"
      }
    });
  }
}

export function requireRole(roles: Role[]) {
  return (request: Request, response: Response, next: NextFunction): void => {
    const role = request.authUser?.role;
    if (!role || !roles.includes(role)) {
      response.status(403).json({
        error: {
          code: "FORBIDDEN",
          message: "Role-based access denied"
        }
      });
      return;
    }

    next();
  };
}
