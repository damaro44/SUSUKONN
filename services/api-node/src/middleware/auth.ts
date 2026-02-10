import { NextFunction, Request, Response } from "express";
import { engine } from "../domain/index.js";

export function requireAuth(request: Request, response: Response, next: NextFunction): void {
  try {
    const header = request.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
    if (!token) {
      response.status(401).json({
        error: {
          code: "UNAUTHORIZED",
          message: "Missing Bearer token.",
        },
      });
      return;
    }
    const user = engine.authenticate(token);
    request.authUser = user;
    request.accessToken = token;
    next();
  } catch (error) {
    next(error);
  }
}

export function requireRole(roles: Array<"member" | "leader" | "admin">) {
  return (request: Request, response: Response, next: NextFunction): void => {
    const user = request.authUser;
    if (!user || !roles.includes(user.role)) {
      response.status(403).json({
        error: {
          code: "FORBIDDEN",
          message: "Role-based access denied.",
        },
      });
      return;
    }
    next();
  };
}
