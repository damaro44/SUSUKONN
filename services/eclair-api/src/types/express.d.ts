import type { JwtUser } from "../auth/authService.js";

declare global {
  namespace Express {
    interface Request {
      authUser?: JwtUser;
    }
  }
}

export {};
