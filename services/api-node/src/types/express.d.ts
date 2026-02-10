import type { AuthUserView } from "../domain/engine.js";

declare global {
  namespace Express {
    interface Request {
      authUser?: AuthUserView;
      accessToken?: string;
    }
  }
}

export {};
