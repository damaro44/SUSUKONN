import type { NextFunction, Request, Response } from "express";

export function notFoundHandler(_request: Request, response: Response) {
  response.status(404).json({
    error: {
      code: "NOT_FOUND",
      message: "Endpoint not found"
    }
  });
}

export function errorHandler(
  error: unknown,
  _request: Request,
  response: Response,
  _next: NextFunction
): void {
  const message = error instanceof Error ? error.message : "Unexpected server error";

  response.status(400).json({
    error: {
      code: "BAD_REQUEST",
      message
    }
  });
}
