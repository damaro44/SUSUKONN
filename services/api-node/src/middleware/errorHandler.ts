import { NextFunction, Request, Response } from "express";
import { HttpError } from "../utils/errors.js";

export function notFoundHandler(_request: Request, response: Response): void {
  response.status(404).json({
    error: {
      code: "NOT_FOUND",
      message: "Route not found.",
    },
  });
}

export function errorHandler(
  error: unknown,
  _request: Request,
  response: Response,
  _next: NextFunction
): void {
  if (error instanceof HttpError) {
    response.status(error.status).json({
      error: {
        code: error.code,
        message: error.message,
        details: error.details,
      },
    });
    return;
  }
  const fallback = error as Error;
  response.status(500).json({
    error: {
      code: "INTERNAL_SERVER_ERROR",
      message: fallback?.message ?? "Unexpected error.",
    },
  });
}
