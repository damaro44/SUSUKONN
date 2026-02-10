import cors from "cors";
import express from "express";
import helmet from "helmet";
import morgan from "morgan";
import { errorHandler, notFoundHandler } from "./middleware/errorHandler.js";
import { v1Router } from "./routes/v1.js";

export function createApp() {
  const app = express();
  app.use(
    cors({
      origin: true,
      credentials: true,
    })
  );
  app.use(helmet());
  app.use(express.json({ limit: "2mb" }));
  app.use(morgan("dev"));

  app.get("/", (_request, response) => {
    response.json({
      data: {
        name: "SusuKonnect API",
        version: "v1",
      },
    });
  });

  app.use("/v1", v1Router);
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
