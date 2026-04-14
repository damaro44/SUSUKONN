import { createApp } from "./app.js";
import { env } from "./config/env.js";

const app = createApp();

app.listen(env.API_PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Eclair API listening on port ${env.API_PORT}`);
});
