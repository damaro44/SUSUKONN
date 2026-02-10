import { env } from "./config/env.js";
import { createApp } from "./app.js";

const app = createApp();

app.listen(env.API_PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`SusuKonnect API listening on port ${env.API_PORT}`);
});
