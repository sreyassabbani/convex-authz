import { defineApp } from "convex/server";
import authz from "@convex-dev/authz/convex.config.js";

const app = defineApp();
app.use(authz);

export default app;
