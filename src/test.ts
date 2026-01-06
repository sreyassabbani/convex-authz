/// <reference types="vite/client" />
import type { TestConvex } from "convex-test";
import type { GenericSchema, SchemaDefinition } from "convex/server";
import schema from "./component/schema.js";
const modules = import.meta.glob("./component/**/*.ts");

/**
 * Register the authz component with the test convex instance.
 *
 * @example
 * ```typescript
 * import { convexTest } from "convex-test";
 * import authzTest from "@convex-dev/authz/test";
 *
 * test("authorization test", async () => {
 *   const t = convexTest(schema, modules);
 *   authzTest.register(t, "authz");
 *
 *   // Your tests here
 * });
 * ```
 *
 * @param t - The test convex instance, e.g. from calling `convexTest`.
 * @param name - The name of the component, as registered in convex.config.ts. Defaults to "authz".
 */
export function register(
  t: TestConvex<SchemaDefinition<GenericSchema, boolean>>,
  name: string = "authz",
) {
  t.registerComponent(name, schema, modules);
}
export default { register, schema, modules };
