import {
  authzConfig,
  createAuthz,
} from "@djpanda/convex-authz";
import { components } from "./_generated/api";

const config = authzConfig({
  permissions: {
    threads: ["read", "create", "delete"],
    admin: ["manage"],
  },
  roles: {
    admin: {
      grants: {
        admin: ["manage"],
        threads: ["*"],
      },
      label: "Administrator",
    },
    user: {
      grants: {
        threads: ["create"],
      },
      label: "Standard User",
    },
  },
});

export const { authz, P } = createAuthz(components.authz, config);
