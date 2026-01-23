import {
  authzConfig,
  createAuthz,
} from "@djpanda/convex-authz";

import { components } from "./_generated/api";

const config = authzConfig({
  permissions: {
    contacts: ["read", "create", "update", "delete"],
    deals: ["read", "create", "update", "close"],
    org: ["manage_members", "manage_billing"],
    system: ["manage"],
  },
  roles: {
    superuser: {
      grants: {
        system: ["manage"],
        org: ["*"],
        contacts: ["*"],
        deals: ["*"],
      },
      label: "Super User",
    },
    "org:owner": {
      grants: {
        org: ["*"],
        contacts: ["*"],
        deals: ["*"],
      },
      label: "Organization Owner",
    },
    "org:member": {
      grants: {
        contacts: ["read"],
        deals: ["read"],
      },
      label: "Organization Member",
    },
  },
  policies: {
    "deals:close": {
      condition: (ctx) =>
        ctx.hasRole("org:owner") || ctx.getAttribute<boolean>("canCloseDeals") === true,
      message: "Closing deals requires org ownership or explicit clearance.",
    },
  },
  allowCustomRoles: true,
});

export const { authz, P } = createAuthz(components.authz, config);
