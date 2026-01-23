import {
  defineAuthz,
  definePermissions,
  defineRoles,
  definePolicies,
} from "@djpanda/convex-authz";

import { components } from "./_generated/api";

const permissions = definePermissions({
  contacts: {
    read: true,
    create: true,
    update: true,
    delete: true,
  },
  deals: {
    read: true,
    create: true,
    update: true,
    close: true,
  },
  org: {
    manage_members: true,
    manage_billing: true,
  },
  system: {
    manage: true,
  },
});

const roles = defineRoles(permissions, {
  superuser: {
    permissions: {
      system: ["manage"],
      org: ["*"],
      contacts: ["*"],
      deals: ["*"],
    },
    label: "Super User",
  },
  "org:owner": {
    permissions: {
      org: ["*"],
      contacts: ["*"],
      deals: ["*"],
    },
    label: "Organization Owner",
  },
  "org:member": {
    permissions: {
      contacts: ["read"],
      deals: ["read"],
    },
    label: "Organization Member",
  },
});

const policies = definePolicies(permissions, {
  "deals:close": {
    condition: (ctx) =>
      ctx.hasRole("org:owner") || ctx.getAttribute<boolean>("canCloseDeals") === true,
    message: "Closing deals requires org ownership or explicit clearance.",
  },
});

export const { authz, P } = defineAuthz(components.authz, {
  permissions,
  roles,
  policies,
  allowCustomRoles: true,
});
