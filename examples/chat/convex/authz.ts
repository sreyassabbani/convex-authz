import {
  defineAuthz,
  definePermissions,
  defineRoles,
} from "@djpanda/convex-authz";
import { components } from "./_generated/api";

const permissions = definePermissions({
  threads: {
    read: true,
    create: true,
    delete: true,
  },
  admin: {
    manage: true,
  },
});

const roles = defineRoles(permissions, {
  admin: {
    permissions: {
      admin: ["manage"],
      threads: ["*"],
    },
    label: "Administrator",
  },
  user: {
    permissions: {
      threads: ["create"],
    },
    label: "Standard User",
  },
});

export const { authz, P } = defineAuthz(components.authz, {
  permissions,
  roles,
});
