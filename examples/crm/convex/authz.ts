import { defineAuthz } from "@djpanda/convex-authz";
import { DataModel } from "./_generated/dataModel";

import { components } from "./_generated/api";

export const authz = defineAuthz(components.authz, {
    permissions: {
        contacts: ["read", "create", "update", "delete"],
        deals: ["read", "create", "update", "close"],
        org: ["manage_members", "manage_billing"],
        system: ["manage"],
    },
    roles: {
        superuser: {
            permissions: ["system:manage", "org:*", "contacts:*", "deals:*"],
            label: "Super User",
        },
        "org:owner": {
            permissions: ["org:*", "contacts:*", "deals:*"],
            label: "Organization Owner",
        },
        "org:member": {
            permissions: ["contacts:read", "deals:read"],
            label: "Organization Member",
        },
    },
    allowCustomRoles: true,
});
