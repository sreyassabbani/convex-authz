import { defineAuthz } from "@djpanda/convex-authz";
import { components } from "./_generated/api";

export const authz = defineAuthz(components.authz, {
    permissions: {
        threads: ["read", "create", "delete"],
        admin: ["manage"],
    },
    roles: {
        admin: {
            permissions: ["admin:manage", "threads:*"],
            label: "Administrator",
        },
        user: {
            permissions: ["threads:create"],
            label: "Standard User",
        },
    },
});
