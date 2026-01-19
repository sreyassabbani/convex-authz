import { describe, expect, it, vi } from "vitest";
import { defineAuthz, type ComponentApi } from "./index.js";

// Mock component API
const mockComponent = {
  queries: {
    checkPermission: "checkPermission",
    hasRole: "hasRole",
    getUserRoles: "getUserRoles",
  },
  mutations: {
    assignRole: "assignRole",
    revokeRole: "revokeRole",
  },
} as unknown as ComponentApi;

describe("defineAuthz", () => {
  it("should create an authz client with config", () => {
    const authz = defineAuthz(mockComponent, {
      permissions: {
        documents: ["read", "write"],
      },
      roles: {
        admin: {
          permissions: ["documents:*"],
        },
        "org:member": {
          permissions: ["documents:read"],
        },
      },
    });

    expect(authz).toBeDefined();
    expect(authz.config.roles.admin.permissions).toEqual(["documents:*"]);

    // Check internal mapping logic
    // @ts-expect-error - accessing protected method for testing
    const map = authz.getRolePermissionsMap();
    expect(map.admin).toEqual(["documents:*"]);
    expect(map["org:member"]).toEqual(["documents:read"]);
  });

  it("should support indexed strategy", () => {
    const authz = defineAuthz(mockComponent, {
      permissions: {},
      roles: {},
    }, { strategy: "indexed" });

    // constructor name might be minified, but we check prototype?
    expect(authz.constructor.name).toBe("IndexedAuthz");
  });
});

describe("Authz Client", () => {
  const authz = defineAuthz(mockComponent, {
    permissions: {},
    roles: {
      "org:admin": { permissions: [] },
      "global_admin": { permissions: [] }
    },
  });

  describe("parseRole", () => {
    it("should parse global roles", () => {
      // @ts-expect-error - accessing protected method
      const result = authz.parseRole("global_admin");
      expect(result).toEqual({ role: "global_admin", scope: undefined });
    });

    it("should parse scoped roles with scopeId", () => {
      // @ts-expect-error - accessing protected method
      const result = authz.parseRole("org:admin", "123");
      // The implementation returns the full role name and the scope object
      expect(result).toEqual({
        role: "org:admin",
        scope: { type: "org", id: "123" }
      });
    });
  });
});
