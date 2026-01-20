import { describe, expect, it, vi } from "vitest";
import { defineAuthz, type ComponentApi } from "./index.js";
import type { GenericQueryCtx, GenericDataModel } from "convex/server";

type QueryCtx = Pick<GenericQueryCtx<GenericDataModel>, "runQuery">;

// Mock component API
const mockComponent: ComponentApi = {
  queries: {
    checkPermission: "checkPermission",
    hasRole: "hasRole",
    getUserRoles: "getUserRoles",
  },
  mutations: {
    assignRole: "assignRole",
    revokeRole: "revokeRole",
    setAttribute: "setAttribute",
    removeAttribute: "removeAttribute",
    grantPermission: "grantPermission",
    denyPermission: "denyPermission",
    removePermissionOverride: "removePermissionOverride",
  },
} as any as ComponentApi; // We still need a small cast here because we're not providing all methods, but using any for easier mocking in tests is generally acceptable IF it doesn't leak. However, I will try to make it cleaner.

describe("defineAuthz", () => {
  it("should create an authz client with config and generators", () => {
    const { authz, P } = defineAuthz(mockComponent, {
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
    expect(P).toBeDefined();

    // Check selector generation
    expect(P.documents.read).toEqual({ resource: "documents", action: "read" });
    expect(P.documents.ALL).toEqual({ resource: "documents", action: "*" });

    expect(authz.config.roles.admin.permissions).toEqual(["documents:*"]);

    // Check internal mapping logic
    // @ts-expect-error - accessing protected method for testing
    const map = authz.getRolePermissionsMap();
    expect(map.admin).toEqual(["documents:*"]);
    expect(map["org:member"]).toEqual(["documents:read"]);
  });

  it("should support indexed strategy", () => {
    const { authz } = defineAuthz(mockComponent, {
      permissions: {},
      roles: {},
    }, { strategy: "indexed" });

    // constructor name might be minified, but we check prototype?
    expect(authz.constructor.name).toBe("IndexedAuthz");
  });
});

describe("Authz Client", () => {
  const { authz, P } = defineAuthz(mockComponent, {
    permissions: {
      threads: ["read"],
      org: ["manage"]
    },
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

  describe("Fluent API", () => {
    it("should chain perform and check correctly", async () => {
      const ctx = {
        runQuery: vi.fn().mockResolvedValue({ allowed: true })
      } as any as QueryCtx;
      const userId = "user1";

      // Builder usage
      const result = await authz.can(userId).perform(P.threads.read).check(ctx);

      expect(result).toBe(true);
      expect(ctx.runQuery).toHaveBeenCalledWith(
        mockComponent.queries.checkPermission,
        expect.objectContaining({
          userId,
          permission: "threads:read"
        })
      );
    });

    it("should chain scope correctly", async () => {
      const ctx = {
        runQuery: vi.fn().mockResolvedValue({ allowed: true })
      } as any as QueryCtx;
      const userId = "user1";
      const orgScope = { type: "org", id: "1" };

      // Builder usage with scope
      await authz.can(userId).perform(P.org.manage).in(orgScope).check(ctx);

      expect(ctx.runQuery).toHaveBeenCalledWith(
        mockComponent.queries.checkPermission,
        expect.objectContaining({
          userId,
          permission: "org:manage",
          scope: orgScope
        })
      );
    });
  });
});
