import { describe, expect, it } from "vitest";
import {
  definePermissions,
  defineRoles,
  definePolicies,
  flattenRolePermissions,
} from "./index.js";

describe("client helpers", () => {
  describe("definePermissions", () => {
    it("should return permissions as-is", () => {
      const permissions = definePermissions({
        documents: {
          create: true,
          read: true,
          update: true,
          delete: true,
        },
        settings: {
          view: true,
          manage: true,
        },
      });

      expect(permissions.documents.create).toBe(true);
      expect(permissions.settings.manage).toBe(true);
    });
  });

  describe("defineRoles", () => {
    it("should return roles as-is", () => {
      const permissions = definePermissions({
        documents: {
          create: true,
          read: true,
        },
      });

      const roles = defineRoles(permissions, {
        admin: { documents: ["create", "read"] },
        viewer: { documents: ["read"] },
      });

      expect(roles.admin.documents).toEqual(["create", "read"]);
      expect(roles.viewer.documents).toEqual(["read"]);
    });
  });

  describe("definePolicies", () => {
    it("should return policies as-is", () => {
      const policies = definePolicies({
        isAdmin: {
          condition: (ctx) => ctx.subject.roles.includes("admin"),
          message: "Must be admin",
        },
      });

      expect(policies.isAdmin.message).toBe("Must be admin");
    });
  });

  describe("flattenRolePermissions", () => {
    it("should flatten role permissions to strings", () => {
      const roles = {
        admin: {
          documents: ["create", "read", "update", "delete"],
          settings: ["view", "manage"],
        },
        viewer: {
          documents: ["read"],
        },
      };

      const adminPerms = flattenRolePermissions(roles, "admin");
      expect(adminPerms).toContain("documents:create");
      expect(adminPerms).toContain("documents:read");
      expect(adminPerms).toContain("settings:manage");
      expect(adminPerms).toHaveLength(6);

      const viewerPerms = flattenRolePermissions(roles, "viewer");
      expect(viewerPerms).toEqual(["documents:read"]);
    });

    it("should return empty array for unknown role", () => {
      const roles = {
        admin: { documents: ["read"] },
      };

      const perms = flattenRolePermissions(roles, "unknown");
      expect(perms).toEqual([]);
    });
  });
});
