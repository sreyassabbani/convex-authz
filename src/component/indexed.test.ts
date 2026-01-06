import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import schema from "./schema.js";
import { api } from "./_generated/api.js";

const modules = import.meta.glob("./**/*.ts");

describe("O(1) Indexed Authorization", () => {
  describe("indexed role assignment", () => {
    it("should assign role and compute permissions", async () => {
      const t = convexTest(schema, modules);

      const roleId = await t.mutation(api.indexed.assignRoleWithCompute, {
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:read", "documents:write", "documents:delete"],
      });

      expect(roleId).toBeDefined();

      // Check that permissions were pre-computed
      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        userId: "user_123",
      });

      expect(permissions).toHaveLength(3);
    });

    it("should check permission in O(1)", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        userId: "user_123",
        role: "editor",
        rolePermissions: ["documents:read", "documents:write"],
      });

      const canRead = await t.query(api.indexed.checkPermissionFast, {
        userId: "user_123",
        permission: "documents:read",
      });

      expect(canRead).toBe(true);

      const canDelete = await t.query(api.indexed.checkPermissionFast, {
        userId: "user_123",
        permission: "documents:delete",
      });

      expect(canDelete).toBe(false);
    });

    it("should check role in O(1)", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        userId: "user_123",
        role: "admin",
        rolePermissions: ["*:*"],
      });

      const hasAdmin = await t.query(api.indexed.hasRoleFast, {
        userId: "user_123",
        role: "admin",
      });

      expect(hasAdmin).toBe(true);

      const hasViewer = await t.query(api.indexed.hasRoleFast, {
        userId: "user_123",
        role: "viewer",
      });

      expect(hasViewer).toBe(false);
    });

    it("should revoke role and remove permissions", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        userId: "user_123",
        role: "editor",
        rolePermissions: ["documents:read", "documents:write"],
      });

      const revoked = await t.mutation(api.indexed.revokeRoleWithCompute, {
        userId: "user_123",
        role: "editor",
        rolePermissions: ["documents:read", "documents:write"],
      });

      expect(revoked).toBe(true);

      const permissions = await t.query(api.indexed.getUserPermissionsFast, {
        userId: "user_123",
      });

      expect(permissions).toHaveLength(0);
    });
  });

  describe("indexed scoped permissions", () => {
    it("should handle scoped role assignments", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.assignRoleWithCompute, {
        userId: "user_123",
        role: "editor",
        rolePermissions: ["documents:read", "documents:write"],
        scope: { type: "team", id: "team_456" },
      });

      // Global check should fail
      const canReadGlobal = await t.query(api.indexed.checkPermissionFast, {
        userId: "user_123",
        permission: "documents:read",
      });

      expect(canReadGlobal).toBe(false);

      // Scoped check should pass
      const canReadScoped = await t.query(api.indexed.checkPermissionFast, {
        userId: "user_123",
        permission: "documents:read",
        objectType: "team",
        objectId: "team_456",
      });

      expect(canReadScoped).toBe(true);
    });
  });

  describe("indexed direct permissions", () => {
    it("should grant direct permission", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.grantPermissionDirect, {
        userId: "user_123",
        permission: "special:access",
        reason: "VIP user",
      });

      const hasPermission = await t.query(api.indexed.checkPermissionFast, {
        userId: "user_123",
        permission: "special:access",
      });

      expect(hasPermission).toBe(true);
    });

    it("should deny permission overriding role", async () => {
      const t = convexTest(schema, modules);

      // First assign role with permission
      await t.mutation(api.indexed.assignRoleWithCompute, {
        userId: "user_123",
        role: "admin",
        rolePermissions: ["documents:delete"],
      });

      // Then deny that specific permission
      await t.mutation(api.indexed.denyPermissionDirect, {
        userId: "user_123",
        permission: "documents:delete",
        reason: "Restricted",
      });

      const canDelete = await t.query(api.indexed.checkPermissionFast, {
        userId: "user_123",
        permission: "documents:delete",
      });

      // Deny should take precedence
      expect(canDelete).toBe(false);
    });
  });

  describe("indexed relationships", () => {
    it("should add relationship with computed effective relations", async () => {
      const t = convexTest(schema, modules);

      const relationId = await t.mutation(api.indexed.addRelationWithCompute, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(relationId).toBeDefined();

      const hasRelation = await t.query(api.indexed.hasRelationFast, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(hasRelation).toBe(true);
    });

    it("should remove relationship", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.indexed.addRelationWithCompute, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      const removed = await t.mutation(api.indexed.removeRelationWithCompute, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(removed).toBe(true);

      const hasRelation = await t.query(api.indexed.hasRelationFast, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(hasRelation).toBe(false);
    });
  });
});
