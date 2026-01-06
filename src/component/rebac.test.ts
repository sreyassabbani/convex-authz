import { convexTest } from "convex-test";
import { describe, expect, it } from "vitest";
import schema from "./schema.js";
import { api } from "./_generated/api.js";

const modules = import.meta.glob("./**/*.ts");

describe("ReBAC (Relationship-Based Access Control)", () => {
  describe("direct relationships", () => {
    it("should add a relationship", async () => {
      const t = convexTest(schema, modules);

      const relationId = await t.mutation(api.rebac.addRelation, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(relationId).toBeDefined();
    });

    it("should check a direct relationship", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.rebac.addRelation, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      const exists = await t.query(api.rebac.hasDirectRelation, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(exists).toBe(true);
    });

    it("should return false for non-existent relationship", async () => {
      const t = convexTest(schema, modules);

      const exists = await t.query(api.rebac.hasDirectRelation, {
        subjectType: "user",
        subjectId: "alice",
        relation: "owner",
        objectType: "team",
        objectId: "sales",
      });

      expect(exists).toBe(false);
    });

    it("should remove a relationship", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.rebac.addRelation, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      const removed = await t.mutation(api.rebac.removeRelation, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(removed).toBe(true);

      const exists = await t.query(api.rebac.hasDirectRelation, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      expect(exists).toBe(false);
    });

    it("should get all relationships for a subject", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.rebac.addRelation, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      await t.mutation(api.rebac.addRelation, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "marketing",
      });

      const relations = await t.query(api.rebac.getSubjectRelations, {
        subjectType: "user",
        subjectId: "alice",
      });

      expect(relations).toHaveLength(2);
    });
  });

  describe("relationship traversal", () => {
    it("should traverse relationships with rules", async () => {
      const t = convexTest(schema, modules);

      // Setup: user -> team -> account hierarchy
      // alice is member of sales team
      await t.mutation(api.rebac.addRelation, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      // sales team owns acme account
      await t.mutation(api.rebac.addRelation, {
        subjectType: "team",
        subjectId: "sales",
        relation: "owner",
        objectType: "account",
        objectId: "acme",
      });

      // Check if alice can view acme account through traversal
      const result = await t.query(api.rebac.checkRelationWithTraversal, {
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "account",
        objectId: "acme",
        traversalRules: {
          "account:viewer": [
            { through: "team", via: "owner", inherit: "member" },
          ],
        },
      });

      expect(result.allowed).toBe(true);
      expect(result.path).toBeDefined();
    });

    it("should fail traversal when path doesn't exist", async () => {
      const t = convexTest(schema, modules);

      // alice is member of marketing team
      await t.mutation(api.rebac.addRelation, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "marketing",
      });

      // sales team owns acme account (not marketing)
      await t.mutation(api.rebac.addRelation, {
        subjectType: "team",
        subjectId: "sales",
        relation: "owner",
        objectType: "account",
        objectId: "acme",
      });

      // alice should NOT have access to acme
      const result = await t.query(api.rebac.checkRelationWithTraversal, {
        subjectType: "user",
        subjectId: "alice",
        relation: "viewer",
        objectType: "account",
        objectId: "acme",
        traversalRules: {
          "account:viewer": [
            { through: "team", via: "owner", inherit: "member" },
          ],
        },
      });

      expect(result.allowed).toBe(false);
    });
  });

  describe("object relationships", () => {
    it("should get all subjects with relation to an object", async () => {
      const t = convexTest(schema, modules);

      await t.mutation(api.rebac.addRelation, {
        subjectType: "user",
        subjectId: "alice",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      await t.mutation(api.rebac.addRelation, {
        subjectType: "user",
        subjectId: "bob",
        relation: "member",
        objectType: "team",
        objectId: "sales",
      });

      const relations = await t.query(api.rebac.getObjectRelations, {
        objectType: "team",
        objectId: "sales",
      });

      expect(relations).toHaveLength(2);
      expect(relations.map((r: { subjectId: string }) => r.subjectId)).toContain("alice");
      expect(relations.map((r: { subjectId: string }) => r.subjectId)).toContain("bob");
    });
  });
});
