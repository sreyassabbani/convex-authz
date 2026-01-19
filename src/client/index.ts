/**
 * @djpanda/convex-authz - Authorization Component for Convex
 *
 * A comprehensive RBAC/ABAC/ReBAC authorization component featuring
 * O(1) indexed lookups, inspired by Google Zanzibar.
 *
 * @example
 * ```typescript
 * import {
 *   Authz,
 *   definePermissions,
 *   defineRoles,
 *   AnyRole,
 *   GlobalRole,
 *   AnyPermission,
 * } from "@djpanda/convex-authz";
 * import { components } from "./_generated/api";
 *
 * const permissions = definePermissions({
 *   documents: { create: true, read: true, update: true, delete: true },
 * });
 *
 * const roles = defineRoles(permissions, {
 *   admin: { documents: ["create", "read", "update", "delete"] },
 *   viewer: { documents: ["read"] },
 * });
 *
 * export const authz = new Authz(components.authz, { permissions, roles });
 * ```
 */

import type {
  GenericActionCtx,
  GenericDataModel,
  GenericMutationCtx,
  GenericQueryCtx,
} from "convex/server";
import type { ComponentApi } from "../component/_generated/component.js";

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Permission configuration structure
 */
export type PermissionConfig = Record<string, Record<string, boolean>>;

export type RoleConfig<P extends PermissionConfig> = Record<
  string,
  { [K in keyof P & string]?: Array<keyof P[K] & string> }
>;

/**
 * Scope configuration for the authz system
 */
export interface AuthzConfig<P extends PermissionConfig> {
  permissions: P;
  roles: {
    [scope: string]: RoleConfig<P>;
  };
}

/**
 * Helper to extract the scope from a role string (e.g., "org:admin" -> "org")
 */
export type ScopeOf<R extends string> = R extends `${infer S}:${string}`
  ? S
  : "global";

/**
 * Helper to get all valid global role names
 */
export type GlobalRole<C extends AuthzConfig<PermissionConfig>> =
  keyof C["roles"]["global"] & string;

/**
 * Helper to get all valid role strings (e.g., "global:admin", "org:member")
 */
export type AnyRole<C extends AuthzConfig<PermissionConfig>> = {
  [S in keyof C["roles"] & string]: S extends "global"
  ? keyof C["roles"][S] & string
  : `${S}:${keyof C["roles"][S] & string}`;
}[keyof C["roles"] & string];

/**
 * Helper to get all valid permission strings (e.g., "documents:read", "org:delete")
 */
export type AnyPermission<C extends AuthzConfig<PermissionConfig>> = {
  [K in keyof C["permissions"] & string]: `${K}:${keyof C["permissions"][K] & string}`;
}[keyof C["permissions"] & string];

/**
 * Helper to get the ID type for a given scope
 */
export type ScopeIdType<S extends string> = string; // In a real app, this could be Id<S> if S maps to a table

/**
 * Argument type for scope-dependent methods
 */
export type ScopeArgs<
  C extends AuthzConfig<PermissionConfig>,
  R extends string,
> = ScopeOf<R> extends "global" ? [] : [scopeId: string];

/**
 * Policy definition for ABAC
 */
export type PolicyConfig = {
  condition: (ctx: PolicyContext) => boolean | Promise<boolean>;
  message?: string;
};

export type PolicyDefinition = Record<string, PolicyConfig>;

/**
 * Policy evaluation context
 */
export interface PolicyContext {
  subject: {
    userId: string;
    roles: string[];
    attributes: Record<string, unknown>;
  };
  resource?: {
    type: string;
    id: string;
    [key: string]: unknown;
  };
  action: string;
}

/**
 * Internal Scope representation
 */
export interface Scope {
  type: string;
  id: string;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Define type-safe permissions
 */
export function definePermissions<P extends PermissionConfig>(
  permissions: P
): P {
  return permissions;
}

/**
 * Define type-safe roles for a specific scope
 */
export function defineRoles<P extends PermissionConfig>(
  _permissions: P,
  roles: RoleConfig<P>
): RoleConfig<P> {
  return roles;
}

/**
 * Define the full authz configuration
 */
export function defineAuthzConfig<P extends PermissionConfig>(
  config: AuthzConfig<P>
): AuthzConfig<P> {
  return config;
}

/**
 * Define type-safe policies
 */
export function definePolicies<P extends PolicyDefinition>(policies: P): P {
  return policies;
}

/**
 * Flatten role permissions into an array of permission strings
 */
export function flattenRolePermissions<P extends PermissionConfig>(
  roleConfig: RoleConfig<P>,
  roleName: string
): string[] {
  const rolePerms = roleConfig[roleName];
  if (!rolePerms) return [];

  const permissions: string[] = [];
  for (const [resource, actions] of Object.entries(rolePerms)) {
    if (Array.isArray(actions)) {
      for (const action of actions) {
        permissions.push(`${resource}:${String(action)}`);
      }
    }
  }
  return permissions;
}

// ============================================================================
// Context Types for Client Methods
// ============================================================================

type QueryCtx = Pick<GenericQueryCtx<GenericDataModel>, "runQuery">;
type MutationCtx = Pick<GenericMutationCtx<GenericDataModel>, "runMutation">;
type ActionCtx = Pick<
  GenericActionCtx<GenericDataModel>,
  "runQuery" | "runMutation" | "runAction"
>;

/**
 * Standard Authz client for RBAC/ABAC operations
 */
export class Authz<
  P extends PermissionConfig,
  C extends AuthzConfig<P>,
  Policy extends PolicyDefinition = Record<string, never>,
> {
  constructor(
    public component: ComponentApi,
    private options: {
      config: C;
      policies?: Policy;
      defaultActorId?: string;
    }
  ) { }

  /**
   * Build role permissions map for queries
   */
  private buildRolePermissionsMap(): Record<string, string[]> {
    const map: Record<string, string[]> = {};

    for (const [scope, roles] of Object.entries(this.options.config.roles)) {
      for (const roleName of Object.keys(roles)) {
        const fullRoleName = scope === "global" ? roleName : `${scope}:${roleName}`;
        map[fullRoleName] = flattenRolePermissions(roles, roleName);
      }
    }

    return map;
  }

  /**
   * Parse a role string into scope and role name
   */
  private parseRole(roleString: string, scopeId?: string): { role: string; scope?: Scope } {
    if (roleString.includes(":")) {
      const [scopeType, roleName] = roleString.split(":");
      return {
        role: roleName,
        scope: scopeId ? { type: scopeType, id: scopeId } : undefined,
      };
    }
    return { role: roleString };
  }

  /**
   * Check if user has permission
   */
  async can(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope
  ): Promise<boolean> {
    const result = await ctx.runQuery(this.component.queries.checkPermission, {
      userId,
      permission,
      scope,
      rolePermissions: this.buildRolePermissionsMap(),
    });

    return result.allowed;
  }

  /**
   * Require permission or throw error
   */
  async require(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope
  ): Promise<void> {
    const result = await ctx.runQuery(this.component.queries.checkPermission, {
      userId,
      permission,
      scope,
      rolePermissions: this.buildRolePermissionsMap(),
    });

    if (!result.allowed) {
      throw new Error(
        `Permission denied: ${permission}${scope ? ` on ${scope.type}:${scope.id}` : ""} - ${result.reason}`
      );
    }
  }

  /**
   * Check if user has a role
   */
  async hasRole<R extends AnyRole<C>>(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    role: R,
    ...args: ScopeArgs<C, R>
  ): Promise<boolean> {
    const { role: roleName, scope } = this.parseRole(role, args[0]);
    return await ctx.runQuery(this.component.queries.hasRole, {
      userId,
      role: roleName,
      scope,
    });
  }

  /**
   * Get all roles for a user
   */
  async getUserRoles(ctx: QueryCtx | ActionCtx, userId: string, scope?: Scope) {
    return await ctx.runQuery(this.component.queries.getUserRoles, {
      userId,
      scope,
    });
  }

  /**
   * Get all effective permissions for a user
   */
  async getUserPermissions(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    scope?: Scope
  ) {
    return await ctx.runQuery(this.component.queries.getEffectivePermissions, {
      userId,
      rolePermissions: this.buildRolePermissionsMap(),
      scope,
    });
  }

  /**
   * Assign a role to a user
   */
  async assignRole<R extends GlobalRole<C>>(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: R,
    expiresAt?: number,
    actorId?: string
  ): Promise<string>;
  async assignRole<R extends AnyRole<C>>(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: R,
    scopeId: string,
    expiresAt?: number,
    actorId?: string
  ): Promise<string>;
  async assignRole(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: string,
    ...args: [unknown?, unknown?, unknown?]
  ): Promise<string> {
    const isGlobal = !role.includes(":");
    const scopeId = (isGlobal ? undefined : args[0]) as string | undefined;
    const expiresAt = (isGlobal ? args[0] : args[1]) as number | undefined;
    const actorId = (isGlobal ? args[1] : args[2]) as string | undefined;

    const { role: roleName, scope } = this.parseRole(role, scopeId);

    return await ctx.runMutation(this.component.mutations.assignRole, {
      userId,
      role: roleName,
      scope,
      expiresAt,
      assignedBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
    });
  }
  /**
   * Revoke a role from a user
   */
  async revokeRole<R extends GlobalRole<C>>(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: R,
    actorId?: string
  ): Promise<boolean>;
  async revokeRole<R extends AnyRole<C>>(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: R,
    scopeId: string,
    actorId?: string
  ): Promise<boolean>;
  async revokeRole(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: string,
    ...args: [unknown?, unknown?]
  ): Promise<boolean> {
    const isGlobal = !role.includes(":");
    const scopeId = (isGlobal ? undefined : args[0]) as string | undefined;
    const actorId = (isGlobal ? args[0] : args[1]) as string | undefined;

    const { role: roleName, scope } = this.parseRole(role, scopeId);

    return await ctx.runMutation(this.component.mutations.revokeRole, {
      userId,
      role: roleName,
      scope,
      revokedBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
    });
  }

  /**
   * Set a user attribute
   */
  async setAttribute(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    key: string,
    value: unknown,
    actorId?: string
  ): Promise<string> {
    return await ctx.runMutation(this.component.mutations.setAttribute, {
      userId,
      key,
      value,
      setBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
    });
  }

  /**
   * Remove a user attribute
   */
  async removeAttribute(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    key: string,
    actorId?: string
  ): Promise<boolean> {
    return await ctx.runMutation(this.component.mutations.removeAttribute, {
      userId,
      key,
      removedBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
    });
  }

  /**
   * Grant a direct permission override
   */
  async grantPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: AnyPermission<C>,
    scope?: Scope,
    reason?: string,
    expiresAt?: number,
    actorId?: string
  ): Promise<string> {
    return await ctx.runMutation(this.component.mutations.grantPermission, {
      userId,
      permission,
      scope,
      reason,
      expiresAt,
      createdBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
    });
  }

  /**
   * Deny a permission (explicit deny override)
   */
  async denyPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: AnyPermission<C>,
    scope?: Scope,
    reason?: string,
    expiresAt?: number,
    actorId?: string
  ): Promise<string> {
    return await ctx.runMutation(this.component.mutations.denyPermission, {
      userId,
      permission,
      scope,
      reason,
      expiresAt,
      createdBy: actorId ?? this.options.defaultActorId,
      enableAudit: true,
    });
  }
  async getUserAttributes(ctx: QueryCtx | ActionCtx, userId: string) {
    return await ctx.runQuery(this.component.queries.getUserAttributes, {
      userId,
    });
  }

  /**
   * Get audit log entries
   */
  async getAuditLog(
    ctx: QueryCtx | ActionCtx,
    options?: {
      userId?: string;
      action?: string;
      limit?: number;
    }
  ) {
    return await ctx.runQuery(this.component.queries.getAuditLog, {
      userId: options?.userId,
      action: options?.action as
        | "permission_check"
        | "role_assigned"
        | "role_revoked"
        | "permission_granted"
        | "permission_denied"
        | "attribute_set"
        | "attribute_removed"
        | undefined,
      limit: options?.limit,
    });
  }
}

// ============================================================================
// IndexedAuthz Client Class (O(1) Lookups)
// ============================================================================

/**
 * O(1) Indexed Authz client with pre-computed permissions
 *
 * Use this for production workloads with many permission checks.
 * Writes are slower but reads are instant via indexed lookups.
 */
export class IndexedAuthz<
  P extends PermissionConfig,
  C extends AuthzConfig<P>,
> {
  constructor(
    public component: ComponentApi,
    private options: {
      config: C;
      defaultActorId?: string;
    }
  ) { }

  /**
   * Build role permissions map for computed roles
   */
  private buildRolePermissionsMap(): Record<string, string[]> {
    const map: Record<string, string[]> = {};

    for (const [scope, roles] of Object.entries(this.options.config.roles)) {
      for (const roleName of Object.keys(roles)) {
        const fullRoleName = scope === "global" ? roleName : `${scope}:${roleName}`;
        map[fullRoleName] = flattenRolePermissions(roles, roleName);
      }
    }

    return map;
  }

  /**
   * Parse a role string into scope and role name
   */
  private parseRole(roleString: string, scopeId?: string): { role: string; scope?: Scope } {
    if (roleString.includes(":")) {
      const [scopeType, roleName] = roleString.split(":");
      return {
        role: roleName,
        scope: scopeId ? { type: scopeType, id: scopeId } : undefined,
      };
    }
    return { role: roleString };
  }

  /**
   * Check permission - O(1) indexed lookup
   */
  async can(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope
  ): Promise<boolean> {
    return await ctx.runQuery(this.component.indexed.checkPermissionFast, {
      userId,
      permission,
      objectType: scope?.type,
      objectId: scope?.id,
    });
  }

  /**
   * Require permission or throw - O(1)
   */
  async require(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope
  ): Promise<void> {
    const allowed = await this.can(ctx, userId, permission, scope);
    if (!allowed) {
      throw new Error(
        `Permission denied: ${permission}${scope ? ` on ${scope.type}:${scope.id}` : ""}`
      );
    }
  }

  /**
   * Check if user has a role
   */
  async hasRole<R extends AnyRole<C>>(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    role: R,
    ...args: ScopeArgs<C, R>
  ): Promise<boolean> {
    const { role: roleName, scope } = this.parseRole(role, args[0]);
    return await ctx.runQuery(this.component.indexed.hasRoleFast, {
      userId,
      role: roleName,
      objectType: scope?.type,
      objectId: scope?.id,
    });
  }

  /**
   * Check relationship - O(1) indexed lookup
   */
  async hasRelation(
    ctx: QueryCtx | ActionCtx,
    subjectType: string,
    subjectId: string,
    relation: string,
    objectType: string,
    objectId: string
  ): Promise<boolean> {
    return await ctx.runQuery(this.component.indexed.hasRelationFast, {
      subjectType,
      subjectId,
      relation,
      objectType,
      objectId,
    });
  }

  /**
   * Get all permissions for a user
   */
  async getUserPermissions(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    scope?: Scope
  ) {
    const scopeKey = scope ? `${scope.type}:${scope.id}` : undefined;
    return await ctx.runQuery(this.component.indexed.getUserPermissionsFast, {
      userId,
      scopeKey,
    });
  }

  /**
   * Get all roles for a user
   */
  async getUserRoles(ctx: QueryCtx | ActionCtx, userId: string, scope?: Scope) {
    const scopeKey = scope ? `${scope.type}:${scope.id}` : undefined;
    return await ctx.runQuery(this.component.indexed.getUserRolesFast, {
      userId,
      scopeKey,
    });
  }

  /**
   * Assign a role and pre-compute permissions
   */
  async assignRole<R extends GlobalRole<C>>(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: R,
    expiresAt?: number,
    actorId?: string
  ): Promise<string>;
  async assignRole<R extends AnyRole<C>>(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: R,
    scopeId: string,
    expiresAt?: number,
    actorId?: string
  ): Promise<string>;
  async assignRole(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: string,
    ...args: [unknown?, unknown?, unknown?]
  ): Promise<string> {
    const isGlobal = !role.includes(":");
    const scopeId = (isGlobal ? undefined : args[0]) as string | undefined;
    const expiresAt = (isGlobal ? args[0] : args[1]) as number | undefined;
    const actorId = (isGlobal ? args[1] : args[2]) as string | undefined;

    const { role: roleName, scope } = this.parseRole(role, scopeId);

    // Get scoped role config
    const scopeName = (role.includes(':') ? role.split(':')[0] : 'global') as keyof C["roles"] & string;
    const scopeRoles = this.options.config.roles[scopeName];
    const rolePermissions = flattenRolePermissions(scopeRoles, roleName);

    return await ctx.runMutation(this.component.indexed.assignRoleWithCompute, {
      userId,
      role: roleName,
      rolePermissions,
      scope,
      expiresAt,
      assignedBy: actorId ?? this.options.defaultActorId,
    });
  }

  /**
   * Revoke a role and recompute permissions
   */
  async revokeRole<R extends GlobalRole<C>>(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: R,
    actorId?: string
  ): Promise<boolean>;
  async revokeRole<R extends AnyRole<C>>(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: R,
    scopeId: string,
    actorId?: string
  ): Promise<boolean>;
  async revokeRole(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: string,
    ...args: [unknown?, unknown?]
  ): Promise<boolean> {
    const isGlobal = !role.includes(":");
    const scopeId = (isGlobal ? undefined : args[0]) as string | undefined;
    const { role: roleName, scope } = this.parseRole(role, scopeId);

    // Get scoped role config
    const scopeName = (role.includes(':') ? role.split(':')[0] : 'global') as keyof C["roles"] & string;
    const scopeRoles = this.options.config.roles[scopeName];
    const rolePermissions = flattenRolePermissions(scopeRoles, roleName);

    return await ctx.runMutation(this.component.indexed.revokeRoleWithCompute, {
      userId,
      role: roleName,
      rolePermissions,
      scope,
    });
  }

  /**
   * Grant a direct permission
   */
  async grantPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope,
    reason?: string,
    expiresAt?: number,
    grantedBy?: string
  ): Promise<string> {
    return await ctx.runMutation(this.component.indexed.grantPermissionDirect, {
      userId,
      permission,
      scope,
      reason,
      grantedBy: grantedBy ?? this.options.defaultActorId,
      expiresAt,
    });
  }

  /**
   * Deny a permission
   */
  async denyPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope,
    reason?: string,
    expiresAt?: number,
    deniedBy?: string
  ): Promise<string> {
    return await ctx.runMutation(this.component.indexed.denyPermissionDirect, {
      userId,
      permission,
      scope,
      reason,
      deniedBy: deniedBy ?? this.options.defaultActorId,
      expiresAt,
    });
  }

  /**
   * Add a relationship with computed transitive relations
   */
  async addRelation(
    ctx: MutationCtx | ActionCtx,
    subjectType: string,
    subjectId: string,
    relation: string,
    objectType: string,
    objectId: string,
    inheritedRelations?: Array<{
      relation: string;
      fromObjectType: string;
      fromRelation: string;
    }>,
    createdBy?: string
  ): Promise<string> {
    return await ctx.runMutation(this.component.indexed.addRelationWithCompute, {
      subjectType,
      subjectId,
      relation,
      objectType,
      objectId,
      inheritedRelations,
      createdBy: createdBy ?? this.options.defaultActorId,
    });
  }

  /**
   * Remove a relationship
   */
  async removeRelation(
    ctx: MutationCtx | ActionCtx,
    subjectType: string,
    subjectId: string,
    relation: string,
    objectType: string,
    objectId: string
  ): Promise<boolean> {
    return await ctx.runMutation(
      this.component.indexed.removeRelationWithCompute,
      {
        subjectType,
        subjectId,
        relation,
        objectType,
        objectId,
      }
    );
  }
}

// ============================================================================
// Re-exports
// ============================================================================

export type { ComponentApi } from "../component/_generated/component.js";
