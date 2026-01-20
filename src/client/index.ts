/**
 * @djpanda/convex-authz - Authorization Component for Convex
 *
 * A comprehensive RBAC/ABAC/ReBAC authorization component featuring
 * O(1) indexed lookups, inspired by Google Zanzibar.
 */

import type {
  GenericActionCtx,
  GenericDataModel,
  GenericMutationCtx,
  GenericQueryCtx,
} from "convex/server";
import { v, type Validator } from "convex/values";
import type { ComponentApi } from "../component/_generated/component.js";

export type { ComponentApi } from "../component/_generated/component.js";

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Configuration of Resources and their valid actions.
 * Uses `readonly` arrays to preserve literal types for type safety.
 * Example: { documents: ["read", "write"] as const }
 */
export type PermissionsConfig = {
  readonly [resource: string]: readonly string[];
};

/**
 * Derive all valid permission patterns from a PermissionsConfig.
 * This includes:
 * - Exact permissions: "documents:read", "documents:write"
 * - Resource wildcards: "documents:*"
 * - Global wildcard: "*"
 * 
 * NOTE: For full type safety, use `as const` on your permissions config.
 */
export type ValidPermissionPattern<P extends PermissionsConfig> =
  | "*"
  | {
    [K in keyof P & string]: P[K] extends readonly (infer A extends string)[]
    ? `${K}:${A}` | `${K}:*`
    : never;
  }[keyof P & string];

/**
 * Definition of a single role, with type-safe permissions.
 * The permissions array is constrained to valid patterns derived from the PermissionsConfig.
 */
export type RoleDefinition<P extends PermissionsConfig> = {
  /**
   * List of permissions granted by this role.
   * Must be valid permission strings like "resource:action", "resource:*", or "*".
   */
  permissions: ValidPermissionPattern<P>[];
  /**
   * Optional human-readable label
   */
  label?: string;
  /**
   * Optional description
   */
  description?: string;
};

/**
 * Configuration of Roles, typed against the PermissionsConfig.
 * Keys can be namespaced (e.g. "org:admin") or global (e.g. "superadmin").
 */
export type RolesConfig<P extends PermissionsConfig> = Record<string, RoleDefinition<P>>;

/**
 * Main Authz Configuration
 */
export interface AuthzConfig<P extends PermissionsConfig = PermissionsConfig> {
  permissions: P;
  roles: RolesConfig<P>;
}

/**
 * Options for the Authz client
 */
export interface AuthzOptions {
  /**
   * Strategy to use for permission checks.
   * - "standard": Direct checks against the roles configuration (stateless).
   * - "indexed": Use O(1) indexed lookups (requires `assignRole` to compute permissions).
   * @default "standard"
   */
  strategy?: "standard" | "indexed";
  /**
   * Default actor ID to record in audit logs key if not provided in method calls.
   */
  defaultActorId?: string;
}

// ============================================================================
// Type Helpers
// ============================================================================

/**
 * Extract all valid role names from the config
 */
export type RoleName<C extends AuthzConfig> = keyof C["roles"] & string;

/**
 * Extract all valid permission strings from the config
 * e.g., "documents:read"
 */
export type PermissionString<C extends AuthzConfig> = {
  [R in keyof C["permissions"] & string]: `${R}:${C["permissions"][R][number] & string}`;
}[keyof C["permissions"] & string];

/**
 * Helper to get the scope part of a role (e.g., "org" from "org:admin")
 * Returns "global" if no namespace is present
 */
export type ScopeName<R extends string> = R extends `${infer S}:${string}` ? S : "global";

/**
 * Scope argument for methods.
 * If the role/permission is namespaced (e.g. "org:admin"), requires a scopeId.
 * If global, no scopeId is needed.
 */
export type ScopeArgs<R extends string> = ScopeName<R> extends "global"
  ? []
  : [scopeId: string];

/**
 * Internal Scope Object
 */
export interface Scope {
  type: string;
  id: string;
}

// ============================================================================
// Main Factory
// ============================================================================

/**
 * Define your Authorization configuration and get a typed Client.
 *
 * @param component - The Convex Component API object (usually `components.authz`)
 * @param config - The Permissions and Roles configuration
 * @param options - Additional options (strategy, defaults)
 *
 * @example
 * ```ts
 * const authz = defineAuthz(components.authz, {
 *   permissions: {
 *     documents: ["read", "write"],
 *   },
 *   roles: {
 *     admin: { permissions: ["*"] },
 *     "org:member": { permissions: ["documents:read"] },
 *   }
 * });
 * ```
 */
export function defineAuthz<
  const P extends PermissionsConfig,
>(
  component: ComponentApi,
  config: { permissions: P; roles: RolesConfig<P>; allowCustomRoles?: boolean },
  options?: AuthzOptions
) {
  // Cast to any to resolve variance issues between generic P and base PermissionsConfig
  // The types at the call site are still fully checked
  if (options?.strategy === "indexed") {
    return new IndexedAuthz<AuthzConfig<P>>(component, config as any, options);
  }
  return new Authz<AuthzConfig<P>>(component, config as any, options);
}

// ============================================================================
// Client Classes
// ============================================================================

type QueryCtx = Pick<GenericQueryCtx<GenericDataModel>, "runQuery">;
type MutationCtx = Pick<GenericMutationCtx<GenericDataModel>, "runMutation">;
type ActionCtx = Pick<
  GenericActionCtx<GenericDataModel>,
  "runQuery" | "runMutation" | "runAction"
>;

/**
 * Standard Authz Client (Runtime Role Evaluation)
 */
export class Authz<C extends AuthzConfig<any>> {
  public readonly validators = {
    role: v.string() as Validator<RoleName<C>>,
    permission: v.string() as Validator<PermissionString<C>>,
  };

  constructor(
    public component: ComponentApi,
    public config: C,
    public options: AuthzOptions = {}
  ) { }

  /**
   * Helper to build the mapping of role -> permissions for the backend
   */
  protected getRolePermissionsMap(): Record<string, string[]> {
    const map: Record<string, string[]> = {};
    for (const [role, def] of Object.entries(this.config.roles)) {
      map[role] = def.permissions;
    }
    return map;
  }

  /**
   * Parse a role string to determine its scope
   */
  protected parseRole(role: string, scopeId?: string): { role: string; scope?: Scope } {
    if (role.includes(":")) {
      const [type] = role.split(":");
      // The role name in the backend is typically stored as the full key "type:name"
      // BUT for scoped assignment, we often just want the "name" part if the system treats it that way using "by_role".
      // However, the current backend implementation of `getRolePermissionsMap` (previously) and usage implies we pass the full key.

      // We will treat the "role" passed to the backend as the FULL role name (e.g. "org:admin")
      // The "scope" object is context for WHERE it applies.
      return {
        role,
        scope: scopeId ? { type, id: scopeId } : undefined,
      };
    }
    return { role, scope: undefined };
  }

  /* --- Check Queries --- */

  /**
   * Check if user has a permission
   */
  async can(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: PermissionString<C>,
    scope?: Scope
  ): Promise<boolean> {
    return (await ctx.runQuery(this.component.queries.checkPermission, {
      userId,
      permission,
      scope,
      rolePermissions: this.getRolePermissionsMap(),
    })).allowed;
  }

  // Overload for can to support simple ID if we know the type?
  // Let's stick to explicitly passing Scope object for `can` to ensure correctness for now.
  // The User wanted "intuitive". `type` is often redundant if implied by permission resource? 
  // "documents:read" -> type "documents"? Not always. Could be "org".

  async hasRole<R extends RoleName<C> | string>(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    role: R,
    ...args: (string | Scope | undefined)[]
  ): Promise<boolean> {
    let scope: Scope | undefined;
    const firstArg = args[0];

    if (typeof firstArg === "string") {
      scope = this.parseRole(role, firstArg).scope;
    } else if (firstArg && typeof firstArg === "object" && "type" in firstArg) {
      scope = firstArg;
    } else {
      scope = this.parseRole(role).scope;
    }

    return await ctx.runQuery(this.component.queries.hasRole, {
      userId,
      role: this.parseRole(role).role, // Use parsed role name (strips prefix if needed, though usually we keep full name)
      scope,
    });
  }

  /* --- Management Mutations --- */

  async assignRole<R extends RoleName<C> | string>(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: R,
    ...args: (string | number | Scope | undefined)[]
  ): Promise<string> {
    let scope: Scope | undefined;
    let expiresAt: number | undefined;

    const firstArg = args[0];
    const secondArg = args[1];

    if (typeof firstArg === "string") {
      // (scopeId, expiresAt?)
      scope = this.parseRole(role, firstArg).scope;
      expiresAt = secondArg as number | undefined;
    } else if (firstArg && typeof firstArg === "object" && "type" in firstArg) {
      // (Scope, expiresAt?)
      scope = firstArg;
      expiresAt = secondArg as number | undefined;
    } else if (typeof firstArg === "number") {
      // (expiresAt)
      expiresAt = firstArg;
      scope = this.parseRole(role).scope;
    } else {
      scope = this.parseRole(role).scope;
    }

    return await ctx.runMutation(this.component.mutations.assignRole, {
      userId,
      role: this.parseRole(role).role,
      scope,
      expiresAt,
      assignedBy: this.options.defaultActorId,
      enableAudit: true,
    });
  }

  async revokeRole<R extends RoleName<C> | string>(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: R,
    ...args: (string | Scope | undefined)[]
  ): Promise<boolean> {
    let scope: Scope | undefined;
    const firstArg = args[0];

    if (typeof firstArg === "string") {
      scope = this.parseRole(role, firstArg).scope;
    } else if (firstArg && typeof firstArg === "object" && "type" in firstArg) {
      scope = firstArg;
    } else {
      scope = this.parseRole(role).scope;
    }

    return await ctx.runMutation(this.component.mutations.revokeRole, {
      userId,
      role: this.parseRole(role).role,
      scope,
      revokedBy: this.options.defaultActorId,
      enableAudit: true,
    });
  }

  /* --- Other Methods --- */

  /**
   * Get all roles for a user
   */
  async getUserRoles(ctx: QueryCtx | ActionCtx, userId: string, scope?: Scope): Promise<{
    role: string;
    scope?: Scope;
    expiresAt?: number;
  }[]> {
    const roles = await ctx.runQuery(this.component.queries.getUserRoles, {
      userId,
      scope,
    });

    return roles.map(r => ({
      role: r.role,
      scope: r.scope,
      expiresAt: r.expiresAt
    }));
  }

  /**
   * Grant a direct permission override
   */
  async grantPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope,
    reason?: string,
    expiresAt?: number,
    createdBy?: string
  ): Promise<string> {
    return await ctx.runMutation(this.component.mutations.grantPermission, {
      userId,
      permission,
      scope,
      reason,
      expiresAt,
      createdBy: createdBy ?? this.options.defaultActorId,
      enableAudit: true,
    });
  }

  /**
   * Deny a permission (explicit deny override)
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
    return await ctx.runMutation(this.component.mutations.denyPermission, {
      userId,
      permission,
      scope,
      reason,
      expiresAt,
      createdBy: deniedBy ?? this.options.defaultActorId,
      enableAudit: true,
    });
  }

  async getUserAttributes(ctx: QueryCtx | ActionCtx, userId: string) {
    return await ctx.runQuery(this.component.queries.getUserAttributes, {
      userId,
    });
  }

  async setAttribute(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    key: string,
    value: unknown,
    assignedBy?: string
  ): Promise<string> {
    return await ctx.runMutation(this.component.mutations.setAttribute, {
      userId,
      key,
      value,
      setBy: assignedBy ?? this.options.defaultActorId,
      enableAudit: true,
    });
  }

  async removeAttribute(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    key: string,
    removedBy?: string
  ): Promise<boolean> {
    return await ctx.runMutation(this.component.mutations.removeAttribute, {
      userId,
      key,
      removedBy: removedBy ?? this.options.defaultActorId,
      enableAudit: true,
    });
  }

  // =========================================================================
  // Dynamic Role Management
  // =========================================================================

  /**
   * Get all role definitions for a scope (system + custom roles)
   */
  async getRoleDefinitions(
    ctx: QueryCtx | ActionCtx,
    scope?: Scope
  ) {
    return await ctx.runQuery(this.component.queries.getRoleDefinitions, {
      scope,
    });
  }

  /**
   * Create a custom role for a specific scope
   */
  async createRole(
    ctx: MutationCtx | ActionCtx,
    scope: Scope,
    definition: {
      name: string;
      permissions: string[];
      parentRole?: string;
      label?: string;
      description?: string;
    }
  ): Promise<string> {
    return await ctx.runMutation(this.component.mutations.createRoleDefinition, {
      name: definition.name,
      scope,
      permissions: definition.permissions,
      parentRole: definition.parentRole,
      isSystem: false,
      label: definition.label,
      description: definition.description,
      createdBy: this.options.defaultActorId,
    });
  }

  /**
   * Update a custom role
   */
  async updateRole(
    ctx: MutationCtx | ActionCtx,
    roleId: string,
    updates: {
      permissions?: string[];
      parentRole?: string | null;
      label?: string;
      description?: string;
    }
  ): Promise<boolean> {
    return await ctx.runMutation(this.component.mutations.updateRoleDefinition, {
      roleId: roleId as any, // The component expects Id<"roleDefinitions">
      permissions: updates.permissions,
      parentRole: updates.parentRole,
      label: updates.label,
      description: updates.description,
      updatedBy: this.options.defaultActorId,
    });
  }

  /**
   * Delete a custom role
   */
  async deleteRole(
    ctx: MutationCtx | ActionCtx,
    roleId: string
  ): Promise<boolean> {
    return await ctx.runMutation(this.component.mutations.deleteRoleDefinition, {
      roleId: roleId as any, // The component expects Id<"roleDefinitions">
      deletedBy: this.options.defaultActorId,
    });
  }

  /**
   * Resolve effective permissions for a role (including hierarchy)
   */
  async resolveRolePermissions(
    ctx: QueryCtx | ActionCtx,
    roleName: string,
    scope?: Scope
  ) {
    return await ctx.runQuery(this.component.queries.resolveRolePermissions, {
      roleName,
      scope,
    });
  }
}

/**
 * Indexed Authz Client (O(1) lookups)
 */
export class IndexedAuthz<C extends AuthzConfig<any>> extends Authz<C> {
  // Override check to use fast path
  async can(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: PermissionString<C>,
    scopeId?: string | Scope
  ): Promise<boolean> {
    // For indexed lookups, scopeKey is typically "type:id" or "global"
    // We need the type.
    const scope = typeof scopeId === 'object' ? scopeId : undefined;

    return await ctx.runQuery(this.component.indexed.checkPermissionFast, {
      userId,
      permission,
      objectType: scope?.type,
      objectId: scope?.id,
    });
  }

  // Override hasRole to use fast path
  async hasRole<R extends RoleName<C> | string>(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    role: R,
    ...args: (string | Scope | undefined)[]
  ): Promise<boolean> {
    let scope: Scope | undefined;
    const firstArg = args[0];

    if (typeof firstArg === "string") {
      scope = this.parseRole(role, firstArg).scope;
    } else if (firstArg && typeof firstArg === "object" && "type" in firstArg) {
      scope = firstArg;
    } else {
      scope = this.parseRole(role).scope;
    }

    return await ctx.runQuery(this.component.indexed.hasRoleFast, {
      userId,
      role: this.parseRole(role).role,
      objectType: scope?.type,
      objectId: scope?.id,
    });
  }

  async assignRole<R extends RoleName<C> | string>(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    role: R,
    ...args: (string | number | Scope | undefined)[]
  ): Promise<string> {
    let scope: Scope | undefined;
    let expiresAt: number | undefined;

    const firstArg = args[0];
    const secondArg = args[1];

    if (typeof firstArg === "string") {
      scope = this.parseRole(role, firstArg).scope;
      expiresAt = secondArg as number | undefined;
    } else if (firstArg && typeof firstArg === "object" && "type" in firstArg) {
      scope = firstArg;
      expiresAt = secondArg as number | undefined;
    } else if (typeof firstArg === "number") {
      expiresAt = firstArg;
      scope = this.parseRole(role).scope;
    } else {
      scope = this.parseRole(role).scope;
    }

    const { role: parsedRoleName } = this.parseRole(role);
    const rolePermissions = this.config.roles[parsedRoleName]?.permissions || [];

    return await ctx.runMutation(this.component.indexed.assignRoleWithCompute, {
      userId,
      role: parsedRoleName,
      rolePermissions: rolePermissions,
      scope,
      expiresAt,
      assignedBy: this.options.defaultActorId,
    });
  }

  async getUserRoles(ctx: QueryCtx | ActionCtx, userId: string, scope?: Scope) {
    const scopeKey = scope ? `${scope.type}:${scope.id}` : undefined;
    return await ctx.runQuery(this.component.indexed.getUserRolesFast, {
      userId,
      scopeKey,
    });
  }

  async grantPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: string,
    scope?: Scope,
    reason?: string,
    expiresAt?: number,
    createdBy?: string
  ): Promise<string> {
    return await ctx.runMutation(this.component.indexed.grantPermissionDirect, {
      userId,
      permission,
      scope,
      reason,
      expiresAt,
      grantedBy: createdBy ?? this.options.defaultActorId,
    });
  }

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
      expiresAt,
      deniedBy: deniedBy ?? this.options.defaultActorId,
    });
  }
}
