import type {
  GenericActionCtx,
  GenericDataModel,
  GenericMutationCtx,
  GenericQueryCtx,
} from "convex/server";
import { ConvexError, v, type Validator, type Value } from "convex/values";
import type { ComponentApi } from "../component/_generated/component.js";
import type { Id } from "../component/_generated/dataModel.js";
import {
  createPolicyContext,
  matchesPermissionPattern,
  parsePermission,
} from "../component/helpers.js";
import {
  createSelectors,
  normalizePermissionInput,
  normalizeRoleGrants,
} from "./config.js";
import type {
  AttributeValue,
  Attributes,
  AuthzConfig,
  AuthzOptions,
  CheckOptions,
  CheckResult,
  EnvironmentContext,
  PermissionInput,
  PermissionString,
  PolicyDecision,
  PolicyDefinition,
  RelationInput,
  ResourceContext,
  RoleName,
  RoleGrantsMap,
  PermissionsConfig,
  Scope,
  SubjectContextInput,
  ValidPermissionPattern,
} from "./types.js";

// ============================================================================
// Client Classes
// ============================================================================

type QueryCtx = Pick<GenericQueryCtx<GenericDataModel>, "runQuery">;
type MutationCtx = Pick<GenericMutationCtx<GenericDataModel>, "runMutation">;
type ActionCtx = Pick<
  GenericActionCtx<GenericDataModel>,
  "runQuery" | "runMutation" | "runAction"
>;

function isScope(value: unknown): value is Scope {
  return !!value
    && typeof value === "object"
    && "type" in value
    && "id" in value;
}

/**
 * Fluent Builder for Permission Checks
 */
export class PermissionBuilder<P extends PermissionsConfig> {
  private permission?: PermissionString<P>;
  private options: CheckOptions<P> = {};

  constructor(
    private authz: Authz<P>,
    private userId: string
  ) { }

  /**
   * Specify the permission to check (e.g. P.threads.read)
   */
  perform(selector: PermissionInput<P>) {
    this.permission = normalizePermissionInput(selector);
    return this;
  }

  /**
   * Specify the scope for this check (e.g. specific organization)
   */
  in(scope: Scope) {
    this.options.scope = scope;
    return this;
  }

  withResource(resource: ResourceContext) {
    this.options.resource = resource;
    return this;
  }

  withSubject(subject: SubjectContextInput) {
    this.options.subject = subject;
    return this;
  }

  withEnvironment(environment: EnvironmentContext) {
    this.options.environment = environment;
    return this;
  }

  audit(enable: boolean = true) {
    this.options.audit = enable;
    return this;
  }

  /**
   * Execute the permission check
   */
  async check(ctx: QueryCtx | ActionCtx): Promise<boolean> {
    if (!this.permission) throw new Error("No permission selector provided. Call .perform() first.");
    return this.authz.can(ctx, this.userId, this.permission, this.options);
  }

  async require(ctx: QueryCtx | ActionCtx): Promise<void> {
    if (!this.permission) throw new Error("No permission selector provided. Call .perform() first.");
    await this.authz.require(ctx, this.userId, this.permission, this.options);
  }

  async explain(ctx: QueryCtx | ActionCtx): Promise<CheckResult> {
    if (!this.permission) throw new Error("No permission selector provided. Call .perform() first.");
    return this.authz.check(ctx, this.userId, this.permission, this.options);
  }
}

/**
 * Standard Authz Client (Runtime Role Evaluation)
 */
export class Authz<P extends PermissionsConfig> {
  public readonly validators = {
    role: v.string() as Validator<RoleName<P>>,
    permission: v.string() as Validator<PermissionString<P>>,
    permissionPattern: v.string() as Validator<ValidPermissionPattern<P>>,
  };
  private roleGrantsMap?: Record<string, ValidPermissionPattern<P>[]>;

  constructor(
    public component: ComponentApi,
    public config: AuthzConfig<P>,
    public options: AuthzOptions = {}
  ) { }

  /**
   * Helper to build the mapping of role -> grants for the backend
   */
  protected getRoleGrantsMap(): Record<string, ValidPermissionPattern<P>[]> {
    if (this.roleGrantsMap) return this.roleGrantsMap;

    const map: Record<string, ValidPermissionPattern<P>[]> = {};
    const visiting = new Set<string>();

    const resolve = (roleName: string): ValidPermissionPattern<P>[] => {
      if (map[roleName]) return map[roleName];
      const def = this.config.roles[roleName];
      if (!def) return [];
      if (visiting.has(roleName)) {
        return def.grants;
      }
      visiting.add(roleName);

      const permissions = [...def.grants];
      if (def.inherits) {
        permissions.push(...resolve(def.inherits));
      }

      const deduped = Array.from(new Set(permissions));
      map[roleName] = deduped;
      visiting.delete(roleName);
      return deduped;
    };

    for (const roleName of Object.keys(this.config.roles)) {
      resolve(roleName);
    }

    this.roleGrantsMap = map;
    return map;
  }

  /**
   * Parse a role string to determine its scope
   */
  protected parseRole(role: string, scopeId?: string): { role: string; scope?: Scope } {
    if (role.includes(":")) {
      const [type] = role.split(":");
      return {
        role,
        scope: scopeId ? { type, id: scopeId } : undefined,
      };
    }
    return { role, scope: undefined };
  }

  /* --- Check Queries --- */

  /**
   * Start a fluent permission check
   * @param userId The user to check permissions for
   */
  can(userId: string): PermissionBuilder<P>;

  /**
   * Check if user has a permission
   */
  can(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: PermissionInput<P>,
    options?: Scope | CheckOptions<P>
  ): Promise<boolean>;

  can(
    arg1: string | QueryCtx | ActionCtx,
    arg2?: string,
    arg3?: PermissionInput<P>,
    arg4?: Scope | CheckOptions<P>
  ): PermissionBuilder<P> | Promise<boolean> {
    // Overload 1: can(userId) -> Builder
    if (typeof arg1 === "string" && !arg2) {
      return new PermissionBuilder(this, arg1);
    }

    // Overload 2: can(ctx, userId, permission, options) -> Promise<boolean>
    return this.check(
      arg1 as QueryCtx | ActionCtx,
      arg2 as string,
      arg3 as PermissionInput<P>,
      arg4
    ).then((result) => result.allowed);
  }

  /**
   * Internal implementation of permission checking
   */
  protected async runCheck(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: PermissionString<P>,
    scope?: Scope
  ): Promise<CheckResult> {
    return await ctx.runQuery(this.component.queries.checkPermission, {
      userId,
      permission,
      scope,
      rolePermissions: this.getRoleGrantsMap(),
    });
  }

  protected normalizeCheckOptions(
    options?: Scope | CheckOptions<P>
  ): CheckOptions<P> {
    if (!options) return {};
    if (isScope(options)) {
      return { scope: options };
    }
    return options;
  }

  protected async getUserAttributeMap(
    ctx: QueryCtx | ActionCtx,
    userId: string
  ): Promise<Attributes> {
    const attributes = await this.getUserAttributes(ctx, userId);
    const map: Attributes = {};
    for (const attribute of attributes) {
      map[attribute.key] = attribute.value as AttributeValue;
    }
    return map;
  }

  protected getPolicyForPermission(permission: string): { key: string; policy: PolicyDefinition } | null {
    const policies = this.config.policies;
    if (!policies) return null;
    if (permission in policies) {
      return { key: permission, policy: policies[permission as keyof typeof policies]! };
    }

    let best: { key: string; policy: PolicyDefinition; score: number } | null = null;
    for (const [key, policy] of Object.entries(policies)) {
      if (!policy) continue;
      if (key === permission) {
        return { key, policy };
      }
      if (!matchesPermissionPattern(permission, key)) continue;

      let score = 0;
      if (key === "*" || key === "*:*") {
        score = 0;
      } else {
        try {
          const { resource, action } = parsePermission(key);
          score = (resource === "*" ? 0 : 2) + (action === "*" ? 0 : 1);
        } catch {
          score = 0;
        }
      }

      if (!best || score > best.score) {
        best = { key, policy, score };
      }
    }

    return best ? { key: best.key, policy: best.policy } : null;
  }

  protected async applyPolicyIfNeeded(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: PermissionString<P>,
    base: CheckResult,
    options: CheckOptions<P>
  ): Promise<CheckResult> {
    const policyMatch = this.getPolicyForPermission(permission);
    if (!policyMatch) return base;

    const effect = policyMatch.policy.effect ?? "deny";
    if (effect === "deny" && !base.allowed) {
      return base;
    }
    if (effect === "allow" && base.allowed) {
      return base;
    }
    if (effect === "allow" && !base.allowed && base.matchedOverride) {
      return base;
    }

    const roles = options.subject?.roles
      ?? (await this.getUserRoles(ctx, userId, options.scope)).map((r) => r.role);
    const attributes = options.subject?.attributes
      ?? (await this.getUserAttributeMap(ctx, userId));

    const policyContext = createPolicyContext(
      userId,
      roles,
      attributes,
      permission,
      options.resource,
      { ip: options.environment?.ip }
    );

    if (options.environment?.timestamp) {
      policyContext.environment.timestamp = options.environment.timestamp;
    }

    const passed = Boolean(await policyMatch.policy.condition(policyContext));
    const decision: PolicyDecision = {
      key: policyMatch.key,
      effect,
      passed,
      message: policyMatch.policy.message,
    };

    if (effect === "deny") {
      if (!passed) {
        return {
          ...base,
          allowed: false,
          reason: policyMatch.policy.message ?? "Denied by policy",
          policy: decision,
        };
      }
      return { ...base, policy: decision };
    }

    if (passed) {
      return {
        ...base,
        allowed: true,
        reason: policyMatch.policy.message ?? "Allowed by policy",
        policy: decision,
      };
    }

    return { ...base, policy: decision };
  }

  async check(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: PermissionInput<P>,
    options?: Scope | CheckOptions<P>
  ): Promise<CheckResult> {
    const normalizedPermission = normalizePermissionInput(permission);
    const normalizedOptions = this.normalizeCheckOptions(options);
    const base = await this.runCheck(ctx, userId, normalizedPermission, normalizedOptions.scope);
    const result = await this.applyPolicyIfNeeded(ctx, userId, normalizedPermission, base, normalizedOptions);

    if (normalizedOptions.audit ?? this.options.auditChecks) {
      if ("runMutation" in ctx) {
        await ctx.runMutation(this.component.mutations.logPermissionCheck, {
          userId,
          permission: normalizedPermission,
          result: result.allowed,
          scope: normalizedOptions.scope,
          reason: result.reason,
        });
      }
    }

    return result;
  }

  async explain(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: PermissionInput<P>,
    options?: Scope | CheckOptions<P>
  ): Promise<CheckResult> {
    return this.check(ctx, userId, permission, options);
  }

  async require(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: PermissionInput<P>,
    options?: Scope | CheckOptions<P>
  ): Promise<void> {
    const result = await this.check(ctx, userId, permission, options);
    if (result.allowed) return;

    const normalizedOptions = this.normalizeCheckOptions(options);
    const scopeValue = normalizedOptions.scope
      ? ({
        type: normalizedOptions.scope.type,
        id: normalizedOptions.scope.id,
      } as Record<string, Value>)
      : undefined;

    throw new ConvexError({
      code: "FORBIDDEN",
      message: result.reason,
      permission: normalizePermissionInput(permission),
      scope: scopeValue,
    });
  }

  async hasRole<R extends RoleName<P> | string>(
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
      role: this.parseRole(role).role,
      scope,
    });
  }

  /* --- Management Mutations --- */

  async assignRole<R extends RoleName<P> | string>(
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

    return await ctx.runMutation(this.component.mutations.assignRole, {
      userId,
      role: this.parseRole(role).role,
      scope,
      expiresAt,
      assignedBy: this.options.defaultActorId,
      enableAudit: true,
    });
  }

  async revokeRole<R extends RoleName<P> | string>(
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

  async getUserPermissions(ctx: QueryCtx | ActionCtx, userId: string, scope?: Scope) {
    return await ctx.runQuery(this.component.queries.getEffectivePermissions, {
      userId,
      scope,
      rolePermissions: this.getRoleGrantsMap(),
    });
  }

  /**
   * Grant a direct permission override
   */
  async grantPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: ValidPermissionPattern<P>,
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
    permission: ValidPermissionPattern<P>,
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
    value: AttributeValue,
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
  // ReBAC Helpers
  // =========================================================================

  async addRelation(
    ctx: MutationCtx | ActionCtx,
    args: RelationInput
  ): Promise<string> {
    return await ctx.runMutation(this.component.rebac.addRelation, {
      subjectType: args.subjectType,
      subjectId: args.subjectId,
      relation: args.relation,
      objectType: args.objectType,
      objectId: args.objectId,
      createdBy: args.createdBy,
    });
  }

  async removeRelation(
    ctx: MutationCtx | ActionCtx,
    args: Omit<RelationInput, "createdBy" | "inheritedRelations">
  ): Promise<boolean> {
    return await ctx.runMutation(this.component.rebac.removeRelation, {
      subjectType: args.subjectType,
      subjectId: args.subjectId,
      relation: args.relation,
      objectType: args.objectType,
      objectId: args.objectId,
    });
  }

  async hasRelation(
    ctx: QueryCtx | ActionCtx,
    args: Omit<RelationInput, "createdBy" | "inheritedRelations">
  ): Promise<boolean> {
    return await ctx.runQuery(this.component.rebac.hasDirectRelation, {
      subjectType: args.subjectType,
      subjectId: args.subjectId,
      relation: args.relation,
      objectType: args.objectType,
      objectId: args.objectId,
    });
  }

  async getSubjectRelations(
    ctx: QueryCtx | ActionCtx,
    args: { subjectType: string; subjectId: string; objectType?: string }
  ) {
    return await ctx.runQuery(this.component.rebac.getSubjectRelations, args);
  }

  async getObjectRelations(
    ctx: QueryCtx | ActionCtx,
    args: { objectType: string; objectId: string; relation?: string }
  ) {
    return await ctx.runQuery(this.component.rebac.getObjectRelations, args);
  }

  async checkRelationWithTraversal(
    ctx: QueryCtx | ActionCtx,
    args: {
      subjectType: string;
      subjectId: string;
      relation: string;
      objectType: string;
      objectId: string;
      traversalRules?: unknown;
      maxDepth?: number;
    }
  ) {
    return await ctx.runQuery(this.component.rebac.checkRelationWithTraversal, args);
  }

  async listAccessibleObjects(
    ctx: QueryCtx | ActionCtx,
    args: {
      subjectType: string;
      subjectId: string;
      relation: string;
      objectType: string;
      traversalRules?: unknown;
    }
  ) {
    return await ctx.runQuery(this.component.rebac.listAccessibleObjects, args);
  }

  async listUsersWithAccess(
    ctx: QueryCtx | ActionCtx,
    args: {
      objectType: string;
      objectId: string;
      relation: string;
    }
  ) {
    return await ctx.runQuery(this.component.rebac.listUsersWithAccess, args);
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
   * Sync static/system roles into the roleDefinitions table.
   * Useful when allowCustomRoles is enabled.
   */
  async syncSystemRoles(ctx: MutationCtx | ActionCtx) {
    const roles = Object.entries(this.config.roles).map(([name, def]) => ({
      name,
      permissions: def.grants,
      parentRole: def.inherits,
      label: def.label,
      description: def.description,
    }));

    return await ctx.runMutation(this.component.mutations.syncSystemRoles, {
      roles,
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
      grants: RoleGrantsMap<P>;
      inherits?: string;
      label?: string;
      description?: string;
    }
  ): Promise<string> {
    return await ctx.runMutation(this.component.mutations.createRoleDefinition, {
      name: definition.name,
      scope,
      permissions: normalizeRoleGrants(definition.grants),
      parentRole: definition.inherits,
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
      grants?: RoleGrantsMap<P>;
      inherits?: string | null;
      label?: string;
      description?: string;
    }
  ): Promise<boolean> {
    return await ctx.runMutation(this.component.mutations.updateRoleDefinition, {
      roleId: roleId as Id<"roleDefinitions">,
      permissions: updates.grants ? normalizeRoleGrants(updates.grants) : undefined,
      parentRole: updates.inherits,
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
      roleId: roleId as Id<"roleDefinitions">,
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
export class IndexedAuthz<P extends PermissionsConfig> extends Authz<P> {
  protected async runCheck(
    ctx: QueryCtx | ActionCtx,
    userId: string,
    permission: PermissionString<P>,
    scope?: Scope
  ): Promise<CheckResult> {
    const allowed = await ctx.runQuery(this.component.indexed.checkPermissionFast, {
      userId,
      permission,
      objectType: scope?.type,
      objectId: scope?.id,
    });
    return {
      allowed,
      reason: allowed ? "Allowed by indexed permissions" : "No indexed permission match",
    };
  }

  async hasRole<R extends RoleName<P> | string>(
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

  async assignRole<R extends RoleName<P> | string>(
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
    const rolePermissions = this.getRoleGrantsMap()[parsedRoleName] || [];

    return await ctx.runMutation(this.component.indexed.assignRoleWithCompute, {
      userId,
      role: parsedRoleName,
      rolePermissions: rolePermissions,
      scope,
      expiresAt,
      assignedBy: this.options.defaultActorId,
    });
  }

  async revokeRole<R extends RoleName<P> | string>(
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

    const { role: parsedRoleName } = this.parseRole(role);
    const rolePermissions = this.getRoleGrantsMap()[parsedRoleName] || [];

    return await ctx.runMutation(this.component.indexed.revokeRoleWithCompute, {
      userId,
      role: parsedRoleName,
      rolePermissions,
      scope,
    });
  }

  async getUserRoles(ctx: QueryCtx | ActionCtx, userId: string, scope?: Scope): Promise<{
    role: string;
    scope?: Scope;
    expiresAt?: number;
  }[]> {
    const scopeKey = scope ? `${scope.type}:${scope.id}` : undefined;
    const roles = await ctx.runQuery(this.component.indexed.getUserRolesFast, {
      userId,
      scopeKey,
    });
    return roles.map((role) => ({
      role: role.role,
      scope: role.scope,
      expiresAt: "expiresAt" in role ? role.expiresAt : undefined,
    }));
  }

  async getUserPermissions(ctx: QueryCtx | ActionCtx, userId: string, scope?: Scope) {
    const scopeKey = scope ? `${scope.type}:${scope.id}` : undefined;
    const permissions = await ctx.runQuery(this.component.indexed.getUserPermissionsFast, {
      userId,
      scopeKey,
    });
    const roles = await this.getUserRoles(ctx, userId, scope);

    const effectByPermission = new Map<string, "allow" | "deny">();
    for (const entry of permissions) {
      if (entry.effect === "deny") {
        effectByPermission.set(entry.permission, "deny");
      } else if (!effectByPermission.has(entry.permission)) {
        effectByPermission.set(entry.permission, "allow");
      }
    }

    return {
      permissions: Array.from(effectByPermission.entries())
        .filter(([, effect]) => effect === "allow")
        .map(([permission]) => permission),
      deniedPermissions: Array.from(effectByPermission.entries())
        .filter(([, effect]) => effect === "deny")
        .map(([permission]) => permission),
      roles: roles.map((r) => r.role),
    };
  }

  async grantPermission(
    ctx: MutationCtx | ActionCtx,
    userId: string,
    permission: ValidPermissionPattern<P>,
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
    permission: ValidPermissionPattern<P>,
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

  async addRelation(
    ctx: MutationCtx | ActionCtx,
    args: RelationInput
  ): Promise<string> {
    return await ctx.runMutation(this.component.indexed.addRelationWithCompute, {
      subjectType: args.subjectType,
      subjectId: args.subjectId,
      relation: args.relation,
      objectType: args.objectType,
      objectId: args.objectId,
      inheritedRelations: args.inheritedRelations,
      createdBy: args.createdBy,
    });
  }

  async removeRelation(
    ctx: MutationCtx | ActionCtx,
    args: Omit<RelationInput, "createdBy" | "inheritedRelations">
  ): Promise<boolean> {
    return await ctx.runMutation(this.component.indexed.removeRelationWithCompute, {
      subjectType: args.subjectType,
      subjectId: args.subjectId,
      relation: args.relation,
      objectType: args.objectType,
      objectId: args.objectId,
    });
  }

  async hasRelation(
    ctx: QueryCtx | ActionCtx,
    args: Omit<RelationInput, "createdBy" | "inheritedRelations">
  ): Promise<boolean> {
    return await ctx.runQuery(this.component.indexed.hasRelationFast, {
      subjectType: args.subjectType,
      subjectId: args.subjectId,
      relation: args.relation,
      objectType: args.objectType,
      objectId: args.objectId,
    });
  }
}

// ============================================================================
// Main Factory
// ============================================================================

/**
 * Define your Authorization configuration and get a typed Client.
 */
export function createAuthz<
  const P extends PermissionsConfig,
>(
  component: ComponentApi,
  config: AuthzConfig<P>,
  options?: AuthzOptions
) {
  if (options?.strategy === "indexed") {
    const authz = new IndexedAuthz<P>(component, config, options);
    return {
      authz,
      P: createSelectors(config.permissions),
      permissions: config.permissions,
      roles: config.roles,
      policies: config.policies,
    };
  }
  const authz = new Authz<P>(component, config, options);
  return {
    authz,
    P: createSelectors(config.permissions),
    permissions: config.permissions,
    roles: config.roles,
    policies: config.policies,
  };
}
