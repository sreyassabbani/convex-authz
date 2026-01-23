import type { PolicyContext } from "../component/helpers.js";

/**
 * Configuration of Resources and their valid actions.
 * Uses `readonly` arrays to preserve literal types for type safety.
 * Example: { documents: ["read", "write"] as const }
 */
export type PermissionsConfig<DataModel extends Record<string, unknown> = Record<string, unknown>> = {
  readonly [T in keyof DataModel & string]: readonly string[];
};

type AllActions<P extends PermissionsConfig> = P[keyof P & string][number] & string;

/**
 * Derive all valid permission patterns from a PermissionsConfig.
 * This includes:
 * - Exact permissions: "documents:read", "documents:write"
 * - Resource wildcards: "documents:*"
 * - Global wildcard: "*"
 */
export type ValidPermissionPattern<P extends PermissionsConfig> =
  | "*"
  | "*:*"
  | `*:${AllActions<P>}`
  | {
    [K in keyof P & string]: P[K] extends readonly (infer A extends string)[]
    ? `${K}:${A}` | `${K}:*`
    : never;
  }[keyof P & string];

/**
 * Resource -> actions mapping for a role, e.g. { documents: ["read", "update"] }
 */
export type RoleGrantsMap<P extends PermissionsConfig> = {
  readonly [K in keyof P & string]?: readonly (P[K][number] | "*")[];
};

/**
 * Definition of a single role, with type-safe permissions.
 * The permissions array is constrained to valid patterns derived from the PermissionsConfig.
 */
export type RoleDefinition<P extends PermissionsConfig> = {
  /**
   * Resource-based grants for this role.
   * Each entry is a list of allowed actions or "*".
   */
  grants: RoleGrantsMap<P>;
  /**
   * Optional human-readable label
   */
  label?: string;
  /**
   * Optional description
   */
  description?: string;
  /**
   * Optional parent role (static hierarchy).
   */
  inherits?: string;
};

/**
 * Configuration of Roles, typed against the PermissionsConfig.
 * Keys can be namespaced (e.g. "org:admin") or global (e.g. "superadmin").
 */
export type RolesConfig<P extends PermissionsConfig> = Record<string, RoleDefinition<P>>;

/**
 * Normalized role definition (permissions array only).
 */
export type NormalizedRoleDefinition<P extends PermissionsConfig> = {
  grants: ValidPermissionPattern<P>[];
  label?: string;
  description?: string;
  inherits?: string;
};

export type NormalizedRolesConfig<P extends PermissionsConfig> = Record<string, NormalizedRoleDefinition<P>>;

/**
 * Attribute values for ABAC policies.
 */
export type AttributeValue =
  | string
  | number
  | boolean
  | null
  | Array<string | number | boolean | null>
  | Record<string, string | number | boolean | null>;

export type Attributes = Record<string, AttributeValue>;

export interface ResourceContext {
  type: string;
  id: string;
  attributes?: Attributes;
}

export interface SubjectContextInput {
  roles?: string[];
  attributes?: Attributes;
}

export interface EnvironmentContext {
  ip?: string;
  timestamp?: number;
}

export interface RelationInput {
  subjectType: string;
  subjectId: string;
  relation: string;
  objectType: string;
  objectId: string;
  inheritedRelations?: Array<{
    relation: string;
    fromObjectType: string;
    fromRelation: string;
  }>;
  createdBy?: string;
}

export type PolicyEffect = "allow" | "deny";

export interface PolicyDefinition {
  condition: (ctx: PolicyContext) => boolean | Promise<boolean>;
  effect?: PolicyEffect;
  message?: string;
}

export type PoliciesConfig<P extends PermissionsConfig> = Partial<
  Record<ValidPermissionPattern<P>, PolicyDefinition>
>;

/**
 * Main Authz Configuration
 */
export interface AuthzConfig<P extends PermissionsConfig = PermissionsConfig> {
  permissions: P;
  roles: NormalizedRolesConfig<P>;
  policies?: PoliciesConfig<P>;
  allowCustomRoles?: boolean;
}

export interface AuthzConfigDefinition<P extends PermissionsConfig = PermissionsConfig> {
  permissions: P;
  roles: RolesConfig<P>;
  policies?: PoliciesConfig<P>;
  allowCustomRoles?: boolean;
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
  /**
   * Whether to audit permission checks by default.
   */
  auditChecks?: boolean;
}

/**
 * Extract all valid role names from the config
 */
export type RoleName<P extends PermissionsConfig> = keyof RolesConfig<P> & string;

/**
 * Extract all valid permission strings from the config
 * e.g., "documents:read"
 */
export type PermissionString<P extends PermissionsConfig> = {
  [R in keyof P & string]: `${R}:${P[R][number] & string}`;
}[keyof P & string];

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

/**
 * A typed permission selector (e.g. P.threads.read)
 */
export interface PermissionSelector<Resource extends string, Action extends string> {
  resource: Resource;
  action: Action;
}

/**
 * Type helper to generate the structure of 'P' from PermissionsConfig
 */
export type Selectors<P extends PermissionsConfig> = {
  [R in keyof P & string]: {
    [A in P[R][number] & string]: PermissionSelector<R, A>;
  } & {
    /**
     * Wildcard selector for this resource (e.g. "threads:*")
     */
    ALL: PermissionSelector<R, "*">;
  };
};

export type PermissionSelectorFor<P extends PermissionsConfig> = {
  [R in keyof P & string]: {
    [A in P[R][number] & string]: PermissionSelector<R, A>;
  }[P[R][number] & string];
}[keyof P & string];

export type PermissionInput<P extends PermissionsConfig> =
  | PermissionString<P>
  | PermissionSelectorFor<P>;

export interface CheckOptions<P extends PermissionsConfig> {
  scope?: Scope;
  resource?: ResourceContext;
  subject?: SubjectContextInput;
  environment?: EnvironmentContext;
  audit?: boolean;
}

export interface PolicyDecision {
  key: string;
  effect: PolicyEffect;
  passed: boolean;
  message?: string;
}

export interface CheckResult {
  allowed: boolean;
  reason: string;
  matchedRole?: string;
  matchedOverride?: string;
  policy?: PolicyDecision;
}

export type { PolicyContext };
