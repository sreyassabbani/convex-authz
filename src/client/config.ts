import type {
  PermissionsConfig,
  PermissionsMap,
  PermissionsFromMap,
  RoleDefinition,
  RoleInput,
  RolePermissionsInput,
  RolePermissionsMap,
  RolesConfigInput,
  NormalizedRoleDefinition,
  NormalizedRolesConfig,
  PermissionInput,
  PermissionString,
  PoliciesConfig,
  Selectors,
  ValidPermissionPattern,
} from "./types.js";

/**
 * Helper to generate the runtime 'P' object
 */
export function createSelectors<const P extends PermissionsConfig>(permissions: P): Selectors<P> {
  const selectors: Partial<Selectors<P>> = {};

  for (const resource of Object.keys(permissions)) {
    const actions = permissions[resource];
    const resourceSelectors: Record<string, { resource: string; action: string }> = {
      ALL: { resource, action: "*" }
    };
    for (const action of actions) {
      resourceSelectors[action] = { resource, action };
    }
    (selectors as Record<string, Record<string, { resource: string; action: string }>>)[resource] = resourceSelectors;
  }

  return selectors as Selectors<P>;
}

export function definePermissions<const P extends PermissionsConfig>(permissions: P): P;
export function definePermissions<const M extends PermissionsMap>(
  permissions: M
): PermissionsFromMap<M>;
export function definePermissions(
  permissions: PermissionsConfig | PermissionsMap
) {
  const normalized: Record<string, readonly string[]> = {};

  for (const [resource, value] of Object.entries(permissions)) {
    if (Array.isArray(value)) {
      normalized[resource] = value;
      continue;
    }
    if (value && typeof value === "object") {
      normalized[resource] = Object.keys(value);
      continue;
    }
    throw new Error(`Invalid permissions for resource "${resource}".`);
  }

  return normalized;
}

export function definePolicies<const P extends PermissionsConfig>(
  policies: PoliciesConfig<P>
): PoliciesConfig<P>;
export function definePolicies<const P extends PermissionsConfig>(
  _permissions: P,
  policies: PoliciesConfig<P>
): PoliciesConfig<P>;
export function definePolicies<const P extends PermissionsConfig>(
  arg1: P | PoliciesConfig<P>,
  arg2?: PoliciesConfig<P>
): PoliciesConfig<P> {
  if (arg2) {
    return arg2;
  }
  return arg1 as PoliciesConfig<P>;
}

export function defineRoles<const P extends PermissionsConfig>(
  permissions: P,
  roles: RolesConfigInput<P>
): NormalizedRolesConfig<P> {
  return normalizeRoles(permissions, roles);
}

export function normalizeRolePermissions<P extends PermissionsConfig>(
  input: RolePermissionsInput<P>
): ValidPermissionPattern<P>[] {
  if (Array.isArray(input)) {
    return Array.from(new Set(input));
  }

  const patterns: string[] = [];
  for (const [resource, actions] of Object.entries(input)) {
    if (!actions) continue;
    for (const action of actions) {
      patterns.push(action === "*" ? `${resource}:*` : `${resource}:${action}`);
    }
  }

  return Array.from(new Set(patterns)) as ValidPermissionPattern<P>[];
}

function normalizeRoleDefinition<P extends PermissionsConfig>(
  role: RoleInput<P>
): NormalizedRoleDefinition<P> {
  if (Array.isArray(role)) {
    return { permissions: Array.from(new Set(role)) as ValidPermissionPattern<P>[] };
  }

  if (typeof role === "object" && role !== null && "permissions" in role) {
    const def = role as RoleDefinition<P>;
    return {
      permissions: normalizeRolePermissions(def.permissions),
      label: def.label,
      description: def.description,
      parentRole: def.parentRole,
    };
  }

  return {
    permissions: normalizeRolePermissions(role as RolePermissionsMap<P>),
  };
}

export function normalizeRoles<P extends PermissionsConfig>(
  permissions: P,
  roles: RolesConfigInput<P>
): NormalizedRolesConfig<P> {
  const normalized: NormalizedRolesConfig<P> = {};
  void permissions;

  for (const [roleName, roleDef] of Object.entries(roles)) {
    normalized[roleName] = normalizeRoleDefinition(roleDef);
  }

  return normalized;
}

export function normalizePermissionInput<P extends PermissionsConfig>(
  permission: PermissionInput<P>
): PermissionString<P> {
  if (typeof permission === "string") {
    return permission as PermissionString<P>;
  }
  return `${permission.resource}:${permission.action}` as PermissionString<P>;
}
