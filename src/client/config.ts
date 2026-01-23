import type {
  AuthzConfig,
  AuthzConfigDefinition,
  PermissionsConfig,
  RoleDefinition,
  RoleGrantsMap,
  RolesConfig,
  NormalizedRoleDefinition,
  NormalizedRolesConfig,
  PermissionInput,
  PermissionString,
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

export function authzConfig<const P extends PermissionsConfig>(
  config: AuthzConfigDefinition<P>
): AuthzConfig<P> {
  return {
    ...config,
    roles: normalizeRoles(config.permissions, config.roles),
  };
}

export function normalizeRoleGrants<P extends PermissionsConfig>(
  input: RoleGrantsMap<P>
): ValidPermissionPattern<P>[] {
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
  role: RoleDefinition<P>
): NormalizedRoleDefinition<P> {
  return {
    grants: normalizeRoleGrants(role.grants),
    label: role.label,
    description: role.description,
    inherits: role.inherits,
  };
}

export function normalizeRoles<P extends PermissionsConfig>(
  permissions: P,
  roles: RolesConfig<P>
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
