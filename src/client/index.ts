export type { ComponentApi } from "../component/_generated/component.js";
export type { PolicyContext } from "../component/helpers.js";

export {
  defineAuthz,
  Authz,
  IndexedAuthz,
  PermissionBuilder,
} from "./authz.js";

export {
  createSelectors,
  definePermissions,
  defineRoles,
  definePolicies,
} from "./config.js";

export type {
  PermissionsConfig,
  PermissionsMap,
  PermissionsFromMap,
  ValidPermissionPattern,
  RolePermissionsMap,
  RolePermissionsInput,
  RoleDefinition,
  RolesConfig,
  RoleInput,
  RolesConfigInput,
  NormalizedRoleDefinition,
  NormalizedRolesConfig,
  AttributeValue,
  Attributes,
  ResourceContext,
  SubjectContextInput,
  EnvironmentContext,
  RelationInput,
  PolicyEffect,
  PolicyDefinition,
  PoliciesConfig,
  AuthzConfig,
  AuthzConfigInput,
  AuthzOptions,
  RoleName,
  PermissionString,
  ScopeName,
  ScopeArgs,
  Scope,
  PermissionSelector,
  Selectors,
  PermissionSelectorFor,
  PermissionInput,
  CheckOptions,
  PolicyDecision,
  CheckResult,
} from "./types.js";
