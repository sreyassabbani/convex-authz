export type { ComponentApi } from "../component/_generated/component.js";
export type { PolicyContext } from "../component/helpers.js";

export {
  createAuthz,
  Authz,
  IndexedAuthz,
  PermissionBuilder,
} from "./authz.js";

export {
  createSelectors,
  authzConfig,
} from "./config.js";

export type {
  PermissionsConfig,
  ValidPermissionPattern,
  RoleGrantsMap,
  RoleDefinition,
  RolesConfig,
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
  AuthzConfigDefinition,
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
