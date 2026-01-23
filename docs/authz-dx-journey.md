so i wanted to make an authz library for a bunch of projects i've been working on

What followed was a refusal to choose between correctness and developer joy. Authorization is not a single model. It is RBAC for comfort, ABAC for nuance, and ReBAC for real-world graphs. The library had to embrace all three without making people learn a new language to use them.

## Executive view

The core promise is simple: make the safe thing the easy thing.

- The library provides a Convex-native authorization component with RBAC, ABAC, and ReBAC in one surface area.
- It offers two strategies: standard checks for simplicity and indexed checks for scale, both with the same API.
- The public interface is TypeScript-first: permission selectors, typed role configs, and patterns that reduce stringly-typed drift.
- Checks can be explained, audited, and scoped. There is a clear difference between allowed, denied, and why.

If you are evaluating it as an executive decision: this is a practical, TS-native, Convex-native alternative to policy engines that require a separate DSL or service. It is not just a “policy file”; it is a runtime and a modeling system.

## What the library actually provides vs the README

The README promises RBAC, ABAC, ReBAC, O(1) lookups, and type safety. The implementation does, but with some important nuance:

- RBAC is both static (defined roles) and dynamic (custom roles via roleDefinitions) with scoped assignments and expirations.
- ABAC is policy-driven, but policy evaluation is a client-side layer on top of the core RBAC check. The backend core checks roles and overrides; policies are an additional filter that you opt into.
- ReBAC is full graph relationships, including traversal, and supports indexed fast-path reads for relationship checks.
- Indexed mode is Zanzibar-like: precomputed effective permissions and roles with O(1) checks, at the cost of heavier writes.

We aligned the DX so there is only one path:

- `authzConfig` is the single config builder and it accepts one shape.
- Roles always use a `grants` map (resource → actions); no multiple input formats.
- Policies are always keyed by permission patterns and evaluated explicitly.

The intent is to make the README examples feel like real code you can ship, not aspirational pseudocode.

## Design philosophy, Socratic version

Question: Do we want a policy DSL?
Answer: Only if it makes the system safer. In a TS-first codebase, a new DSL usually fragments type safety. So policies are TypeScript functions, but the policy context is explicit and typed.

Question: Should authorization be just a boolean?
Answer: Not if you expect teams to debug production incidents. The API surfaces `explain` with a `CheckResult` that includes reason and policy decisions, while `can` remains the simple boolean.

Question: Should “admin” checks be a wildcard?
Answer: Yes for role definitions, no for runtime checks. Use wildcards in role or override configuration, but make runtime checks explicit actions so it is impossible to “accidentally allow anything”.

Question: How do we avoid the “stringly-typed permission” trap?
Answer: Generate a `P` selector object and accept both selectors and strings in the API, with selectors being the default path.

## The API shape (the piece developers feel)

Configuration and usage are separate on purpose. Configuration is a pure, typed description of the world. Usage is a fluent, readable check surface.

```ts
import {
  authzConfig,
  createAuthz,
} from "@djpanda/convex-authz";
import { components } from "./_generated/api";

const config = authzConfig({
  permissions: {
    documents: ["read", "write", "delete"],
    org: ["manage_members", "manage_billing"],
  },
  roles: {
    admin: {
      grants: {
        documents: ["*"],
        org: ["*"],
      },
    },
    "org:member": {
      grants: {
        documents: ["read"],
      },
    },
  },
  policies: {
    "documents:delete": {
      condition: (ctx) => ctx.hasRole("admin") || ctx.getAttribute("canDelete") === true,
      message: "Deleting documents requires admin or explicit clearance.",
    },
  },
  allowCustomRoles: true,
});

export const { authz, P } = createAuthz(components.authz, config);
```

Now the usage feels like intent, not plumbing:

```ts
const scope = { type: "org", id: orgId };

await authz.can(userId)
  .perform(P.documents.write)
  .in(scope)
  .withResource({ type: "document", id: docId, attributes: { ownerId } })
  .check(ctx);

await authz.require(ctx, userId, P.org.manage_members, scope);
const decision = await authz.explain(ctx, userId, P.documents.delete, {
  scope,
  audit: true,
});
```

DX decisions embedded in that surface:

- `P` is always typed from your permissions; no “wrong string” footguns.
- `authzConfig` is the only configuration entry point, so there is no “which format?” debate.
- `PermissionBuilder` is composable and discoverable, with clear escape hatches.
- `require` throws a structured `ConvexError` with a reason and context.

## ABAC, but not magic

Policy evaluation is explicit. If you want attribute-driven checks, you opt into `policies` and provide the resource/subject context when checking.

```ts
await authz.can(userId)
  .perform(P.documents.write)
  .withResource({
    type: "document",
    id: docId,
    attributes: { ownerId, classification: "internal" },
  })
  .withSubject({ attributes: { clearanceLevel: 3 } })
  .check(ctx);
```

This keeps the system honest: ABAC does not silently override your RBAC model. It is additive and explainable.

## Indexed vs standard strategy

The standard strategy is minimal ceremony and minimal storage. It computes permissions at check time using your role definitions and overrides.

The indexed strategy shifts the work to writes and keeps reads constant time. It precomputes effective roles and permissions (and relations) so read paths are just indexed lookups. It is what you want when your read volume dwarfs your writes.

You do not change your application code; you change a strategy flag.

## Real-world pain and the fixes

Pain: “We ship 100 features, and every permission string drifts.”
Fix: `authzConfig`, `P` selectors, and role definitions that are validated by the compiler.

Pain: “We can not explain why access was denied in production.”
Fix: `explain` with a structured `CheckResult` and optional audit logs.

Pain: “We need org-scoped admin roles, but global roles still exist.”
Fix: explicit `Scope` and scoped role assignment, plus scope-aware checks in both standard and indexed strategies.

Pain: “Policy engines make us write two languages.”
Fix: ABAC policies are TypeScript functions with an explicit context object.

## Struggles worth admitting

Authorization libraries fail for boring reasons, not clever ones.

- The first failure is naming: who owns “admin”, and is it global or scoped?
- The second is drift: permissions are strings, and strings are a slow, quiet source of bugs.
- The third is explanation: an “access denied” without a reason is a ticket that never ends.

The design goal became: minimize ambiguity, make intent obvious, and make the system explain itself.

## Tricks that save time (and make reviews faster)

### 1) Prefer permission selectors in runtime checks

```ts
await authz.require(ctx, userId, P.documents.write);
```

If you ever need a string, it is still allowed. But default to selectors so the compiler keeps you honest.

### 2) Use inheritance for clean hierarchies

```ts
const config = authzConfig({
  permissions: {
    documents: [\"read\", \"write\"],
  },
  roles: {
    viewer: { grants: { documents: [\"read\"] } },
    editor: {
      inherits: \"viewer\",
      grants: { documents: [\"write\"] },
    },
  },
});
```

This avoids repeating “viewer” permissions everywhere and keeps diffs tight.

### 3) Use wildcard policies sparingly, but deliberately

```ts
const config = authzConfig({
  permissions: {
    documents: [\"read\", \"write\"],
  },
  roles: {
    viewer: { grants: { documents: [\"read\"] } },
  },
  policies: {
    \"*:*\": {
      effect: \"deny\",
      condition: (ctx) => ctx.getAttribute(\"suspended\") === true,
      message: \"Account suspended.\",
    },
  },
});
```

Global policies are powerful. Use them for cross-cutting rules like compliance or suspension.

### 4) Get an explanation before you change code

```ts
const decision = await authz.explain(ctx, userId, P.documents.delete, {
  scope: { type: \"org\", id: orgId },
  audit: true,
});

// decision.reason -> human-readable
// decision.policy -> which policy fired
```

This is the difference between a quick fix and a two-day permission hunt.

### 5) Switch strategies without changing app logic

```ts
export const { authz, P } = createAuthz(
  components.authz,
  authzConfig({ permissions, roles }),
  { strategy: \"indexed\" }
);
```

The API stays constant. The performance profile changes.

## Comparisons (modern authorization libraries)

- OpenFGA: Strong Zanzibar model with a dedicated DSL. Great for cross-service policy sharing, but it adds a separate schema language and service boundary. This library stays inside Convex and uses TypeScript as the policy surface.
- Oso: Powerful policy engine with a dedicated language (Polar). Great expressiveness, but another language to teach your team. This library is TS-native, at the cost of losing some static policy analysis.
- Cerbos: YAML-driven policies and good auditability. Good for governance-centric orgs. This library favors developer ergonomics and direct integration rather than external policy files.
- Casbin: Mature and flexible, but string-based in practice and not Convex-specific. This library is scoped for Convex and makes selectors first-class.

If you want a language-agnostic policy service, look elsewhere. If you want a Convex-first, TypeScript-first authorization layer with an ergonomic API, this is the point.

## Patterns borrowed from production code

A few patterns are worth copying from real production systems:

- Safe vs throwing APIs (`can` vs `require`) so code reads like intent.
- A single facade that returns everything developers need (`authz`, `P`, plus typed configs).
- Explicit separation of configuration, runtime checks, and internal helpers.

These patterns keep the library predictable while still allowing advanced use cases.

## The biggest lesson

Authorization is not a model. It is an interface. If the interface is frictionless, teams use it consistently, and the system stays honest. If the interface is clunky, the system devolves into “just this one check” escape hatches.

The goal is not just correctness; it is a culture of correctness that survives product velocity.
