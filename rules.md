# Rego Language Best Practices and Patterns

This document captures high-level patterns and conventions for writing effective Rego policies. These are construct patterns and architectural best practices, not syntax formatting rules.

## Structural Patterns

- **Match package name to file location**: Package names should reflect directory structure. Use consistent convention throughout project (e.g., `foo/bar.rego` → `package foo.bar`).

- **Use lowercase dot notation for package hierarchy**: Follow pattern `organization.domain.purpose` (e.g., `kubernetes.admission`, `rbac.authz`, `terraform.analysis`).

- **Separate concerns by package**: Keep related rules in same package. Use separate packages for different policy domains to enable team collaboration through clear boundaries.

- **Standard module layout**: Organize modules consistently:
  1. METADATA annotations at package level
  2. Package declaration
  3. Imports
  4. Constants and configuration
  5. Helper rules and functions
  6. Main policy rules (with entrypoint annotation)

- **Mark main decision rules with entrypoint**: Use `# METADATA` with `entrypoint: true` to document which rules are meant to be queried externally. Enables automatic compilation and helps tools understand policy structure.

- **Co-locate tests with policies**: Place test files in same directory as policy files. Use `_test.rego` suffix and `package_name_test` for test package names.

## Composition Patterns

- **Prefer multi-value rules over comprehensions**: Use set/object generating rules instead of top-level comprehensions. This enables extensibility—multiple rules can contribute to same result. Better for readability and debuggability.

- **Extract repeated conditions into helper rules**: Improves readability, performance (via memoization), and testability. Use descriptive names with `is_` or `has_` prefix for boolean helpers.

- **Use negation with helper rules for deny-by-default**: Pattern like `deny contains msg if not authenticated_user` handles both undefined and false cases, critical for security policies.

- **Compose logical AND implicitly**: Multiple statements in rule body are implicitly AND'd. Each must succeed for rule to succeed.

- **Compose logical OR through multiple rule definitions**: Define multiple rules with same head. Any rule succeeding makes overall rule succeed.

- **Use `else` for ordered evaluation**: When first-match semantics needed, earlier conditions take precedence. Use for fallback logic.

- **Use `every` for universal quantification**: Express "for all" logic clearly instead of double-negation patterns. Example: `every container in containers { condition }`.

- **Prefer pure functions with explicit arguments**: Pass data as arguments rather than referencing `input`/`data` directly. Easier to test standalone, clear dependencies.

- **Use assignment (`:=`) for function returns**: Avoid last-argument return pattern. Makes return value explicit.

## Design Patterns

- **Default deny for security policies**: Start with `default allow := false` and enumerate only safe conditions. Prevents unknown dangerous actions.

- **Default allow with deny override (hybrid)**: Pattern `authz if { allow; not deny }` combines allowlist and denylist approaches.

- **RBAC pattern**: Map users to roles, roles to permissions. Check if requested action matches assigned permissions.

- **ABAC pattern**: Make decisions based on attributes of user, resource, and environment. Example: check user title, resource exchange, and transaction amount.

- **Multiple validation rules with structured errors**: Build set of error messages. Pattern: `errors contains msg if { condition; msg := "..." }` then `valid if count(errors) == 0`.

- **Deny pattern for admission control**: Generate set of violation messages. Pattern: `deny contains msg if { violation_check; msg := sprintf("...", [...]) }`.

- **Filtering with set comprehensions**: Extract subset matching criteria. Pattern: `active_users := {user | user := input.users[_]; user.status == "active"}`.

- **Aggregation with object rules**: Group and aggregate data. Pattern: `total_by_key[key] := sum if { ... }`.

- **Mock data in tests with `with` keyword**: Replace input or data for testing. Pattern: `rule with input as mock_input with data.config as mock_config`.

## Best Practices

- **Optimize for readability, not performance**: Write declarative code expressing what, not how. Let OPA handle optimization. Only optimize if actual performance issues identified.

- **Use `if` keyword**: Explicitly separates rule head from body. Required in Rego v1, recommended everywhere for clarity.

- **Use `in` for membership**: Clearer and less error-prone than iteration + comparison. Pattern: `"admin" in input.user.roles` instead of `"admin" == input.user.roles[_]`.

- **Use `some...in` for iteration**: Removes ambiguity. Pattern: `some host in data.network.hosts` instead of `host := data.network.hosts[_]`.

- **Use `contains` for set rules**: Preferred over bracket notation. Pattern: `deny contains msg if { ... }` instead of `deny[msg] { ... }`.

- **Use assignment (`:=`) and comparison (`==`)**: Avoid unification operator (`=`) except for pattern matching. Clear intent: `:=` assigns, `==` compares.

- **Declare variables explicitly with `some`**: Improves safety and clarity. Avoid undeclared variables.

- **Prefer sets over arrays for unordered collections**: O(1) lookups vs O(n). Enables set operations (union, intersection, difference).

- **Use schemas for type checking**: Provide JSON schemas for `input` and `data`. Catches typos and structural errors early.

- **Use metadata annotations**: Document rules with YAML comments containing title, description, links. Enables tooling and documentation generation.

- **Import packages, not specific rules**: Provides context. Example: `user.is_admin` clearer than standalone `is_admin`. Exception: rename `input` for context (e.g., `import input as tfplan`).

- **Avoid importing input**: Keep `input` references explicit. Clear distinction from local variables. Exception: contextual renames.

- **Use leading underscore for internal helpers**: Communicates intended scope. Tools can leverage this convention.

- **Defer expensive assignments**: Place assignments close to where they're used. Don't compute values that might not be needed. Check cheap conditions first.

- **Use `opa fmt` on save and in CI/CD**: Ensures consistent formatting across teams.

- **Use `opa check --strict`**: Catches unused imports and variables. Identifies common mistakes early.

- **Write comprehensive tests**: Test both positive and negative cases. Use `with` for mocking. Target high coverage for critical policies.

- **Use Regal linter**: Enforces style guide, identifies bugs and anti-patterns. Integrate with CI/CD.

## Anti-patterns

- **Top-level iteration without assignment**: Pattern `user := input.users[_]` at top level will fail with multiple items. Use in rule body instead.

- **Constant conditions**: Pattern `allow if 1 == 1` provides no logic value. Every rule should check meaningful conditions.

- **Undeclared variables in comprehensions**: Always declare iteration variables with `some`. Pattern: `some topic` before using in comprehension.

- **Unification for simple operations**: Don't use `=` for assignment or comparison. Use `:=` for assignment, `==` for comparison.

- **Non-raw regex patterns**: Use raw strings for regex to avoid double escaping. Pattern: `` regex.match(`[\d]+`, "12345") `` instead of `"[\\d]+"`.

- **Top-level comprehensions for extensibility**: Set/object generating rules are preferred over top-level comprehensions as they can be extended across files.

- **Missing error handling for undefined values**: Handle missing values explicitly. Use pattern `if not helper` where `helper` checks for presence.

- **Default allow for security policies**: For security-critical decisions, use default deny. Default allow permits unknown dangerous actions.

- **Missing input validation**: Don't assume input structure. Use schemas or explicit checks to handle malformed input gracefully.

- **Overly permissive wildcards**: Be specific about what's allowed. Enumerate safe conditions explicitly rather than using broad wildcards.

## Conventions

- **Use `snake_case` for all identifiers**: Rules, functions, variables, and constants all use snake_case naming.

- **Use descriptive, action-oriented names**: Prefer clarity over brevity. Use `is_` or `has_` prefix for boolean helpers.

- **Avoid unnecessary prefixes**: Don't use `get_` or `list_` prefixes (implied by Rego semantics).

- **Package naming hierarchy**: Use lowercase, dot-separated hierarchy matching organization/domain structure.

- **Test naming convention**: Prefix tests with `test_`. Make names descriptive of what's being tested.

- **Keep line length ≤ 120 characters**: Break long comprehensions and expressions across multiple lines for readability.

- **Separate policy from data**: Store configuration and permissions in `data`. Reference from policy rules. Enables data updates without policy changes.

- **Use external data sources judiciously**: Balance freshness vs. performance when pulling runtime data. Use caching for expensive operations.

- **Feature flags for gradual rollout**: Use data-driven flags to enable/disable new rules during transitions.

- **Semantic versioning for policies**: Track breaking vs. non-breaking changes. Document policy version in metadata.

- **Maintain backward compatibility**: Avoid breaking changes when possible. Use deprecation warnings and provide migration paths.

## Architectural Conventions

- **Separation of concerns across packages**: Split policy by domain. Use imports to compose larger decisions from domain-specific packages.

- **Team collaboration pattern**: Allow team packages to contribute to main decision. Main package imports and combines team decisions.

- **Layered architecture**: Structure as base layer (utilities), domain layer (domain-specific rules), decision layer (compose domains).

- **Policy-as-code in version control**: Treat policies as code. Use pull requests, code review, CI/CD testing before deployment.

- **Document public API with entrypoint metadata**: Mark externally-queried rules to document the policy's public interface.
