# Rego Language Knowledge Tile

## Overview

Rego is a declarative query language designed for policy-as-code. It is the native policy language for Open Policy Agent (OPA), a general-purpose policy engine that enables unified, context-aware policy enforcement across the entire technology stack.

**Open Policy Agent (OPA)** provides:
- Policy-based control for cloud-native environments
- Decoupled policy decision-making from policy enforcement
- Unified tooling for writing, testing, and distributing policies
- Integration with Kubernetes, Docker, Terraform, HTTP APIs, and more
- Support for complex authorization models including RBAC, ABAC, and custom logic

Rego policies are declarative rules written in a high-level language that can express complex logic, perform data transformations, and make authorization decisions based on rich contextual information.

## Package Information

**Package Declaration**
Every Rego file begins with a package declaration that organizes policies into namespaces:

```rego
package kubernetes.admission
import rego.v1
```

Packages help organize related policies and prevent naming conflicts. Common package naming conventions:
- `kubernetes.admission` - Kubernetes admission control policies
- `docker.authz` - Docker authorization policies
- `terraform.analysis` - Terraform plan validation
- `httpapi.authz` - HTTP API authorization
- `rbac.authz` - Role-based access control
- `abac.authz` - Attribute-based access control

## Core Imports

Rego provides several built-in modules and supports importing external data and helper functions.

### Common Import Patterns

**Importing Input Data**
```rego
import input as tfplan
```
Assigns the entire input document to a more descriptive variable name.

**Importing External Data**
```rego
import data.kubernetes.namespaces
import data.kubernetes.ingresses
```
Imports external data loaded into OPA for policy evaluation, such as cluster state or configuration.

**OPA v1 Compatibility**
```rego
import rego.v1
```
Enables all Rego v1 keywords (`if`, `contains`, `in`, `every`) for policies running on OPA 0.55+. In OPA 1.0+, these keywords are part of the language by default and no import is required. Do **not** use `import future.keywords` — it is deprecated and cannot be combined with `import rego.v1`.

### Built-in Libraries

Rego includes several built-in libraries for common operations:
- `time.*` - Time and date operations
- `net.*` - Network operations (CIDR matching, IP parsing)
- `crypto.*` - Cryptographic operations
- `io.jwt.*` - JWT token parsing and verification
- `json.*` - JSON validation and manipulation
- `yaml.*` - YAML validation
- `strings.*` - String manipulation
- `regex.*` - Regular expression matching

## Basic Usage

Rego policies define rules that evaluate to true or false, or produce values. The most common patterns involve making authorization decisions or validating configurations.

### Authorization Decisions

The fundamental pattern for authorization:

```rego
package example.authz
import rego.v1

default allow := false

allow if {
    input.user == "admin"
}

allow if {
    input.method == "GET"
    input.user == "viewer"
}
```

### Deny Rules with Violations

Collecting multiple policy violations:

```rego
package example.validation
import rego.v1

deny contains msg if {
    not input.username
    msg := "username is required"
}

deny contains msg if {
    count(input.username) < 3
    msg := "username must be at least 3 characters"
}
```

### Data Transformation

Processing and aggregating data:

```rego
package example.transform
import rego.v1

active_users := {user |
    some user in input.users
    user.status == "active"
}

total_cost_by_team[team] := total if {
    some team
    resources := [r | some r in input.resources; r.team == team]
    costs := [r.cost | some r in resources]
    total := sum(costs)
}
```

## Testing Policies

All Rego policies must be tested with `opa test`. Per the Regal [file-missing-test-suffix](https://www.openpolicyagent.org/projects/regal/rules/testing/file-missing-test-suffix) rule, test files must be named with a `_test.rego` suffix (e.g. `policy_test.rego` alongside `policy.rego`). Use `with input as` to inject mock input and `with data.x as` to inject mock data.

```rego
# policy_test.rego
package example.authz_test

import rego.v1
import data.example.authz  # import the policy package under test

# Passing case: compliant input → allow must be true
test_allowed if {
    authz.allow with input as {"user": "alice", "method": "GET"}
               with data.roles as {"alice": ["viewer"]}
}

# Failing case: non-compliant input → allow must be false
test_denied if {
    not authz.allow with input as {"user": "bob", "method": "DELETE"}
                   with data.roles as {"bob": ["viewer"]}
}
```

The `_test.rego` filename suffix is required by the Regal [file-missing-test-suffix](https://www.openpolicyagent.org/projects/regal/rules/testing/file-missing-test-suffix) rule. The package mirrors the policy with a `_test` suffix (e.g. `package example.authz_test`), enforced by [test-outside-test-package](https://www.openpolicyagent.org/projects/regal/rules/testing/test-outside-test-package). Because the test is in a **different package**, rules from the policy are not in scope — you must import the policy package (`import data.example.authz`) and reference rules via the alias (`authz.allow`). Using just `allow` in a `_test` package will fail.

---

## Capabilities

This Knowledge Tile covers five major themes for using Rego in production environments. Each theme includes detailed examples, best practices, and real-world use cases.

---

### 1. Kubernetes Admission Control

Validate and enforce policies on Kubernetes resources before they are created or updated in the cluster.

**Use Cases:** Image registry validation, resource requirements, label enforcement, security standards, hostname conflict prevention.

[View detailed Kubernetes admission control examples →](kubernetes-admission-control.md)

---

### 2. Infrastructure as Code

Validate Terraform plans and CloudFormation templates before deployment to catch security and compliance issues.

**Use Cases:** Encryption requirements, required tags enforcement, security group validation, CloudFormation hook policies, multi-region compliance.

[View detailed infrastructure as code examples →](infrastructure-as-code.md)

---

### 3. HTTP API Authorization

Implement fine-grained authorization for REST APIs based on user context, roles, and resource ownership.

**Use Cases:** Hierarchical authorization, JWT-based access control, method-based permissions, path-based authorization.

[View detailed HTTP API authorization examples →](http-api-authorization.md)

**Request Body Validation**: Validates POST request bodies using set subtraction to detect unknown fields and explicit iteration for required fields.

[View request body validation examples →](http-api-body-validation.md)

**Rate Limiting**: Enforces per-user rate limits using `default rule := value` for tier-based fallbacks.

[View rate limiting examples →](http-api-rate-limiting.md)

---

### 4. Access Control Models

Implement sophisticated access control patterns including RBAC, ABAC, and custom authorization logic.

**Use Cases:** Role-based access control, attribute-based access control, separation of duty, time-based access, location-based access.

[View detailed access control model examples →](access-control-models.md)

---

### 5. Metadata Annotations

Document and categorize policies using OPA's built-in metadata annotation system for governance, discovery, and type safety.

**Use Cases:** Policy cataloging, entrypoint discovery, schema validation, severity classification, compliance framework tagging, documentation generation.

[View detailed metadata annotation examples →](metadata-annotations.md)

---

### 6. Regal Linter Compliance

Write Rego policies that pass the [Regal linter](https://www.openpolicyagent.org/projects/regal/rules) from the start. The following focused guides cover common Regal rule categories:

- **Naming conventions** (`prefer-snake-case`, `avoid-get-and-list-prefix`, `rule-name-repeats-package`) → [regal-naming-conventions.md](regal-naming-conventions.md)
- **Iteration style** (`prefer-some-in-iteration`, `mixed-iteration`) → [regal-iteration-style.md](regal-iteration-style.md)
- **Membership operators** (`use-in-operator`) → [regal-membership-operators.md](regal-membership-operators.md)
- **Function style** (`external-reference`, `zero-arity-function`) → [regal-function-style.md](regal-function-style.md)
- **Default rules** (`trailing-default-rule`, `default-over-else`) → [regal-defaults.md](regal-defaults.md)
- **Boolean and rule structure** (`prefer-set-or-object-rule`, `boolean-assignment`) → [regal-boolean-structure.md](regal-boolean-structure.md)
- **Comprehension patterns** (`object.keys`, `comprehension-term-assignment`) → [regal-comprehensions.md](regal-comprehensions.md)
- **Bug avoidance** (`not-equals-in-loop`, `sprintf-arguments-mismatch`) → [regal-bugs.md](regal-bugs.md)
- **Testing style** (`file-missing-test-suffix`, `test-outside-test-package`) → [regal-testing-style.md](regal-testing-style.md)
- **Import conventions** (`prefer-package-imports`, `redundant-alias`) → [regal-imports.md](regal-imports.md)
- **Annotations** (`missing-metadata`, `detached-metadata`, `no-defined-entrypoint`) → [regal-annotations.md](regal-annotations.md)

## Additional Resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Policy Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [OPA Playground](https://play.openpolicyagent.org/)
- [Styra Academy](https://academy.styra.com/)
- [Policy Library](https://github.com/open-policy-agent/library)
