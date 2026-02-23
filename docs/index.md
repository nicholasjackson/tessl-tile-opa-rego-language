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

## Capabilities

This Knowledge Tile covers five major themes for using Rego in production environments. Each theme includes detailed examples, best practices, and real-world use cases.

---

### 1. Kubernetes Admission Control

Validate and enforce policies on Kubernetes resources before they are created or updated in the cluster.

**Use Cases:** Image registry validation, resource requirements, label enforcement, security standards, hostname conflict prevention.

**Example: Image Registry Validation**

Ensures all container images come from approved corporate registries:

```rego
package kubernetes.admission
import rego.v1

deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    image := container.image
    not startswith(image, "hooli.com/")
    msg := sprintf("image '%v' comes from untrusted registry", [image])
}
```

**Example: Resource Label Requirements**

Requires specific labels on Kubernetes resources for proper organization:

```rego
package kubernetes.admission
import rego.v1

required_labels := ["app", "team", "environment"]

deny contains msg if {
    input.request.kind.kind == "Deployment"
    labels := input.request.object.metadata.labels
    some required_label in required_labels
    not labels[required_label]
    msg := sprintf("Deployment missing required label: %v", [required_label])
}
```

**Example: Pod Security Standards**

Enforces pod security standards like non-root user and read-only filesystem:

```rego
package kubernetes.admission
import rego.v1

deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container %v must run as non-root user", [container.name])
}

deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    not container.securityContext.readOnlyRootFilesystem
    msg := sprintf("Container %v must use read-only root filesystem", [container.name])
}
```

[View detailed Kubernetes admission control examples →](kubernetes-admission-control.md)

---

### 2. Container & Docker Security

Use OPA as a Docker daemon authorization plugin (`opa-docker-authz`) to intercept and enforce security policies on every Docker API call before it executes.

**Use Cases:** Privileged container prevention, seccomp profile enforcement, sensitive bind mount blocking, user-based read-only access control.

**Example: Seccomp Profile Enforcement**

Prevents containers from running with unconfined seccomp profiles:

```rego
package docker.authz
import rego.v1

default allow := false

allow if {
    not deny
}

deny if {
    seccomp_unconfined
}

seccomp_unconfined if {
    "seccomp:unconfined" in input.Body.HostConfig.SecurityOpt
}
```

**Example: Privileged Container Prevention**

Blocks creation of privileged containers:

```rego
package docker.authz
import rego.v1

default allow := false

allow if {
    not deny
}

deny if {
    input.Body.HostConfig.Privileged == true
}
```

**Example: Volume Mount Restrictions**

Restricts which host paths can be mounted into containers:

```rego
package docker.authz
import rego.v1

default allow := false

allowed_volume_paths := {"/data", "/logs", "/tmp"}

deny if {
    some bind in input.Body.HostConfig.Binds
    [host_path, _] := split(bind, ":")
    not allowed_volume_paths[host_path]
}
```

[View detailed container security examples →](container-docker-security.md)

---

### 3. Infrastructure as Code

Validate Terraform plans and CloudFormation templates before deployment to catch security and compliance issues.

**Use Cases:** Blast radius control, IAM protection, encryption requirements, required tags enforcement, security group validation.

**Example: Blast Radius Control and IAM Protection**

Controls the blast radius of infrastructure changes and prevents IAM modifications:

```rego
package terraform.analysis
import input as tfplan
import rego.v1

blast_radius := 30

weights := {
    "aws_autoscaling_group": {"delete": 100, "create": 10, "modify": 1},
    "aws_instance": {"delete": 10, "create": 1, "modify": 1},
}

default authz := false

authz if {
    score < blast_radius
    not touches_iam
}

score := s if {
    all_resources := [x |
        some resource_type, crud in weights
        del := crud.delete * num_deletes[resource_type]
        new := crud.create * num_creates[resource_type]
        mod := crud.modify * num_modifies[resource_type]
        x := (del + new) + mod
    ]
    s := sum(all_resources)
}

touches_iam if {
    all_resources := resources.aws_iam
    count(all_resources) > 0
}
```

**Example: S3 Bucket Encryption Requirement**

Ensures all S3 buckets have encryption enabled:

```rego
package terraform.analysis
import input as tfplan
import rego.v1

deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "aws_s3_bucket"
    "create" in r.change.actions
    not r.change.after.server_side_encryption_configuration
    msg := sprintf("S3 bucket %v does not have encryption enabled", [r.address])
}
```

**Example: CloudFormation S3 Bucket Access Control**

Enforces security compliance on S3 buckets before CloudFormation deployment:

```rego
package system
import rego.v1

main := {
    "allow": count(deny) == 0,
    "violations": deny,
}

deny contains msg if {
    bucket_create_or_update
    not bucket_is_private
    msg := sprintf("S3 Bucket %s 'AccessControl' attribute value must be 'Private'", [input.resource.id])
}

bucket_create_or_update if {
    input.resource.type == "AWS::S3::Bucket"
    input.action in {"CREATE", "UPDATE"}
}

bucket_is_private if {
    input.resource.properties.AccessControl == "Private"
}
```

[View detailed infrastructure as code examples →](infrastructure-as-code.md)

---

### 4. HTTP API Authorization

Implement fine-grained authorization for REST APIs based on user context, roles, and resource ownership.

**Use Cases:** Hierarchical authorization, JWT-based access control, method-based permissions, path-based authorization.

**Example: Hierarchical Authorization**

Context-aware authorization based on organizational hierarchy:

```rego
package httpapi.authz
import rego.v1

subordinates := {"alice": [], "charlie": [], "bob": ["alice"], "betty": ["charlie"]}

default allow := false

# Allow users to get their own salaries.
allow if {
    input.method == "GET"
    input.path == ["finance", "salary", input.user]
}

# Allow managers to get their subordinates' salaries.
allow if {
    some username
    input.method == "GET"
    input.path = ["finance", "salary", username]
    username in subordinates[input.user]
}
```

**Example: JWT-Based Access Control**

JWT-based authentication with role verification:

```rego
package httpapi.authz
import rego.v1

default allow := false

# Allow users to get their own salaries.
allow if {
    some username
    input.method == "GET"
    input.path = ["finance", "salary", username]
    token.payload.user == username
    user_owns_token
}

# Ensure that the token was issued to the user supplying it.
user_owns_token if input.user == token.payload.azp

# Helper to get the token payload.
token := {"payload": payload} if {
    [header, payload, signature] := io.jwt.decode(input.token)
}
```

**Example: Method-Based Access Control**

Restricts HTTP methods based on user permissions:

```rego
package httpapi.authz
import data.users
import rego.v1

default allow := false

allow if {
    input.method == "GET"
    "read" in users[input.user].permissions
}

allow if {
    input.method in {"POST", "PUT", "PATCH"}
    "write" in users[input.user].permissions
}

allow if {
    input.method == "DELETE"
    "admin" in users[input.user].permissions
}
```

[View detailed HTTP API authorization examples →](http-api-authorization.md)

---

### 5. Access Control Models

Implement sophisticated access control patterns including RBAC, ABAC, and custom authorization logic.

**Use Cases:** Role-based access control, attribute-based access control, separation of duty, time-based access, location-based access.

**Example: Basic RBAC Pattern**

Core RBAC implementation with user/role/permission mappings:

```rego
package rbac.authz
import rego.v1

# user-role assignments
user_roles := {
    "alice": ["engineering", "webdev"],
    "bob": ["hr"],
}

# role-permissions assignments
role_permissions := {
    "engineering": [{"action": "read", "object": "server123"}],
    "webdev": [{"action": "read", "object": "server123"},
                {"action": "write", "object": "server123"}],
    "hr": [{"action": "read", "object": "database456"}],
}

default allow := false

allow if {
    roles := user_roles[input.user]
    some r in roles
    permissions := role_permissions[r]
    some p in permissions
    p == {"action": input.action, "object": input.object}
}
```

**Example: Separation of Duty Violation Detection**

Prevents conflicting role assignments for compliance:

```rego
package rbac.authz
import rego.v1

sod_roles := [
    ["create-payment", "approve-payment"],
    ["create-vendor", "pay-vendor"],
]

sod_violation contains user if {
    some user
    some role1 in user_roles[user]
    some role2 in user_roles[user]
    [role1, role2] in sod_roles
}
```

**Example: Time-Based Access Control**

Restricts access based on time of day using ABAC:

```rego
package abac.authz
import rego.v1

default allow := false

allow if {
    input.method == "GET"
    is_business_hours
}

is_business_hours if {
    [hour, _, _] := time.clock(time.now_ns())
    hour >= 9
    hour < 17
}
```

[View detailed access control model examples →](access-control-models.md)

---

### 6. Metadata Annotations

Document and categorize policies using OPA's built-in metadata annotation system for governance, discovery, and type safety.

**Use Cases:** Policy cataloging, entrypoint discovery, schema validation, severity classification, compliance framework tagging, documentation generation.

**Example: Package-Level Metadata**

Document an entire policy module with title, authors, and custom fields:

```rego
# METADATA
# title: Kubernetes Admission Control
# description: >-
#   Validates Kubernetes resources against organization
#   security standards.
# authors:
# - Platform Security Team <security@example.com>
# custom:
#   category: kubernetes
#   compliance_framework: SOC2
package kubernetes.admission

import rego.v1
```

**Example: Entrypoint Rule Annotation**

Mark decision rules for auto-discovery with severity classification:

```rego
package terraform.analysis

import input as tfplan
import rego.v1

# METADATA
# title: Deny unencrypted S3 buckets
# description: Ensures all S3 buckets have server-side encryption
# entrypoint: true
# custom:
#   severity: HIGH
deny contains msg if {
    some r in tfplan.resource_changes
    r.type == "aws_s3_bucket"
    "create" in r.change.actions
    not r.change.after.server_side_encryption_configuration
    msg := sprintf("S3 bucket %v does not have encryption enabled", [r.address])
}
```

**Example: Runtime Metadata Access**

Use `rego.metadata.rule()` for severity-aware violation reporting:

```rego
package security.reporter

import rego.v1

# METADATA
# title: Deny privileged containers
# entrypoint: true
# custom:
#   severity: HIGH
#   category: pod-security
violations contains violation if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    container.securityContext.privileged == true
    annotation := rego.metadata.rule()
    violation := {
        "severity": annotation.custom.severity,
        "message": sprintf("privileged container %v is not allowed", [container.name]),
    }
}
```

[View detailed metadata annotation examples →](metadata-annotations.md)

---

## 7. Policy Testing

OPA provides first-class support for testing policies. Tests are standard Rego rules prefixed with `test_` and run with the `opa test` command.

**Basic Unit Test:**

```rego
package kubernetes.admission_test

import data.kubernetes.admission
import rego.v1

test_untrusted_image_denied if {
    review := {
        "request": {
            "kind": {"kind": "Pod"},
            "object": {
                "spec": {
                    "containers": [
                        {"image": "hooli.com/nginx"},
                        {"image": "busybox"}
                    ]
                }
            }
        }
    }
    expected := "image 'busybox' comes from untrusted registry"
    expected in admission.deny with input as review
}
```

**Mocking Data and Functions with `with`:**

```rego
package api.authz_test

import data.api.authz
import rego.v1

mock_users := {
    "alice": {"permissions": ["read", "write", "admin"]},
    "bob": {"permissions": ["read"]},
}

test_admin_can_delete if {
    authz.allow with input as {"user": "alice", "method": "DELETE"}
        with data.users as mock_users
}

test_reader_cannot_delete if {
    not authz.allow with input as {"user": "bob", "method": "DELETE"}
        with data.users as mock_users
}
```

**Parameterized Tests:**

```rego
package validation_test

import data.validation
import rego.v1

test_email_validation[description] if {
    some description, tc in {
        "valid email": {"input": {"email": "user@example.com"}, "expected": true},
        "missing @": {"input": {"email": "userexample.com"}, "expected": false},
        "empty email": {"input": {"email": ""}, "expected": false},
    }
    result := validation.valid_email with input as tc.input
    result == tc.expected
}
```

Run tests with the OPA CLI:
```bash
# Run all tests verbosely
opa test . -v

# Run with coverage analysis
opa test --coverage --format=json .

# Filter tests by name
opa test . -v --run "test_admin"
```

[View comprehensive policy testing guide →](policy-testing.md)

## Additional Resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Policy Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [OPA Playground](https://play.openpolicyagent.org/)
- [Styra Academy](https://academy.styra.com/)
- [Policy Library](https://github.com/open-policy-agent/library)
