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

**Importing Built-in Functions**
```rego
import future.keywords.contains
import future.keywords.if
import future.keywords.in
```
Imports modern Rego keywords for cleaner syntax (recommended for new policies).

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

active_users := {user |
    user := input.users[_]
    user.status == "active"
}

total_cost_by_team[team] := total if {
    some team
    resources := [r | r := input.resources[_]; r.team == team]
    costs := [r.cost | r := resources[_]]
    total := sum(costs)
}
```

## Capabilities

This Knowledge Tile covers eight major themes for using Rego in production environments. Each theme includes detailed examples, best practices, and real-world use cases.

---

### 1. Kubernetes Admission Control

Validate and enforce policies on Kubernetes resources before they are created or updated in the cluster.

**Use Cases:** Image registry validation, resource requirements, label enforcement, security standards, hostname conflict prevention.

**Example: Image Registry Validation**

Ensures all container images come from approved corporate registries:

```rego
package kubernetes.admission

deny contains msg if {
    input.request.kind.kind == "Pod"
    image := input.request.object.spec.containers[_].image
    not startswith(image, "hooli.com/")
    msg := sprintf("image '%v' comes from untrusted registry", [image])
}
```

**Example: Resource Label Requirements**

Requires specific labels on Kubernetes resources for proper organization:

```rego
package kubernetes.admission

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

deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container %v must run as non-root user", [container.name])
}

deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem
    msg := sprintf("Container %v must use read-only root filesystem", [container.name])
}
```

[View detailed Kubernetes admission control examples →](kubernetes-admission-control.md)

---

### 2. Container & Docker Security

Control Docker daemon operations and enforce security policies on container configurations.

**Use Cases:** Privileged container prevention, volume mount restrictions, seccomp profile enforcement, user-based access control.

**Example: Seccomp Profile Enforcement**

Prevents containers from running with unconfined seccomp profiles:

```rego
package docker.authz

default allow := false

allow if {
    not deny
}

deny if {
    seccomp_unconfined
}

seccomp_unconfined if {
    input.Body.HostConfig.SecurityOpt[_] == "seccomp:unconfined"
}
```

**Example: Privileged Container Prevention**

Blocks creation of privileged containers:

```rego
package docker.authz

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

deny contains msg if {
    r := tfplan.resource_changes[_]
    r.type == "aws_s3_bucket"
    r.change.actions[_] == "create"
    not r.change.after.server_side_encryption_configuration
    msg := sprintf("S3 bucket %v does not have encryption enabled", [r.address])
}
```

**Example: CloudFormation S3 Bucket Access Control**

Enforces security compliance on S3 buckets before CloudFormation deployment:

```rego
package system

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
    subordinates[input.user][_] == username
}
```

**Example: JWT-Based Access Control**

JWT-based authentication with role verification:

```rego
package httpapi.authz

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

default allow := false

allow if {
    input.method == "GET"
    users[input.user].permissions[_] == "read"
}

allow if {
    input.method in {"POST", "PUT", "PATCH"}
    users[input.user].permissions[_] == "write"
}

allow if {
    input.method == "DELETE"
    users[input.user].permissions[_] == "admin"
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
    r := roles[_]
    permissions := role_permissions[r]
    p := permissions[_]
    p == {"action": input.action, "object": input.object}
}
```

**Example: Separation of Duty Violation Detection**

Prevents conflicting role assignments for compliance:

```rego
package rbac.authz

sod_roles := [
    ["create-payment", "approve-payment"],
    ["create-vendor", "pay-vendor"],
]

sod_violation contains user if {
    some user
    role1 := user_roles[user][_]
    role2 := user_roles[user][_]
    sod_roles[_] == [role1, role2]
}
```

**Example: Time-Based Access Control**

Restricts access based on time of day using ABAC:

```rego
package abac.authz

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

### 6. CI/CD Pipeline Policies

Automate validation and enforce quality standards in continuous integration and deployment pipelines.

**Use Cases:** File validation, change detection, test coverage requirements, security scanning, compliance checks.

**Example: File Validation Policy**

Validates configuration file syntax in CI/CD pipelines:

```rego
package files

# METADATA
# entrypoint: true

deny contains sprintf("%s is an invalid YAML file: %s", [filename, content]) if {
    some filename, content in yaml_file_contents
    changes[filename].status in {"added", "modified"}
    not yaml.is_valid(content)
}

deny contains sprintf("%s is an invalid JSON file: %s", [filename, content]) if {
    some filename, content in json_file_contents
    changes[filename].status in {"added", "modified"}
    not json.is_valid(content)
}

yaml_file_contents[filename] := file_in_pr(filename) if {
    some filename in filenames
    extension(filename) in {"yml", "yaml"}
}

json_file_contents[filename] := file_in_pr(filename) if {
    some filename in filenames
    extension(filename) == "json"
}

extension(filename) := ext if {
    parts := split(filename, ".")
    ext := parts[count(parts) - 1]
}
```

**Example: PR Change Detection**

Determines which tests to run based on changed files:

```rego
package policy["pr-check"]

go_change_prefixes := [
    "build/",
    "capabilities/",
    "internal/",
]

changes["docs"] if {
    some changed_file in input
    startswith(changed_file.filename, "docs/")
}

changes["go"] if {
    some changed_file in input
    some prefix in go_change_prefixes
    startswith(changed_file.filename, prefix)
}

changes["wasm"] if {
    some changed_file in input
    startswith(changed_file.filename, "wasm/")
}
```

**Example: Test Coverage Requirements**

Enforces minimum test coverage thresholds:

```rego
package cicd.coverage

minimum_coverage := 80

deny contains msg if {
    coverage := input.test_results.coverage_percent
    coverage < minimum_coverage
    msg := sprintf("Test coverage %v%% is below minimum %v%%", [coverage, minimum_coverage])
}
```

[View detailed CI/CD pipeline policy examples →](cicd-pipeline-policies.md)

---

### 7. Data Validation & Transformation

Validate input data, perform transformations, and implement content moderation policies.

**Use Cases:** Input validation, email validation, content filtering, data aggregation, object filtering, structured error responses.

**Example: Comprehensive Input Validation**

Validate multiple aspects of input:

```rego
package validation

errors contains msg if {
    not input.username
    msg := "username is required"
}

errors contains msg if {
    count(input.username) < 3
    msg := "username must be at least 3 characters"
}

errors contains msg if {
    not input.email
    msg := "email is required"
}

errors contains msg if {
    not contains(input.email, "@")
    msg := "email must be valid"
}

valid if {
    count(errors) == 0
}
```

**Example: Email Validation**

Simple email format validation:

```rego
package content.validation

valid_email if {
    contains(input.email, "@")
    parts := split(input.email, "@")
    count(parts) == 2
    parts[0] != ""
    parts[1] != ""
}
```

**Example: Data Aggregation**

Aggregate data from multiple sources:

```rego
package transform

total_cost_by_team[team] := total if {
    some team
    resources := [r | r := input.resources[_]; r.team == team]
    costs := [r.cost | r := resources[_]]
    total := sum(costs)
}

resource_count_by_type[resource_type] := count(resources) if {
    some resource_type
    resources := [r | r := input.resources[_]; r.type == resource_type]
}
```

[View detailed data validation and transformation examples →](data-validation-transformation.md)

---

### 8. Network & Compliance Policies

Enforce network security policies and regulatory compliance requirements.

**Use Cases:** CIDR range validation, egress traffic control, PCI-DSS compliance, data residency, network segmentation.

**Example: CIDR Range Validation**

Validates IP addresses against allowed CIDR ranges:

```rego
package network.policies

allowed_cidrs := ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

deny contains msg if {
    ip := input.source_ip
    not is_allowed_ip(ip)
    msg := sprintf("IP address %v is not in allowed CIDR ranges", [ip])
}

is_allowed_ip(ip) if {
    some cidr in allowed_cidrs
    net.cidr_contains(cidr, ip)
}
```

**Example: Egress Traffic Control**

Controls which external services can be accessed:

```rego
package network.egress

allowed_domains := {"api.github.com", "registry.npmjs.org", "*.amazonaws.com"}

deny contains msg if {
    host := input.request.host
    not is_allowed_host(host)
    msg := sprintf("Egress to %v is not allowed", [host])
}

is_allowed_host(host) if {
    some pattern in allowed_domains
    glob.match(pattern, ["."], host)
}
```

**Example: PCI-DSS Compliance Check**

Validates resources against PCI-DSS requirements:

```rego
package compliance.pci

deny contains msg if {
    resource := input.resources[_]
    resource.type == "database"
    not resource.encrypted
    msg := sprintf("Database %v must be encrypted for PCI-DSS compliance", [resource.id])
}

deny contains msg if {
    resource := input.resources[_]
    resource.type == "database"
    not resource.audit_logging_enabled
    msg := sprintf("Database %v must have audit logging for PCI-DSS compliance", [resource.id])
}
```

[View detailed network and compliance policy examples →](network-compliance-policies.md)

---

## Testing Your Policies

Rego supports comprehensive unit testing using the `test_` prefix convention:

```rego
package kubernetes.test_admission

import data.kubernetes.admission

test_image_safety if {
    unsafe_image := {
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
    admission.deny[expected] with input as unsafe_image
}
```

Run tests with the OPA CLI:
```bash
opa test . -v
```

## Additional Resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Policy Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [OPA Playground](https://play.openpolicyagent.org/)
- [Styra Academy](https://academy.styra.com/)
- [Policy Library](https://github.com/open-policy-agent/library)
