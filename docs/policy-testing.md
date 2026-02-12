# Policy Testing

Comprehensive guide to testing OPA/Rego policies. Testing is a first-class concept in OPA — tests are standard Rego rules prefixed with `test_` and executed using the `opa test` command.

Reference: [OPA Policy Testing Documentation](https://www.openpolicyagent.org/docs/policy-testing)

---

## 1. Test Structure and Naming Conventions

Tests follow a simple convention: prefix rule names with `test_` and place them in files suffixed with `_test.rego`. Test packages typically use a `_test` suffix matching the policy package.

```rego
# File: authz_test.rego
package authz_test

import data.authz
import rego.v1

test_allow_admin_access if {
    authz.allow with input as {
        "user": "alice",
        "role": "admin",
        "action": "delete",
    }
}

test_deny_anonymous_access if {
    not authz.allow with input as {
        "user": "anonymous",
        "action": "delete",
    }
}
```

Key conventions:
- Test rules **must** be prefixed with `test_`
- Use descriptive names: `test_<what_is_being_tested>_<expected_outcome>`
- Test files use `_test.rego` suffix
- Test packages use `_test` suffix (e.g., `package authz_test`)
- Tests evaluate to `true` for PASS, `undefined` or non-true for FAIL

---

## 2. Running Tests with the OPA CLI

The `opa test` command discovers and runs all `test_` prefixed rules.

```bash
# Run all tests in current directory (recursive)
opa test .

# Run tests with verbose output showing individual results
opa test . -v

# Filter tests by name using regex
opa test . -v --run "test_allow"

# Run tests with JSON output (useful for CI/CD)
opa test . --format=json

# Fail if no tests are found (prevents silent CI/CD passes)
opa test . --fail-on-empty

# Run tests from specific files
opa test policy.rego policy_test.rego

# Run tests with bundled data files
opa test . -b ./bundle/
```

Example verbose output:
```
data.authz_test.test_allow_admin_access: PASS (1.417µs)
data.authz_test.test_deny_anonymous_access: PASS (426ns)
data.authz_test.test_deny_expired_token: PASS (892ns)
data.authz_test.test_allow_read_only: PASS (513ns)
--------------------------------------------------------------------------------
PASS: 4/4
```

---

## 3. Test Outcomes: PASS, FAIL, ERROR, and SKIPPED

Tests produce four outcome types. Understanding each helps with debugging and test organization.

```rego
package outcomes_test

import rego.v1

# PASS: Rule evaluates to true
test_passes if {
    1 + 1 == 2
}

# FAIL: Rule body is undefined or evaluates to non-true
test_fails if {
    1 + 1 == 3
}

# ERROR: Runtime error during evaluation (e.g., type error, divide by zero)
test_error if {
    x := 1 / 0
    x > 0
}

# SKIPPED: Rules prefixed with todo_ are automatically skipped
todo_test_not_implemented_yet if {
    # This test is skipped - useful for tracking planned tests
    false
}
```

Output:
```
data.outcomes_test.test_passes: PASS (250ns)
data.outcomes_test.test_fails: FAIL (180ns)
data.outcomes_test.test_error: ERROR (320ns)
  policy_test.rego:13: eval_builtin_error: div: divide by zero
data.outcomes_test.todo_test_not_implemented_yet: SKIPPED
--------------------------------------------------------------------------------
PASS: 1/4 FAIL: 1/4 ERROR: 1/4 SKIPPED: 1/4
```

---

## 4. Testing with Mock Input

The `with` keyword replaces `input` during test execution, enabling isolated tests without external dependencies.

```rego
# File: rbac.rego
package rbac

import rego.v1

default allow := false

allow if {
    some role in input.user.roles
    role == "admin"
}

allow if {
    input.method == "GET"
    some role in input.user.roles
    role == "viewer"
}
```

```rego
# File: rbac_test.rego
package rbac_test

import data.rbac
import rego.v1

test_admin_allowed if {
    rbac.allow with input as {
        "user": {"roles": ["admin"]},
        "method": "DELETE",
    }
}

test_viewer_read_allowed if {
    rbac.allow with input as {
        "user": {"roles": ["viewer"]},
        "method": "GET",
    }
}

test_viewer_write_denied if {
    not rbac.allow with input as {
        "user": {"roles": ["viewer"]},
        "method": "DELETE",
    }
}

test_no_roles_denied if {
    not rbac.allow with input as {
        "user": {"roles": []},
        "method": "GET",
    }
}
```

---

## 5. Testing with Mock Data

The `with` keyword can replace `data` references to mock external data sources, bundles, or configuration.

```rego
# File: team_access.rego
package team.access

import rego.v1

import data.teams
import data.permissions

default allow := false

allow if {
    team := teams[input.user]
    perms := permissions[team]
    input.action in perms
}
```

```rego
# File: team_access_test.rego
package team.access_test

import data.team.access
import rego.v1

mock_teams := {
    "alice": "engineering",
    "bob": "marketing",
}

mock_permissions := {
    "engineering": {"read", "write", "deploy"},
    "marketing": {"read"},
}

test_engineer_can_deploy if {
    access.allow with input as {"user": "alice", "action": "deploy"}
        with data.teams as mock_teams
        with data.permissions as mock_permissions
}

test_marketing_cannot_deploy if {
    not access.allow with input as {"user": "bob", "action": "deploy"}
        with data.teams as mock_teams
        with data.permissions as mock_permissions
}

test_unknown_user_denied if {
    not access.allow with input as {"user": "charlie", "action": "read"}
        with data.teams as mock_teams
        with data.permissions as mock_permissions
}
```

---

## 6. Mocking Built-in and Custom Functions

Functions can be replaced during testing using the `with` keyword. The replacement must have the same arity as the original.

```rego
# File: jwt_authz.rego
package jwt.authz

import rego.v1

default allow := false

allow if {
    [valid, header, payload] := io.jwt.decode_verify(input.token, {
        "cert": data.jwks.cert,
        "iss": "https://auth.example.com",
    })
    valid
    "admin" in payload.roles
}
```

```rego
# File: jwt_authz_test.rego
package jwt.authz_test

import data.jwt.authz
import rego.v1

# Mock function must match arity of original
mock_decode_verify_valid(token, _) := [true, {}, {"roles": ["admin"], "sub": "alice"}] if {
    token == "valid-admin-token"
}

mock_decode_verify_valid(token, _) := [true, {}, {"roles": ["viewer"], "sub": "bob"}] if {
    token == "valid-viewer-token"
}

mock_decode_verify_valid(token, _) := [false, {}, {}] if {
    token != "valid-admin-token"
    token != "valid-viewer-token"
}

# Mock that always returns invalid
mock_decode_verify_invalid(_, _) := [false, {}, {}]

test_valid_admin_token if {
    authz.allow with input.token as "valid-admin-token"
        with io.jwt.decode_verify as mock_decode_verify_valid
}

test_valid_viewer_token_denied if {
    not authz.allow with input.token as "valid-viewer-token"
        with io.jwt.decode_verify as mock_decode_verify_valid
}

test_invalid_token_denied if {
    not authz.allow with input.token as "bad-token"
        with io.jwt.decode_verify as mock_decode_verify_invalid
}

# Functions can also be replaced with simple values
test_allow_with_value_mock if {
    authz.allow with input.token as "anything"
        with io.jwt.decode_verify as [true, {}, {"roles": ["admin"]}]
}
```

---

## 7. Testing Deny Rules and Violation Messages

When testing policies that produce deny messages or violation sets, verify both the presence and content of messages.

```rego
# File: container_policy.rego
package container.policy

import rego.v1

deny contains msg if {
    input.privileged == true
    msg := "containers must not run in privileged mode"
}

deny contains msg if {
    not input.resource_limits.memory
    msg := "containers must specify memory limits"
}

deny contains msg if {
    not input.resource_limits.cpu
    msg := "containers must specify CPU limits"
}
```

```rego
# File: container_policy_test.rego
package container.policy_test

import data.container.policy
import rego.v1

# Test that a specific deny message is present
test_deny_privileged if {
    "containers must not run in privileged mode" in policy.deny with input as {
        "privileged": true,
        "resource_limits": {"memory": "256Mi", "cpu": "500m"},
    }
}

# Test that deny is empty for compliant input
test_allow_compliant_container if {
    count(policy.deny) == 0 with input as {
        "privileged": false,
        "resource_limits": {"memory": "256Mi", "cpu": "500m"},
    }
}

# Test multiple violations at once
test_multiple_violations if {
    result := policy.deny with input as {
        "privileged": true,
        "resource_limits": {},
    }
    count(result) == 3
    "containers must not run in privileged mode" in result
    "containers must specify memory limits" in result
    "containers must specify CPU limits" in result
}

# Test that specific deny message is absent
test_no_privileged_violation_when_compliant if {
    result := policy.deny with input as {
        "privileged": false,
        "resource_limits": {},
    }
    not "containers must not run in privileged mode" in result
}
```

---

## 8. Parameterized and Data-Driven Tests

Use variables in the rule head to create parameterized test cases. Each test case is evaluated independently with its own PASS/FAIL status.

```rego
package validation_test

import data.validation
import rego.v1

# Parameterized tests with descriptive case names
test_email_validation[description] if {
    some description, tc in {
        "valid simple email": {
            "input": {"email": "user@example.com"},
            "expected_valid": true,
        },
        "valid email with subdomain": {
            "input": {"email": "user@mail.example.com"},
            "expected_valid": true,
        },
        "missing @ symbol": {
            "input": {"email": "userexample.com"},
            "expected_valid": false,
        },
        "missing domain": {
            "input": {"email": "user@"},
            "expected_valid": false,
        },
        "empty email": {
            "input": {"email": ""},
            "expected_valid": false,
        },
    }
    result := validation.valid_email with input as tc.input
    result == tc.expected_valid
}
```

Output:
```
data.validation_test.test_email_validation: PASS (2.1µs)
  valid simple email: PASS
  valid email with subdomain: PASS
  missing @ symbol: PASS
  missing domain: PASS
  empty email: PASS
```

---

## 9. Testing with External Test Data Files

Load test cases from external JSON or YAML files for large test suites or shared test fixtures.

```json
{
    "test_cases": {
        "valid_admin_request": {
            "input": {
                "user": "alice",
                "role": "admin",
                "action": "delete"
            },
            "expected_allow": true
        },
        "invalid_viewer_delete": {
            "input": {
                "user": "bob",
                "role": "viewer",
                "action": "delete"
            },
            "expected_allow": false
        },
        "valid_viewer_read": {
            "input": {
                "user": "bob",
                "role": "viewer",
                "action": "read"
            },
            "expected_allow": true
        }
    }
}
```

```rego
# File: authz_test.rego
package authz_test

import data.authz
import data.test_cases
import rego.v1

test_authorization[name] if {
    some name, tc in test_cases
    result := authz.allow with input as tc.input
    result == tc.expected_allow
}
```

Run with the data file loaded:
```bash
opa test . -v -d testdata/
```

---

## 10. Testing Helper Functions

Test helper functions in isolation to ensure correct behavior independent of the policies that use them.

```rego
# File: helpers.rego
package helpers

import rego.v1

is_valid_cidr(cidr) if {
    parts := split(cidr, "/")
    count(parts) == 2
    ip := parts[0]
    octets := split(ip, ".")
    count(octets) == 4
    prefix := to_number(parts[1])
    prefix >= 0
    prefix <= 32
}

normalize_path(path) := trimmed if {
    trimmed := trim_right(lower(path), "/")
}

is_sensitive_port(port) if {
    port in {22, 3389, 1433, 3306, 5432, 6379, 27017}
}
```

```rego
# File: helpers_test.rego
package helpers_test

import data.helpers
import rego.v1

test_valid_cidr if {
    helpers.is_valid_cidr("10.0.0.0/8")
}

test_valid_cidr_host if {
    helpers.is_valid_cidr("192.168.1.1/32")
}

test_invalid_cidr_no_prefix if {
    not helpers.is_valid_cidr("10.0.0.0")
}

test_invalid_cidr_bad_prefix if {
    not helpers.is_valid_cidr("10.0.0.0/33")
}

test_normalize_path_lowercase if {
    helpers.normalize_path("/API/Users/") == "/api/users"
}

test_normalize_path_trailing_slash if {
    helpers.normalize_path("/api/users/") == "/api/users"
}

test_sensitive_port_ssh if {
    helpers.is_sensitive_port(22)
}

test_non_sensitive_port if {
    not helpers.is_sensitive_port(8080)
}
```

---

## 11. Testing Partial Rules and Set Generation

Test rules that generate sets or partial objects by verifying membership and cardinality.

```rego
# File: violations.rego
package security.violations

import rego.v1

violations contains violation if {
    some container in input.spec.containers
    container.securityContext.privileged == true
    violation := {
        "type": "privileged_container",
        "container": container.name,
        "severity": "HIGH",
    }
}

violations contains violation if {
    some container in input.spec.containers
    not container.resources.limits
    violation := {
        "type": "missing_resource_limits",
        "container": container.name,
        "severity": "MEDIUM",
    }
}

high_severity_count := count([v | some v in violations; v.severity == "HIGH"])
```

```rego
# File: violations_test.rego
package security.violations_test

import data.security.violations as policy
import rego.v1

mock_pod := {
    "spec": {
        "containers": [
            {
                "name": "app",
                "securityContext": {"privileged": true},
                "resources": {"limits": {"cpu": "500m"}},
            },
            {
                "name": "sidecar",
                "securityContext": {"privileged": false},
            },
        ],
    },
}

test_privileged_container_violation if {
    result := policy.violations with input as mock_pod
    some v in result
    v.type == "privileged_container"
    v.container == "app"
}

test_missing_limits_violation if {
    result := policy.violations with input as mock_pod
    some v in result
    v.type == "missing_resource_limits"
    v.container == "sidecar"
}

test_violation_count if {
    result := policy.violations with input as mock_pod
    count(result) == 2
}

test_high_severity_count if {
    policy.high_severity_count == 1 with input as mock_pod
}

test_compliant_pod_no_violations if {
    compliant := {
        "spec": {
            "containers": [{
                "name": "app",
                "securityContext": {"privileged": false},
                "resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
            }],
        },
    }
    count(policy.violations) == 0 with input as compliant
}
```

---

## 12. Testing Kubernetes Admission Policies

Test patterns for Kubernetes admission control policies using realistic AdmissionReview objects.

```rego
# File: k8s_admission.rego
package kubernetes.admission

import rego.v1

deny contains msg if {
    input.request.kind.kind == "Pod"
    some container in input.request.object.spec.containers
    image := container.image
    not startswith(image, "registry.example.com/")
    msg := sprintf("image '%v' comes from untrusted registry", [image])
}

deny contains msg if {
    input.request.kind.kind == "Deployment"
    labels := object.get(input.request.object.metadata, "labels", {})
    not labels.app
    msg := "Deployment must have 'app' label"
}
```

```rego
# File: k8s_admission_test.rego
package kubernetes.admission_test

import data.kubernetes.admission
import rego.v1

# Helper to build AdmissionReview objects
mock_pod_review(containers) := {
    "request": {
        "kind": {"kind": "Pod"},
        "operation": "CREATE",
        "object": {
            "metadata": {"name": "test-pod"},
            "spec": {"containers": containers},
        },
    },
}

mock_deployment_review(labels) := {
    "request": {
        "kind": {"kind": "Deployment"},
        "operation": "CREATE",
        "object": {
            "metadata": {
                "name": "test-deploy",
                "labels": labels,
            },
            "spec": {},
        },
    },
}

test_trusted_image_allowed if {
    review := mock_pod_review([{
        "name": "app",
        "image": "registry.example.com/myapp:v1.0",
    }])
    count(admission.deny) == 0 with input as review
}

test_untrusted_image_denied if {
    review := mock_pod_review([{
        "name": "app",
        "image": "docker.io/suspicious:latest",
    }])
    result := admission.deny with input as review
    "image 'docker.io/suspicious:latest' comes from untrusted registry" in result
}

test_mixed_images if {
    review := mock_pod_review([
        {"name": "app", "image": "registry.example.com/myapp:v1.0"},
        {"name": "sidecar", "image": "docker.io/envoy:latest"},
    ])
    result := admission.deny with input as review
    count(result) == 1
}

test_deployment_with_labels_allowed if {
    review := mock_deployment_review({"app": "myapp", "team": "platform"})
    count(admission.deny) == 0 with input as review
}

test_deployment_missing_app_label_denied if {
    review := mock_deployment_review({"team": "platform"})
    "Deployment must have 'app' label" in admission.deny with input as review
}
```

---

## 13. Testing Terraform and Infrastructure Policies

Test patterns for infrastructure-as-code policies using Terraform plan JSON structure.

```rego
# File: terraform_policy.rego
package terraform.policy

import rego.v1

deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    change := resource.change.after
    not change.server_side_encryption_configuration
    msg := sprintf("S3 bucket '%v' must have encryption enabled", [resource.address])
}

deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group_rule"
    resource.change.after.cidr_blocks
    some cidr in resource.change.after.cidr_blocks
    cidr == "0.0.0.0/0"
    resource.change.after.type == "ingress"
    msg := sprintf("Security group rule '%v' must not allow ingress from 0.0.0.0/0", [resource.address])
}

warn contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_instance"
    instance_type := resource.change.after.instance_type
    startswith(instance_type, "x1")
    msg := sprintf("Instance '%v' uses expensive type '%v'", [resource.address, instance_type])
}
```

```rego
# File: terraform_policy_test.rego
package terraform.policy_test

import data.terraform.policy
import rego.v1

# Helper to build resource change objects
mock_resource(type, address, after) := {
    "type": type,
    "address": address,
    "change": {
        "actions": ["create"],
        "after": after,
    },
}

test_encrypted_s3_allowed if {
    resource := mock_resource("aws_s3_bucket", "aws_s3_bucket.data", {
        "bucket": "my-data-bucket",
        "server_side_encryption_configuration": {
            "rule": {"apply_server_side_encryption_by_default": {"sse_algorithm": "AES256"}},
        },
    })
    count(policy.deny) == 0 with input.resource_changes as [resource]
}

test_unencrypted_s3_denied if {
    resource := mock_resource("aws_s3_bucket", "aws_s3_bucket.data", {
        "bucket": "my-data-bucket",
    })
    result := policy.deny with input.resource_changes as [resource]
    "S3 bucket 'aws_s3_bucket.data' must have encryption enabled" in result
}

test_open_security_group_denied if {
    resource := mock_resource("aws_security_group_rule", "aws_security_group_rule.web", {
        "type": "ingress",
        "cidr_blocks": ["0.0.0.0/0"],
        "from_port": 22,
        "to_port": 22,
    })
    result := policy.deny with input.resource_changes as [resource]
    count(result) == 1
}

test_restricted_security_group_allowed if {
    resource := mock_resource("aws_security_group_rule", "aws_security_group_rule.web", {
        "type": "ingress",
        "cidr_blocks": ["10.0.0.0/8"],
        "from_port": 443,
        "to_port": 443,
    })
    count(policy.deny) == 0 with input.resource_changes as [resource]
}

test_expensive_instance_warns if {
    resource := mock_resource("aws_instance", "aws_instance.compute", {
        "instance_type": "x1.16xlarge",
    })
    result := policy.warn with input.resource_changes as [resource]
    count(result) == 1
}

test_normal_instance_no_warning if {
    resource := mock_resource("aws_instance", "aws_instance.compute", {
        "instance_type": "t3.medium",
    })
    count(policy.warn) == 0 with input.resource_changes as [resource]
}
```

---

## 14. Testing HTTP API Authorization

Test patterns for HTTP API authorization policies with request structures.

```rego
# File: api_authz.rego
package api.authz

import rego.v1

import data.users

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

```rego
# File: api_authz_test.rego
package api.authz_test

import data.api.authz
import rego.v1

mock_users := {
    "alice": {"permissions": ["read", "write", "admin"]},
    "bob": {"permissions": ["read", "write"]},
    "charlie": {"permissions": ["read"]},
}

test_admin_can_delete if {
    authz.allow with input as {"user": "alice", "method": "DELETE"}
        with data.users as mock_users
}

test_writer_cannot_delete if {
    not authz.allow with input as {"user": "bob", "method": "DELETE"}
        with data.users as mock_users
}

test_reader_can_get if {
    authz.allow with input as {"user": "charlie", "method": "GET"}
        with data.users as mock_users
}

test_reader_cannot_post if {
    not authz.allow with input as {"user": "charlie", "method": "POST"}
        with data.users as mock_users
}

test_unknown_user_denied if {
    not authz.allow with input as {"user": "unknown", "method": "GET"}
        with data.users as mock_users
}

# Parameterized tests for method-permission matrix
test_method_permissions[desc] if {
    some desc, tc in {
        "admin DELETE allowed": {"user": "alice", "method": "DELETE", "expect": true},
        "writer POST allowed": {"user": "bob", "method": "POST", "expect": true},
        "writer PUT allowed": {"user": "bob", "method": "PUT", "expect": true},
        "reader GET allowed": {"user": "charlie", "method": "GET", "expect": true},
        "reader DELETE denied": {"user": "charlie", "method": "DELETE", "expect": false},
        "reader POST denied": {"user": "charlie", "method": "POST", "expect": false},
    }
    result := authz.allow with input as {"user": tc.user, "method": tc.method}
        with data.users as mock_users
    result == tc.expect
}
```

---

## 15. Testing Container Security Policies

Test patterns for Docker and container security policies.

```rego
# File: docker_authz.rego
package docker.authz

import rego.v1

default allow := false

allow if {
    not deny
}

deny if {
    input.Body.HostConfig.Privileged == true
}

deny if {
    "seccomp:unconfined" in input.Body.HostConfig.SecurityOpt
}

deny if {
    some bind in input.Body.HostConfig.Binds
    [host_path, _] := split(bind, ":")
    is_sensitive_path(host_path)
}

is_sensitive_path(path) if startswith(path, "/etc")
is_sensitive_path(path) if startswith(path, "/proc")
is_sensitive_path(path) if path == "/var/run/docker.sock"
```

```rego
# File: docker_authz_test.rego
package docker.authz_test

import data.docker.authz
import rego.v1

# Helper to build Docker API request
mock_docker_request(host_config) := {
    "Body": {
        "Image": "myapp:latest",
        "HostConfig": host_config,
    },
}

test_allow_safe_container if {
    request := mock_docker_request({
        "Privileged": false,
        "SecurityOpt": ["seccomp:runtime/default"],
        "Binds": ["/data:/app/data:ro"],
    })
    authz.allow with input as request
}

test_deny_privileged if {
    request := mock_docker_request({
        "Privileged": true,
        "SecurityOpt": [],
        "Binds": [],
    })
    not authz.allow with input as request
}

test_deny_unconfined_seccomp if {
    request := mock_docker_request({
        "Privileged": false,
        "SecurityOpt": ["seccomp:unconfined"],
        "Binds": [],
    })
    not authz.allow with input as request
}

test_deny_sensitive_bind_mount if {
    request := mock_docker_request({
        "Privileged": false,
        "SecurityOpt": [],
        "Binds": ["/etc/passwd:/tmp/passwd:ro"],
    })
    not authz.allow with input as request
}

test_deny_docker_socket_mount if {
    request := mock_docker_request({
        "Privileged": false,
        "SecurityOpt": [],
        "Binds": ["/var/run/docker.sock:/var/run/docker.sock"],
    })
    not authz.allow with input as request
}

test_allow_safe_bind_mount if {
    request := mock_docker_request({
        "Privileged": false,
        "SecurityOpt": [],
        "Binds": ["/data:/app/data:ro", "/logs:/app/logs"],
    })
    authz.allow with input as request
}
```

---

## 16. Negative Testing Patterns

Systematically verify that policies reject invalid inputs. Negative tests are as important as positive tests for security policies.

```rego
# File: input_validation.rego
package validation

import rego.v1

errors contains msg if {
    not input.username
    msg := "username is required"
}

errors contains msg if {
    count(input.username) < 3
    msg := "username must be at least 3 characters"
}

errors contains msg if {
    count(input.username) > 50
    msg := "username must not exceed 50 characters"
}

errors contains msg if {
    not regex.match(`^[a-zA-Z0-9_]+$`, input.username)
    msg := "username must be alphanumeric with underscores only"
}

valid if {
    count(errors) == 0
}
```

```rego
# File: input_validation_test.rego
package validation_test

import data.validation
import rego.v1

# Positive: valid inputs
test_valid_username if {
    validation.valid with input as {"username": "alice_123"}
}

# Negative: missing field
test_missing_username if {
    not validation.valid with input as {}
    "username is required" in validation.errors with input as {}
}

# Negative: too short
test_short_username if {
    not validation.valid with input as {"username": "ab"}
    "username must be at least 3 characters" in validation.errors with input as {"username": "ab"}
}

# Negative: too long
test_long_username if {
    long_name := concat("", [c | some i in numbers.range(0, 50); c := "a"])
    not validation.valid with input as {"username": long_name}
}

# Negative: invalid characters
test_special_characters_rejected if {
    not validation.valid with input as {"username": "alice@bob"}
    "username must be alphanumeric with underscores only" in validation.errors with input as {"username": "alice@bob"}
}

# Boundary: exactly minimum length
test_minimum_length_boundary if {
    validation.valid with input as {"username": "abc"}
}

# Boundary: exactly maximum length
test_maximum_length_boundary if {
    name_50 := concat("", [c | some i in numbers.range(0, 49); c := "a"])
    validation.valid with input as {"username": name_50}
}
```

---

## 17. Test Coverage Analysis

Use `opa test --coverage` to measure how much of your policy code is exercised by tests.

```bash
# Generate coverage report in JSON format
opa test --coverage --format=json policy.rego policy_test.rego

# Generate coverage for a directory
opa test --coverage --format=json .
```

Example coverage output:
```json
{
  "files": {
    "policy.rego": {
      "covered": [
        {"start": {"row": 5}, "end": {"row": 8}},
        {"start": {"row": 10}, "end": {"row": 13}}
      ],
      "not_covered": [
        {"start": {"row": 15}, "end": {"row": 18}}
      ],
      "covered_lines": [5, 6, 7, 8, 10, 11, 12, 13],
      "not_covered_lines": [15, 16, 17, 18],
      "coverage": 66.67
    }
  }
}
```

Coverage tips:
- Aim for high coverage on security-critical policies (deny rules, allow rules)
- Coverage gaps on helper functions indicate missing test scenarios
- An uncovered rule head means no test exercises that code path
- Use `--var-values` alongside coverage to debug why specific lines are not reached

```bash
# Combined: verbose output with variable values for debugging
opa test . -v --var-values
```

---

## 18. Skipping Tests with `todo_`

Mark tests as planned but not yet implemented using the `todo_` prefix. These tests are reported as SKIPPED rather than FAIL.

```rego
package authz_test

import data.authz
import rego.v1

# Implemented tests
test_basic_allow if {
    authz.allow with input as {"user": "admin", "role": "admin"}
}

# Planned tests - skipped during execution
todo_test_oauth2_token_validation if {
    # TODO: implement once OAuth2 integration is complete
    false
}

todo_test_rate_limiting if {
    # TODO: implement after rate limiter module is added
    false
}

todo_test_audit_logging if {
    # TODO: verify audit events are generated
    false
}
```

Output:
```
data.authz_test.test_basic_allow: PASS (380ns)
data.authz_test.todo_test_oauth2_token_validation: SKIPPED
data.authz_test.todo_test_rate_limiting: SKIPPED
data.authz_test.todo_test_audit_logging: SKIPPED
--------------------------------------------------------------------------------
PASS: 1/4 SKIPPED: 3/4
```

---

## 19. Test Organization and Project Structure

Organize test files alongside their corresponding policy files for maintainability.

```
policies/
├── kubernetes/
│   ├── admission.rego
│   ├── admission_test.rego
│   ├── testdata/
│   │   ├── valid_pod.json
│   │   └── invalid_pod.json
│   └── helpers.rego
├── terraform/
│   ├── aws_policy.rego
│   ├── aws_policy_test.rego
│   └── testdata/
│       └── plan.json
├── http/
│   ├── authz.rego
│   ├── authz_test.rego
│   └── testdata/
│       └── users.json
└── shared/
    ├── helpers.rego
    └── helpers_test.rego
```

Key principles:
- Co-locate test files with their policy files
- Use `_test.rego` suffix for test files
- Use `testdata/` directories for external fixtures
- Use `_test` package suffix for test packages
- Shared test helpers go in a common test package
- Run all tests from the project root: `opa test . -v`

---

## 20. CI/CD Integration for Policy Testing

Integrate OPA policy tests into your CI/CD pipeline to catch policy regressions.

```bash
#!/bin/bash
# Script: test-policies.sh

set -euo pipefail

echo "=== Formatting policies ==="
opa fmt --write --list .

echo "=== Running strict checks ==="
opa check --strict .

echo "=== Running policy tests ==="
opa test . -v --fail-on-empty

echo "=== Generating coverage report ==="
opa test --coverage --format=json . > coverage.json

# Extract overall coverage percentage
coverage=$(jq '[.files[].coverage] | add / length' coverage.json)
echo "Overall coverage: ${coverage}%"

# Fail if coverage is below threshold
min_coverage=80
if (( $(echo "$coverage < $min_coverage" | bc -l) )); then
    echo "ERROR: Coverage ${coverage}% is below minimum ${min_coverage}%"
    exit 1
fi

echo "=== All checks passed ==="
```

GitHub Actions example:
```yaml
name: Policy Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install OPA
        run: |
          curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
          chmod 755 opa
          sudo mv opa /usr/local/bin/

      - name: Format check
        run: opa fmt --fail --list .

      - name: Strict check
        run: opa check --strict .

      - name: Run tests
        run: opa test . -v --fail-on-empty

      - name: Coverage report
        run: opa test --coverage --format=json . > coverage.json

      - name: Check coverage threshold
        run: |
          coverage=$(jq '[.files[].coverage] | add / length' coverage.json)
          echo "Coverage: ${coverage}%"
          if (( $(echo "$coverage < 80" | bc -l) )); then
            echo "Coverage below 80%"
            exit 1
          fi
```

---

## Quick Reference

| Feature | Syntax |
|---------|--------|
| Test rule | `test_descriptive_name if { ... }` |
| Skip test | `todo_test_name if { ... }` |
| Mock input | `rule with input as {...}` |
| Mock data | `rule with data.path as {...}` |
| Mock function | `rule with builtin_func as mock_func` |
| Mock with value | `rule with builtin_func as value` |
| Run tests | `opa test . -v` |
| Filter tests | `opa test . -v --run "pattern"` |
| Coverage | `opa test --coverage --format=json .` |
| JSON output | `opa test . --format=json` |
| Debug values | `opa test . -v --var-values` |

## Summary

This document covers the following testing patterns:

1. **Test Structure** - Naming conventions and file organization
2. **Running Tests** - OPA CLI commands and options
3. **Test Outcomes** - PASS, FAIL, ERROR, and SKIPPED statuses
4. **Mock Input** - Replacing `input` with test data
5. **Mock Data** - Replacing `data` references
6. **Mock Functions** - Replacing built-in and custom functions
7. **Deny Rules** - Testing violation messages and sets
8. **Parameterized Tests** - Data-driven test cases
9. **External Test Data** - Loading fixtures from JSON/YAML files
10. **Helper Functions** - Testing utilities in isolation
11. **Partial Rules** - Testing set generation and membership
12. **Kubernetes Policies** - AdmissionReview test patterns
13. **Terraform Policies** - Plan JSON test patterns
14. **HTTP Authorization** - API authorization test patterns
15. **Container Security** - Docker authorization test patterns
16. **Negative Testing** - Ensuring policies reject invalid inputs
17. **Coverage Analysis** - Measuring test coverage
18. **Skipping Tests** - Using `todo_` prefix for planned tests
19. **Project Structure** - Organizing tests in codebases
20. **CI/CD Integration** - Automated testing in pipelines

These patterns provide a comprehensive toolkit for building reliable, well-tested OPA policies across all domains.
