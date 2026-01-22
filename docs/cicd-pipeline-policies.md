# CI/CD Pipeline Policies

This document provides comprehensive examples of using Rego to enforce policies and validation in CI/CD pipelines. These policies help automate quality gates, security checks, and compliance requirements throughout the software delivery lifecycle.

---

## 1. File Validation

### 1.1 YAML and JSON Syntax Validation

Validates configuration file syntax to catch errors before deployment.

```rego
package cicd.validation

# METADATA
# description: Validates YAML and JSON file syntax in pull requests
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

yaml_file_contents[filename] := file_content if {
    some filename in filenames
    extension(filename) in {"yml", "yaml"}
    file_content := files[filename]
}

json_file_contents[filename] := file_content if {
    some filename in filenames
    extension(filename) == "json"
    file_content := files[filename]
}

extension(filename) := ext if {
    parts := split(filename, ".")
    ext := parts[count(parts) - 1]
}
```

### 1.2 TOML Configuration Validation

Validates TOML configuration files commonly used in CI/CD pipelines.

```rego
package cicd.validation

deny contains sprintf("%s contains invalid TOML syntax", [filename]) if {
    some filename in filenames
    extension(filename) == "toml"
    content := files[filename]
    changes[filename].status in {"added", "modified"}
    not is_valid_toml(content)
}

# Helper to validate TOML by attempting to parse as structured data
is_valid_toml(content) if {
    # TOML validation would typically use an external parser
    # This is a simplified check for basic structure
    lines := split(content, "\n")
    every line in lines {
        valid_toml_line(line)
    }
}

valid_toml_line(line) if trim_space(line) == ""
valid_toml_line(line) if startswith(trim_space(line), "#")
valid_toml_line(line) if contains(line, "=")
valid_toml_line(line) if startswith(trim_space(line), "[")
```

### 1.3 Configuration File Schema Validation

Ensures configuration files follow required schemas.

```rego
package cicd.validation

required_package_json_fields := ["name", "version", "description", "license"]

deny contains sprintf("package.json missing required field: %s", [field]) if {
    "package.json" in filenames
    changes["package.json"].status in {"added", "modified"}
    content := json.unmarshal(files["package.json"])
    some field in required_package_json_fields
    not content[field]
}

deny contains msg if {
    "package.json" in filenames
    changes["package.json"].status in {"added", "modified"}
    content := json.unmarshal(files["package.json"])
    not is_valid_semver(content.version)
    msg := sprintf("package.json version '%s' is not valid semver", [content.version])
}

is_valid_semver(version) if {
    semver.is_valid(version)
}
```

---

## 2. PR Change Detection and Test Routing

### 2.1 Smart Test Selection Based on Changed Files

Determines which test suites to run based on file changes.

```rego
package cicd.test_routing

go_change_prefixes := [
    "internal/",
    "pkg/",
    "cmd/",
    "api/",
]

frontend_change_prefixes := [
    "ui/",
    "web/",
    "frontend/",
]

changes["backend"] if {
    some changed_file in input.files
    endswith(changed_file.filename, ".go")
}

changes["backend"] if {
    some changed_file in input.files
    strings.any_prefix_match(changed_file.filename, go_change_prefixes)
}

changes["frontend"] if {
    some changed_file in input.files
    strings.any_prefix_match(changed_file.filename, frontend_change_prefixes)
}

changes["frontend"] if {
    some changed_file in input.files
    extension(changed_file.filename) in {"ts", "tsx", "jsx", "js", "vue"}
}

changes["infrastructure"] if {
    some changed_file in input.files
    extension(changed_file.filename) in {"tf", "tfvars"}
}

changes["docker"] if {
    some changed_file in input.files
    contains(changed_file.filename, "Dockerfile")
}

changes["docs"] if {
    some changed_file in input.files
    startswith(changed_file.filename, "docs/")
}

changes["docs"] if {
    some changed_file in input.files
    extension(changed_file.filename) == "md"
}

extension(filename) := ext if {
    parts := split(filename, ".")
    ext := parts[count(parts) - 1]
}

# Test matrix output
required_tests contains "backend-unit" if changes["backend"]
required_tests contains "backend-integration" if changes["backend"]
required_tests contains "frontend-unit" if changes["frontend"]
required_tests contains "frontend-e2e" if changes["frontend"]
required_tests contains "terraform-validate" if changes["infrastructure"]
required_tests contains "docker-build" if changes["docker"]
```

### 2.2 Conditional Integration Test Requirements

Requires integration tests only when critical paths are modified.

```rego
package cicd.test_requirements

critical_paths := [
    "services/payment/",
    "services/auth/",
    "database/migrations/",
    "api/",
]

require_integration_tests if {
    some changed_file in input.files
    some critical_path in critical_paths
    startswith(changed_file.filename, critical_path)
}

deny contains "Integration tests must be run for changes to critical services" if {
    require_integration_tests
    not input.tests_run.integration
}

deny contains sprintf("Modified critical file: %s requires integration test evidence", [filename]) if {
    require_integration_tests
    some changed_file in input.files
    filename := changed_file.filename
    some critical_path in critical_paths
    startswith(filename, critical_path)
    not has_integration_test_for(filename)
}

has_integration_test_for(filename) if {
    test_file := integration_test_path(filename)
    test_file in input.test_files_executed
}

integration_test_path(filename) := test_path if {
    dir := substring(filename, 0, last_index_of(filename, "/"))
    base := substring(filename, last_index_of(filename, "/") + 1, count(filename))
    name := trim_suffix(base, sprintf(".%s", [extension(filename)]))
    test_path := sprintf("%s/%s_integration_test.go", [dir, name])
}

last_index_of(str, search) := idx if {
    indices := indexof_n(str, search)
    idx := indices[count(indices) - 1]
}
```

---

## 3. Test Coverage Requirements

### 3.1 Minimum Coverage Thresholds

Enforces minimum test coverage percentages.

```rego
package cicd.coverage

minimum_coverage := 80
minimum_new_code_coverage := 90

deny contains msg if {
    coverage := input.test_results.coverage_percent
    coverage < minimum_coverage
    msg := sprintf("Test coverage %v%% is below minimum %v%%", [coverage, minimum_coverage])
}

deny contains msg if {
    new_code_coverage := input.test_results.new_code_coverage_percent
    new_code_coverage < minimum_new_code_coverage
    msg := sprintf("New code coverage %v%% is below minimum %v%%", [new_code_coverage, minimum_new_code_coverage])
}

deny contains sprintf("Package '%s' has coverage %v%% below minimum %v%%", [pkg, cov, minimum_coverage]) if {
    some pkg, cov in input.test_results.package_coverage
    cov < minimum_coverage
}
```

### 3.2 Coverage Trend Validation

Ensures coverage doesn't decrease between builds.

```rego
package cicd.coverage

deny contains msg if {
    current := input.current_coverage
    previous := input.previous_coverage
    decrease := previous - current
    decrease > 0
    msg := sprintf("Coverage decreased by %.2f%% (from %.2f%% to %.2f%%)", [decrease, previous, current])
}

warning contains msg if {
    current := input.current_coverage
    previous := input.previous_coverage
    increase := current - previous
    increase < 1.0
    increase >= 0
    msg := sprintf("Coverage increased by only %.2f%% - consider adding more tests", [increase])
}
```

### 3.3 Test File Requirements

Requires test files for new source files.

```rego
package cicd.test_requirements

test_required_extensions := {"go", "py", "js", "ts", "java"}

deny contains sprintf("New file %s requires corresponding test file %s", [filename, test_file]) if {
    some changed_file in input.files
    changed_file.status == "added"
    filename := changed_file.filename
    ext := extension(filename)
    ext in test_required_extensions
    not is_test_file(filename)
    test_file := expected_test_file(filename)
    not test_file_exists(test_file)
}

is_test_file(filename) if contains(filename, "_test")
is_test_file(filename) if contains(filename, ".test")
is_test_file(filename) if startswith(filename, "test_")

expected_test_file(filename) := test_file if {
    ext := extension(filename)
    ext == "go"
    base := trim_suffix(filename, ".go")
    test_file := sprintf("%s_test.go", [base])
}

expected_test_file(filename) := test_file if {
    ext := extension(filename)
    ext in {"js", "ts"}
    base := trim_suffix(filename, sprintf(".%s", [ext]))
    test_file := sprintf("%s.test.%s", [base, ext])
}

expected_test_file(filename) := test_file if {
    ext := extension(filename)
    ext == "py"
    parts := split(filename, "/")
    file := parts[count(parts) - 1]
    base := trim_suffix(file, ".py")
    test_file := sprintf("test_%s.py", [base])
}

test_file_exists(test_file) if {
    some changed_file in input.files
    changed_file.filename == test_file
}

test_file_exists(test_file) if {
    test_file in input.existing_files
}
```

---

## 4. Branch Protection Policies

### 4.1 Protected Branch Enforcement

Prevents direct commits to protected branches.

```rego
package cicd.branch_protection

protected_branches := {"main", "master", "production", "release"}

deny contains sprintf("Direct commits to protected branch '%s' are not allowed", [branch]) if {
    branch := input.target_branch
    branch in protected_branches
    input.event_type == "push"
    not input.via_pull_request
}

deny contains msg if {
    input.target_branch in protected_branches
    input.via_pull_request
    approvals := count(input.pull_request.approvals)
    approvals < 2
    msg := sprintf("Pull request requires at least 2 approvals, found %d", [approvals])
}

deny contains sprintf("Pull request to '%s' requires approval from code owner", [branch]) if {
    branch := input.target_branch
    branch in protected_branches
    not has_codeowner_approval
}

has_codeowner_approval if {
    some approval in input.pull_request.approvals
    approval.user in input.codeowners
}
```

### 4.2 Branch Naming Convention

Enforces branch naming standards.

```rego
package cicd.branch_naming

valid_prefixes := {"feature/", "bugfix/", "hotfix/", "release/", "chore/"}

deny contains sprintf("Branch name '%s' must start with one of: %v", [branch, valid_prefixes]) if {
    branch := input.branch_name
    not branch in {"main", "master", "develop"}
    not has_valid_prefix(branch)
}

has_valid_prefix(branch) if {
    some prefix in valid_prefixes
    startswith(branch, prefix)
}

deny contains sprintf("Branch name '%s' contains invalid characters (use lowercase, hyphens, slashes)", [branch]) if {
    branch := input.branch_name
    not regex.match(`^[a-z0-9/_-]+$`, branch)
}

deny contains sprintf("Branch name '%s' exceeds maximum length of 64 characters", [branch]) if {
    branch := input.branch_name
    count(branch) > 64
}
```

---

## 5. Commit Message Validation

### 5.1 Conventional Commit Format

Enforces conventional commit message format.

```rego
package cicd.commit_validation

conventional_types := {
    "feat", "fix", "docs", "style", "refactor",
    "perf", "test", "build", "ci", "chore", "revert"
}

deny contains sprintf("Commit message must follow conventional format: <type>: <description>") if {
    message := input.commit.message
    not is_conventional_commit(message)
}

is_conventional_commit(message) if {
    lines := split(message, "\n")
    subject := lines[0]
    regex.match(`^[a-z]+(\([a-z0-9-]+\))?!?: .+`, subject)
    type := extract_type(subject)
    type in conventional_types
}

extract_type(subject) := type if {
    parts := regex.find_all_string_submatch_n(`^([a-z]+)`, subject, 1)
    type := parts[0][1]
}

deny contains "Commit message subject line must be 72 characters or less" if {
    message := input.commit.message
    lines := split(message, "\n")
    subject := lines[0]
    count(subject) > 72
}

deny contains "Commit message must have blank line between subject and body" if {
    message := input.commit.message
    lines := split(message, "\n")
    count(lines) > 2
    lines[1] != ""
}
```

### 5.2 Commit Message Content Requirements

Ensures commit messages reference issue tracking.

```rego
package cicd.commit_validation

deny contains "Commit message must reference an issue (e.g., 'fixes #123' or 'relates to PROJ-456')" if {
    message := lower(input.commit.message)
    not contains_issue_reference(message)
    not input.commit.is_merge_commit
}

contains_issue_reference(message) if {
    regex.match(`(fixes|closes|resolves|relates to|refs?) #[0-9]+`, message)
}

contains_issue_reference(message) if {
    regex.match(`[A-Z]+-[0-9]+`, message)
}

deny contains "Commit message must not contain 'WIP' or 'TODO' in subject line" if {
    message := input.commit.message
    lines := split(message, "\n")
    subject := lower(lines[0])
    contains(subject, "wip")
}

deny contains "Commit message must not contain 'WIP' or 'TODO' in subject line" if {
    message := input.commit.message
    lines := split(message, "\n")
    subject := lower(lines[0])
    contains(subject, "todo")
}
```

---

## 6. Deployment Approval Workflows

### 6.1 Environment-Based Approval Requirements

Requires different approval levels for different environments.

```rego
package cicd.deployment

environment_approvals := {
    "production": 2,
    "staging": 1,
    "development": 0,
}

deny contains sprintf("Deployment to '%s' requires %d approvals, found %d", [env, required, actual]) if {
    env := input.deployment.environment
    required := environment_approvals[env]
    actual := count(input.deployment.approvals)
    actual < required
}

deny contains sprintf("Deployment to production requires approval from security team") if {
    input.deployment.environment == "production"
    not has_security_approval
}

has_security_approval if {
    some approval in input.deployment.approvals
    approval.team == "security"
}

deny contains "Production deployments must occur during approved maintenance window" if {
    input.deployment.environment == "production"
    not in_maintenance_window
}

in_maintenance_window if {
    [hour, _, _] := time.clock(time.now_ns())
    day := time.weekday(time.now_ns())
    day in {"Saturday", "Sunday"}
    hour >= 2
    hour <= 6
}
```

### 6.2 Deployment Change Window Validation

Ensures deployments happen during approved time windows.

```rego
package cicd.deployment

# Block deployments during business hours on weekdays
deny contains "Production deployments not allowed during business hours (9 AM - 5 PM weekdays)" if {
    input.deployment.environment == "production"
    not input.deployment.emergency
    is_business_hours
}

is_business_hours if {
    [hour, _, _] := time.clock(time.now_ns())
    day := time.weekday(time.now_ns())
    day in {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}
    hour >= 9
    hour < 17
}

# Require change ticket for production
deny contains "Production deployment requires approved change ticket number" if {
    input.deployment.environment == "production"
    not input.deployment.emergency
    not input.deployment.change_ticket
}

deny contains sprintf("Change ticket '%s' is not in approved status", [ticket]) if {
    input.deployment.environment == "production"
    ticket := input.deployment.change_ticket
    not change_ticket_approved(ticket)
}

change_ticket_approved(ticket) if {
    ticket_status := input.change_tickets[ticket].status
    ticket_status == "approved"
}
```

---

## 7. Artifact Scanning and Signing

### 7.1 Container Image Scanning Requirements

Ensures container images are scanned for vulnerabilities.

```rego
package cicd.artifact_scanning

critical_severity_threshold := 0
high_severity_threshold := 5

deny contains sprintf("Container image has %d critical vulnerabilities (max: %d)", [count, critical_severity_threshold]) if {
    count := input.scan_results.critical_count
    count > critical_severity_threshold
}

deny contains sprintf("Container image has %d high vulnerabilities (max: %d)", [count, high_severity_threshold]) if {
    count := input.scan_results.high_count
    count > high_severity_threshold
}

deny contains sprintf("Container image vulnerability scan is outdated (scanned: %s)", [scan_time]) if {
    scan_time := input.scan_results.scanned_at
    scan_age_hours := (time.now_ns() - time.parse_rfc3339_ns(scan_time)) / 1000000000 / 3600
    scan_age_hours > 24
}

deny contains "Container image must be scanned before deployment" if {
    not input.scan_results
}
```

### 7.2 Artifact Signing Verification

Ensures artifacts are properly signed.

```rego
package cicd.artifact_signing

deny contains "Container image must be signed before deployment to production" if {
    input.deployment.environment == "production"
    not input.artifact.signed
}

deny contains sprintf("Artifact signature verification failed: %s", [error]) if {
    input.artifact.signed
    not input.artifact.signature_valid
    error := input.artifact.signature_error
}

deny contains "Artifact must be signed by trusted key" if {
    input.artifact.signed
    input.artifact.signature_valid
    not signer_is_trusted
}

signer_is_trusted if {
    signer := input.artifact.signer
    signer in data.trusted_signers
}

deny contains sprintf("Artifact signature timestamp %s is too old", [timestamp]) if {
    timestamp := input.artifact.signature_timestamp
    age_hours := (time.now_ns() - time.parse_rfc3339_ns(timestamp)) / 1000000000 / 3600
    age_hours > 168  # 1 week
}
```

---

## 8. Environment Promotion Rules

### 8.1 Sequential Environment Promotion

Ensures code progresses through environments in order.

```rego
package cicd.promotion

environment_order := ["development", "staging", "production"]

deny contains sprintf("Cannot deploy to '%s' without successful deployment to '%s'", [target, previous]) if {
    target := input.deployment.environment
    some i, env in environment_order
    env == target
    i > 0
    previous := environment_order[i - 1]
    not deployed_to_environment(previous)
}

deployed_to_environment(env) if {
    some deployment in input.deployment_history
    deployment.environment == env
    deployment.status == "success"
    deployment.git_sha == input.deployment.git_sha
}

deny contains sprintf("Deployment to '%s' requires at least 24 hours soak time in staging", [env]) if {
    env := input.deployment.environment
    env == "production"
    staging_deployment_time := get_staging_deployment_time
    soak_hours := (time.now_ns() - staging_deployment_time) / 1000000000 / 3600
    soak_hours < 24
}

get_staging_deployment_time := deployment_time if {
    some deployment in input.deployment_history
    deployment.environment == "staging"
    deployment.git_sha == input.deployment.git_sha
    deployment.status == "success"
    deployment_time := time.parse_rfc3339_ns(deployment.completed_at)
}
```

### 8.2 Production Promotion Gates

Enforces quality gates before production deployment.

```rego
package cicd.promotion

deny contains "All automated tests must pass before production deployment" if {
    input.deployment.environment == "production"
    not all_tests_passing
}

all_tests_passing if {
    input.test_results.unit.status == "passed"
    input.test_results.integration.status == "passed"
    input.test_results.e2e.status == "passed"
}

deny contains sprintf("Performance benchmarks degraded by %.2f%%", [degradation]) if {
    input.deployment.environment == "production"
    baseline := input.performance_benchmarks.baseline
    current := input.performance_benchmarks.current
    degradation := ((baseline - current) / baseline) * 100
    degradation > 10  # More than 10% degradation
}

deny contains "Production deployment requires sign-off from product owner" if {
    input.deployment.environment == "production"
    not has_product_owner_signoff
}

has_product_owner_signoff if {
    some approval in input.deployment.approvals
    approval.role == "product_owner"
}
```

---

## 9. Rollback Policies and Safeguards

### 9.1 Automated Rollback Triggers

Defines conditions for automatic rollback.

```rego
package cicd.rollback

require_rollback contains "Error rate exceeds 5% threshold" if {
    error_rate := input.metrics.error_rate_percent
    error_rate > 5.0
}

require_rollback contains sprintf("Response time degraded by %.2f%%", [degradation]) if {
    baseline := input.metrics.baseline_response_time_ms
    current := input.metrics.current_response_time_ms
    degradation := ((current - baseline) / baseline) * 100
    degradation > 50
}

require_rollback contains "Health check failures exceed threshold" if {
    failures := input.metrics.health_check_failures
    total := input.metrics.health_check_total
    failure_rate := (failures / total) * 100
    failure_rate > 10
}

require_rollback contains "Critical alerts triggered" if {
    some alert in input.alerts
    alert.severity == "critical"
    alert.status == "firing"
}
```

### 9.2 Rollback Approval Requirements

Ensures rollbacks follow proper procedures.

```rego
package cicd.rollback

deny contains "Rollback must include incident ticket reference" if {
    input.action == "rollback"
    not input.incident_ticket
}

deny contains "Rollback requires approval from on-call engineer" if {
    input.action == "rollback"
    input.environment == "production"
    not has_oncall_approval
}

has_oncall_approval if {
    some approval in input.approvals
    approval.is_oncall
}

warning contains "Consider creating postmortem for production rollback" if {
    input.action == "rollback"
    input.environment == "production"
    not input.postmortem_created
}
```

---

## 10. Build Configuration Validation

### 10.1 Dockerfile Best Practices

Validates Dockerfile security and best practices.

```rego
package cicd.dockerfile

deny contains "Dockerfile must not use latest tag for base images" if {
    some instruction in input.dockerfile.instructions
    instruction.cmd == "FROM"
    contains(instruction.value, ":latest")
}

deny contains sprintf("Dockerfile must not run as root user (found USER %s)", [user]) if {
    not has_user_instruction
    not uses_nonroot_base_image
}

deny contains "Dockerfile should use specific package versions" if {
    some instruction in input.dockerfile.instructions
    instruction.cmd == "RUN"
    contains(instruction.value, "apt-get install")
    not contains(instruction.value, "=")
}

has_user_instruction if {
    some instruction in input.dockerfile.instructions
    instruction.cmd == "USER"
    instruction.value != "root"
    instruction.value != "0"
}

deny contains "Dockerfile must include HEALTHCHECK instruction" if {
    not has_healthcheck
}

has_healthcheck if {
    some instruction in input.dockerfile.instructions
    instruction.cmd == "HEALTHCHECK"
}

deny contains "Dockerfile should use multi-stage builds to reduce image size" if {
    from_count := count([i | some i in input.dockerfile.instructions; i.cmd == "FROM"])
    from_count == 1
    final_size_mb := input.image_size_bytes / 1024 / 1024
    final_size_mb > 500
}
```

### 10.2 CI Pipeline Configuration Validation

Validates GitHub Actions or GitLab CI configuration.

```rego
package cicd.pipeline_config

deny contains "CI pipeline must include security scanning job" if {
    not has_security_scan_job
}

has_security_scan_job if {
    some job_name, job in input.workflow.jobs
    contains(lower(job_name), "security")
}

has_security_scan_job if {
    some job_name, job in input.workflow.jobs
    some step in job.steps
    contains(lower(step.name), "security scan")
}

deny contains "CI pipeline must run tests before build" if {
    test_job := get_job_by_name("test")
    build_job := get_job_by_name("build")
    not build_job.needs[_] == "test"
}

deny contains sprintf("Job '%s' missing required timeout", [job_name]) if {
    some job_name, job in input.workflow.jobs
    not job.timeout_minutes
}

deny contains sprintf("Job '%s' timeout exceeds maximum of 60 minutes", [job_name]) if {
    some job_name, job in input.workflow.jobs
    job.timeout_minutes > 60
}
```

---

## 11. Dependency Vulnerability Scanning

### 11.1 Dependency Vulnerability Thresholds

Blocks builds with vulnerable dependencies.

```rego
package cicd.dependency_scanning

deny contains sprintf("Found %d critical vulnerabilities in dependencies", [count]) if {
    count := count([v | some v in input.vulnerabilities; v.severity == "critical"])
    count > 0
}

deny contains sprintf("Found %d high vulnerabilities in dependencies", [count]) if {
    count := count([v | some v in input.vulnerabilities; v.severity == "high"])
    count > 5
}

deny contains sprintf("Dependency '%s' has known vulnerability %s", [dep, cve]) if {
    some vuln in input.vulnerabilities
    vuln.severity in {"critical", "high"}
    not has_exception(vuln.cve)
    dep := vuln.package
    cve := vuln.cve
}

has_exception(cve) if {
    some exception in input.vulnerability_exceptions
    exception.cve == cve
    exception.status == "approved"
    not is_expired(exception.expires_at)
}

is_expired(expires_at) if {
    expiry := time.parse_rfc3339_ns(expires_at)
    expiry < time.now_ns()
}
```

### 11.2 Dependency Update Requirements

Ensures dependencies are kept up to date.

```rego
package cicd.dependency_scanning

deny contains sprintf("Dependency '%s' is %d days behind latest version", [dep, days]) if {
    some dependency in input.dependencies
    dep := dependency.name
    current := dependency.current_version
    latest := dependency.latest_version
    current != latest
    days := dependency.days_behind_latest
    days > 90
    not is_major_version_change(current, latest)
}

is_major_version_change(current, latest) if {
    current_parts := split(current, ".")
    latest_parts := split(latest, ".")
    current_parts[0] != latest_parts[0]
}

warning contains sprintf("Dependency '%s' has available security update", [dep]) if {
    some dependency in input.dependencies
    dep := dependency.name
    dependency.security_update_available
}
```

---

## 12. License Compliance Checking

### 12.1 Allowed License Validation

Ensures dependencies use approved licenses.

```rego
package cicd.license_compliance

approved_licenses := {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
}

copyleft_licenses := {
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
}

deny contains sprintf("Dependency '%s' uses unapproved license: %s", [dep, license]) if {
    some dependency in input.dependencies
    dep := dependency.name
    license := dependency.license
    not license in approved_licenses
    not license in copyleft_licenses
}

deny contains sprintf("Dependency '%s' uses copyleft license '%s' which may require legal review", [dep, license]) if {
    some dependency in input.dependencies
    dep := dependency.name
    license := dependency.license
    license in copyleft_licenses
    not has_legal_exception(dep)
}

deny contains sprintf("Dependency '%s' has no license information", [dep]) if {
    some dependency in input.dependencies
    dep := dependency.name
    not dependency.license
}

has_legal_exception(dep) if {
    some exception in input.legal_exceptions
    exception.package == dep
    exception.status == "approved"
}
```

### 12.2 License Header Validation

Ensures source files contain required license headers.

```rego
package cicd.license_compliance

required_header := `Copyright (c) 2024 Example Corp. All rights reserved.
Licensed under the Apache License, Version 2.0`

source_file_extensions := {"go", "py", "js", "ts", "java", "rs"}

deny contains sprintf("File '%s' missing required license header", [filename]) if {
    some changed_file in input.files
    changed_file.status == "added"
    filename := changed_file.filename
    ext := extension(filename)
    ext in source_file_extensions
    content := changed_file.content
    not has_license_header(content)
}

has_license_header(content) if {
    lines := split(content, "\n")
    header_lines := [l | some l in lines; count(l) > 0][0:5]
    header_text := concat("\n", header_lines)
    contains(header_text, "Copyright")
    contains(header_text, "License")
}
```

---

## 13. Code Quality Gate Enforcement

### 13.1 Code Quality Metrics

Enforces quality thresholds on code metrics.

```rego
package cicd.quality_gates

deny contains sprintf("Code complexity score %.2f exceeds maximum of 10", [complexity]) if {
    some file in input.quality_metrics.files
    complexity := file.complexity_score
    complexity > 10
}

deny contains sprintf("Function '%s' exceeds maximum length of 50 lines", [func]) if {
    some file in input.quality_metrics.files
    some function in file.functions
    func := function.name
    function.line_count > 50
}

deny contains sprintf("File '%s' has %d code smells", [filename, count]) if {
    some file in input.quality_metrics.files
    filename := file.name
    count := count(file.code_smells)
    count > 10
}

deny contains "Code duplication exceeds 5% threshold" if {
    duplication := input.quality_metrics.duplication_percent
    duplication > 5.0
}

deny contains sprintf("Technical debt ratio %.2f%% exceeds maximum of 10%%", [ratio]) if {
    ratio := input.quality_metrics.technical_debt_ratio
    ratio > 10.0
}
```

### 13.2 Static Analysis Requirements

Ensures static analysis tools are run and pass.

```rego
package cicd.quality_gates

deny contains sprintf("Static analysis tool '%s' found %d issues", [tool, count]) if {
    some tool, results in input.static_analysis
    count := count(results.issues)
    count > 0
}

deny contains "ESLint must pass with no errors" if {
    eslint := input.static_analysis.eslint
    eslint.error_count > 0
}

deny contains sprintf("Found %d linting warnings (max: 10)", [count]) if {
    eslint := input.static_analysis.eslint
    count := eslint.warning_count
    count > 10
}

deny contains "Go code must be formatted with gofmt" if {
    gofmt := input.static_analysis.gofmt
    count(gofmt.unformatted_files) > 0
}
```

---

## 14. Container Image Scanning in CI

### 14.1 Base Image Compliance

Validates base images meet security requirements.

```rego
package cicd.container_scanning

approved_base_images := {
    "alpine:3.18",
    "ubuntu:22.04",
    "debian:bookworm-slim",
    "gcr.io/distroless/base-debian12",
}

deny contains sprintf("Base image '%s' is not in approved list", [image]) if {
    base_image := input.dockerfile.base_image
    not base_image in approved_base_images
    not is_approved_registry(base_image)
}

is_approved_registry(image) if {
    startswith(image, "mycompany.azurecr.io/")
}

is_approved_registry(image) if {
    startswith(image, "gcr.io/mycompany/")
}

deny contains "Container image must not contain high-risk packages" if {
    some package in input.scan_results.packages
    package.name in high_risk_packages
}

high_risk_packages := {"telnet", "ftp", "rsh", "wget"}

deny contains sprintf("Container image contains %d unnecessary packages", [count]) if {
    count := count([p | some p in input.scan_results.packages;
                    p.name in unnecessary_packages])
    count > 0
}

unnecessary_packages := {"vim", "nano", "curl", "netcat"}
```

### 14.2 Container Security Scanning

Validates container security configuration.

```rego
package cicd.container_scanning

deny contains "Container must not run privileged" if {
    input.container_config.privileged == true
}

deny contains "Container must not use host network" if {
    input.container_config.network_mode == "host"
}

deny contains "Container should define resource limits" if {
    not input.container_config.resources.limits.memory
}

deny contains "Container should define resource limits" if {
    not input.container_config.resources.limits.cpu
}

deny contains sprintf("Container exposes privileged port %d", [port]) if {
    some port in input.container_config.exposed_ports
    port < 1024
}

deny contains "Container should use read-only root filesystem" if {
    not input.container_config.read_only_root_filesystem
}
```

---

## 15. Secrets Detection in Code

### 15.1 Secret Pattern Detection

Detects potential secrets in code changes.

```rego
package cicd.secrets_detection

secret_patterns := {
    "aws_key": `AKIA[0-9A-Z]{16}`,
    "github_token": `ghp_[a-zA-Z0-9]{36}`,
    "private_key": `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`,
    "password": `(password|passwd|pwd)\s*=\s*['"][^'"]{8,}['"]`,
    "api_key": `api[_-]?key\s*[:=]\s*['"][^'"]{20,}['"]`,
}

deny contains sprintf("File '%s' contains potential %s", [filename, secret_type]) if {
    some changed_file in input.files
    filename := changed_file.filename
    content := changed_file.content
    some secret_type, pattern in secret_patterns
    regex.match(pattern, content)
}

deny contains sprintf("File '%s' contains high-entropy string that may be a secret", [filename]) if {
    some changed_file in input.files
    filename := changed_file.filename
    changed_file.status in {"added", "modified"}
    some line in split(changed_file.content, "\n")
    has_high_entropy_string(line)
}

has_high_entropy_string(line) if {
    strings := extract_quoted_strings(line)
    some str in strings
    count(str) > 20
    entropy(str) > 4.5
}

extract_quoted_strings(line) := strings if {
    matches := regex.find_all_string_submatch_n(`["']([^"']{20,})["']`, line, -1)
    strings := [m[1] | some m in matches]
}

# Simplified entropy calculation
entropy(str) := score if {
    chars := {c | some c in str}
    score := count(chars) / count(str) * 10
}
```

### 15.2 Secrets File Detection

Prevents committing common secret files.

```rego
package cicd.secrets_detection

forbidden_files := {
    ".env",
    ".env.local",
    ".env.production",
    "secrets.yml",
    "secrets.yaml",
    "credentials.json",
    "service-account.json",
    "id_rsa",
    "id_dsa",
    ".pem",
    ".key",
}

deny contains sprintf("File '%s' should not be committed to repository", [filename]) if {
    some changed_file in input.files
    filename := changed_file.filename
    base_name := base_filename(filename)
    base_name in forbidden_files
}

deny contains sprintf("File '%s' with extension '.%s' should not be committed", [filename, ext]) if {
    some changed_file in input.files
    filename := changed_file.filename
    ext := extension(filename)
    ext in {"pem", "key", "p12", "pfx", "jks"}
}

base_filename(path) := name if {
    parts := split(path, "/")
    name := parts[count(parts) - 1]
}
```

---

## 16. Performance Regression Detection

### 16.1 Benchmark Performance Gates

Detects performance regressions in benchmarks.

```rego
package cicd.performance

max_regression_percent := 10

deny contains sprintf("Benchmark '%s' regressed by %.2f%%", [name, regression]) if {
    some benchmark in input.benchmarks
    name := benchmark.name
    baseline := benchmark.baseline_ns_per_op
    current := benchmark.current_ns_per_op
    regression := ((current - baseline) / baseline) * 100
    regression > max_regression_percent
}

deny contains sprintf("Memory usage increased by %.2f%% for '%s'", [increase, name]) if {
    some benchmark in input.benchmarks
    name := benchmark.name
    baseline_mem := benchmark.baseline_bytes_per_op
    current_mem := benchmark.current_bytes_per_op
    increase := ((current_mem - baseline_mem) / baseline_mem) * 100
    increase > 15
}

warning contains sprintf("Allocations increased for '%s': %d -> %d", [name, baseline, current]) if {
    some benchmark in input.benchmarks
    name := benchmark.name
    baseline := benchmark.baseline_allocs_per_op
    current := benchmark.current_allocs_per_op
    current > baseline
}
```

### 16.2 Load Test Thresholds

Validates load test results meet SLA requirements.

```rego
package cicd.performance

sla_response_time_ms := 200
sla_error_rate_percent := 0.1

deny contains sprintf("Average response time %.2fms exceeds SLA of %dms", [avg, sla_response_time_ms]) if {
    avg := input.load_test.avg_response_time_ms
    avg > sla_response_time_ms
}

deny contains sprintf("P95 response time %.2fms exceeds threshold of %dms", [p95, threshold]) if {
    p95 := input.load_test.p95_response_time_ms
    threshold := sla_response_time_ms * 2
    p95 > threshold
}

deny contains sprintf("Error rate %.2f%% exceeds SLA of %.2f%%", [rate, sla_error_rate_percent]) if {
    rate := input.load_test.error_rate_percent
    rate > sla_error_rate_percent
}

deny contains sprintf("Throughput %d req/s is below minimum of 1000 req/s", [throughput]) if {
    throughput := input.load_test.requests_per_second
    throughput < 1000
}
```

---

## 17. Documentation Requirements

### 17.1 Documentation Update Requirements

Ensures documentation is updated with code changes.

```rego
package cicd.documentation

significant_change_threshold := 10  # files

deny contains "Significant changes require documentation updates" if {
    changed_files := count(input.files)
    changed_files > significant_change_threshold
    not has_doc_changes
}

has_doc_changes if {
    some changed_file in input.files
    extension(changed_file.filename) == "md"
}

has_doc_changes if {
    some changed_file in input.files
    startswith(changed_file.filename, "docs/")
}

deny contains sprintf("New API endpoint '%s' requires documentation", [endpoint]) if {
    some changed_file in input.files
    contains(changed_file.filename, "routes")
    changed_file.status in {"added", "modified"}
    some line in split(changed_file.content, "\n")
    endpoint := extract_endpoint(line)
    not endpoint_documented(endpoint)
}

extract_endpoint(line) := endpoint if {
    regex.match(`@(Get|Post|Put|Delete|Patch)\(['"]([^'"]+)['"]`, line)
    matches := regex.find_all_string_submatch_n(`@(Get|Post|Put|Delete|Patch)\(['"]([^'"]+)['"]`, line, 1)
    endpoint := matches[0][2]
}

endpoint_documented(endpoint) if {
    some doc_file in input.files
    contains(doc_file.filename, "README")
    contains(doc_file.content, endpoint)
}

endpoint_documented(endpoint) if {
    some doc_file in input.files
    extension(doc_file.filename) == "md"
    contains(doc_file.content, endpoint)
}
```

### 17.2 README Completeness Check

Validates README contains required sections.

```rego
package cicd.documentation

required_readme_sections := {
    "Installation",
    "Usage",
    "Configuration",
    "Contributing",
    "License",
}

deny contains sprintf("README.md missing required section: %s", [section]) if {
    readme := get_readme_content
    some section in required_readme_sections
    not contains_section(readme, section)
}

get_readme_content := content if {
    some file in input.files
    contains(file.filename, "README.md")
    content := file.content
}

contains_section(content, section) if {
    contains(content, sprintf("## %s", [section]))
}

contains_section(content, section) if {
    contains(content, sprintf("# %s", [section]))
}
```

---

## 18. Release Note Generation Validation

### 18.1 Release Notes Required for Version Bumps

Ensures release notes accompany version changes.

```rego
package cicd.release_notes

deny contains "Version bump requires release notes" if {
    version_changed
    not has_release_notes
}

version_changed if {
    some changed_file in input.files
    changed_file.filename in {"package.json", "pom.xml", "Cargo.toml", "pyproject.toml"}
    changed_file.status == "modified"
}

has_release_notes if {
    some changed_file in input.files
    contains(changed_file.filename, "CHANGELOG")
}

has_release_notes if {
    some changed_file in input.files
    startswith(changed_file.filename, "release-notes/")
}

deny contains "CHANGELOG.md must include version number and date" if {
    has_release_notes
    changelog := get_changelog
    not contains_version_header(changelog)
}

get_changelog := content if {
    some file in input.files
    contains(file.filename, "CHANGELOG")
    content := file.content
}

contains_version_header(content) if {
    regex.match(`## \[?\d+\.\d+\.\d+\]? - \d{4}-\d{2}-\d{2}`, content)
}
```

### 18.2 Release Notes Content Validation

Validates quality and completeness of release notes.

```rego
package cicd.release_notes

changelog_sections := {"Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"}

warning contains sprintf("CHANGELOG missing recommended section: %s", [section]) if {
    changelog := get_changelog
    some section in changelog_sections
    not contains(changelog, sprintf("### %s", [section]))
    has_relevant_changes(section)
}

has_relevant_changes("Added") if {
    some file in input.files
    file.status == "added"
}

has_relevant_changes("Fixed") if {
    some file in input.files
    commit_message := input.commit.message
    contains(lower(commit_message), "fix")
}

has_relevant_changes("Security") if {
    some file in input.files
    commit_message := input.commit.message
    contains(lower(commit_message), "security")
}

deny contains "Release notes must include breaking changes section if major version bumped" if {
    is_major_version_bump
    changelog := get_changelog
    not contains(lower(changelog), "breaking")
}

is_major_version_bump if {
    old_version := input.version_info.old_version
    new_version := input.version_info.new_version
    old_parts := split(old_version, ".")
    new_parts := split(new_version, ".")
    old_parts[0] != new_parts[0]
}
```

---

## 19. Feature Flag Validation

### 19.1 Feature Flag Configuration Validation

Ensures feature flags are properly configured.

```rego
package cicd.feature_flags

deny contains sprintf("Feature flag '%s' missing required metadata", [flag]) if {
    some flag, config in input.feature_flags
    not config.description
}

deny contains sprintf("Feature flag '%s' missing owner", [flag]) if {
    some flag, config in input.feature_flags
    not config.owner
}

deny contains sprintf("Feature flag '%s' missing expiration date", [flag]) if {
    some flag, config in input.feature_flags
    not config.expires_at
}

deny contains sprintf("Feature flag '%s' has expired", [flag]) if {
    some flag, config in input.feature_flags
    expires_at := time.parse_rfc3339_ns(config.expires_at)
    expires_at < time.now_ns()
}

warning contains sprintf("Feature flag '%s' expires in less than 30 days", [flag]) if {
    some flag, config in input.feature_flags
    expires_at := time.parse_rfc3339_ns(config.expires_at)
    days_until_expiry := (expires_at - time.now_ns()) / 1000000000 / 86400
    days_until_expiry < 30
    days_until_expiry > 0
}
```

### 19.2 Feature Flag Cleanup Detection

Identifies stale feature flags that should be removed.

```rego
package cicd.feature_flags

deny contains sprintf("Feature flag '%s' enabled at 100%% for over 60 days - consider removing", [flag]) if {
    some flag, config in input.feature_flags
    config.rollout_percentage == 100
    created_at := time.parse_rfc3339_ns(config.created_at)
    age_days := (time.now_ns() - created_at) / 1000000000 / 86400
    age_days > 60
}

deny contains sprintf("Feature flag '%s' never used in code", [flag]) if {
    some flag, config in input.feature_flags
    not flag_referenced_in_code(flag)
}

flag_referenced_in_code(flag) if {
    some file in input.source_files
    contains(file.content, flag)
}

warning contains sprintf("Feature flag '%s' used in %d places - consider refactoring", [flag, count]) if {
    some flag, config in input.feature_flags
    references := [1 | some file in input.source_files;
                   some line in split(file.content, "\n");
                   contains(line, flag)]
    count := count(references)
    count > 10
}
```

---

## 20. Pipeline Dependency Validation

### 20.1 Job Dependency Requirements

Ensures CI/CD jobs have proper dependencies.

```rego
package cicd.pipeline_dependencies

# Test must run before build
deny contains "Build job must depend on test job" if {
    some job_name, job in input.pipeline.jobs
    job_name == "build"
    not has_dependency(job, "test")
}

# Deployment must depend on build and scan
deny contains sprintf("Deploy job '%s' must depend on build and security-scan", [job_name]) if {
    some job_name, job in input.pipeline.jobs
    startswith(job_name, "deploy")
    not has_dependency(job, "build")
}

deny contains sprintf("Deploy job '%s' must depend on security-scan", [job_name]) if {
    some job_name, job in input.pipeline.jobs
    startswith(job_name, "deploy")
    not has_dependency(job, "security-scan")
}

has_dependency(job, dep_name) if {
    some dep in job.depends_on
    dep == dep_name
}

has_dependency(job, dep_name) if {
    some dep in job.needs
    dep == dep_name
}

# Prevent circular dependencies
deny contains sprintf("Circular dependency detected: %v", [cycle]) if {
    cycle := detect_cycle
    count(cycle) > 0
}

detect_cycle := cycle if {
    some job_name, job in input.pipeline.jobs
    cycle := find_cycle(job_name, [])
    count(cycle) > 0
}

find_cycle(job_name, visited) := cycle if {
    job_name in visited
    cycle := array.concat(visited, [job_name])
}

find_cycle(job_name, visited) := cycle if {
    not job_name in visited
    job := input.pipeline.jobs[job_name]
    some dep in job.depends_on
    cycle := find_cycle(dep, array.concat(visited, [job_name]))
}

default find_cycle(_, _) := []
```

### 20.2 Parallel Job Optimization

Identifies opportunities for parallel execution.

```rego
package cicd.pipeline_dependencies

warning contains sprintf("Jobs '%s' and '%s' can run in parallel", [job1, job2]) if {
    some job1, config1 in input.pipeline.jobs
    some job2, config2 in input.pipeline.jobs
    job1 < job2  # Avoid duplicate pairs
    not jobs_have_dependency(job1, job2)
    not jobs_have_dependency(job2, job1)
    jobs_can_parallelize(config1, config2)
}

jobs_have_dependency(job1, job2) if {
    config := input.pipeline.jobs[job1]
    some dep in config.depends_on
    dep == job2
}

jobs_can_parallelize(config1, config2) if {
    # Jobs that don't share resources can run in parallel
    not shares_resources(config1, config2)
}

shares_resources(config1, config2) if {
    config1.runner == config2.runner
    config1.concurrent == false
}

shares_resources(config1, config2) if {
    config2.concurrent == false
}
```

---

## Summary

These 20 examples demonstrate comprehensive CI/CD pipeline policy enforcement using Rego:

1. **File Validation** - Syntax checking for YAML, JSON, TOML
2. **PR Change Detection** - Smart test routing based on changes
3. **Test Coverage** - Minimum thresholds and trend validation
4. **Branch Protection** - Protected branch and naming enforcement
5. **Commit Messages** - Conventional commits and content requirements
6. **Deployment Approvals** - Environment-based approval workflows
7. **Artifact Scanning** - Container vulnerability and signature verification
8. **Environment Promotion** - Sequential progression and quality gates
9. **Rollback Policies** - Automated triggers and approval requirements
10. **Build Configuration** - Dockerfile and pipeline validation
11. **Dependency Scanning** - Vulnerability and update requirements
12. **License Compliance** - Approved licenses and header validation
13. **Code Quality Gates** - Metrics and static analysis enforcement
14. **Container Scanning** - Base image and security validation
15. **Secrets Detection** - Pattern matching and file prevention
16. **Performance Regression** - Benchmark and load test validation
17. **Documentation** - Update requirements and completeness checks
18. **Release Notes** - Version bump and content validation
19. **Feature Flags** - Configuration and cleanup detection
20. **Pipeline Dependencies** - Job ordering and parallel optimization

Each policy can be customized to match your organization's specific requirements and integrated into GitHub Actions, GitLab CI, Jenkins, or other CI/CD platforms using OPA's `eval` command.
