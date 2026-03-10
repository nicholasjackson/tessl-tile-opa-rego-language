# OPA / Rego Language Tile

## Description

This tile teaches AI agents how to write correct, idiomatic [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies using [Open Policy Agent (OPA)](https://www.openpolicyagent.org/). It covers the full range of OPA use cases and enforces best practices through steering rules and curated reference documentation.

### What AI agents learn from this tile

**Policy domains covered:**
- **Kubernetes admission control** — OPA webhook policies and OPA Gatekeeper `ConstraintTemplate` policies
- **Infrastructure-as-Code validation** — Terraform plan validation (raw Terraform and HCP Terraform/Enterprise input structures), AWS CloudFormation hook policies
- **Container security** — Docker daemon authorization with `opa-docker-authz`
- **HTTP API authorization** — JWT-authenticated API gateway policies driven by OpenAPI specs
- **RBAC / access control** — Role-based and attribute-based access control patterns
- **Policy testing** — Test-driven development with `opa test`, mocking with `with`, parameterised tests
- **Metadata annotations** — `# METADATA` blocks, entrypoints, severity classification, `opa inspect`

**Key patterns enforced:**
- Write tests first (TDD) before implementing policies
- Use `import rego.v1` and OPA 1.0 syntax (`if`, `contains`, `some...in`, `every`)
- Normalize Terraform plan input with `tfplan := object.get(input, "plan", input)` for HCP Terraform compatibility
- Default-deny security posture
- Structured violation messages via `deny contains msg if { ... }`
- `object.get` for safe field access with defaults
- Check both `create` and `update` actions in IaC policies