# Task: Terraform Plan Validation Policy

We use OPA to validate Terraform plans before they are applied. Write a Rego policy that prevents `aws_security_group` resources from allowing inbound SSH access (port 22) from the internet.

The policy must support both raw Terraform input (where `resource_changes` is at `input.resource_changes`) and HCP Terraform / Terraform Enterprise input (where the plan is nested under `input.plan`, so `resource_changes` is at `input.plan.resource_changes`).
