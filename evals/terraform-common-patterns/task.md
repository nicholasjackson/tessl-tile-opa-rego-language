# Terraform: Common Patterns

Write a minimal OPA policy for Terraform plan validation. The policy should deny `aws_s3_bucket` resources being created without a `bucket_prefix` attribute set.

The policy must work correctly with both raw Terraform input (where `resource_changes` is at `input.resource_changes`) and HCP Terraform / Terraform Enterprise input (where the plan is nested under `input.plan`).
