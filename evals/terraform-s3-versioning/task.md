# Terraform: S3 Bucket Versioning

We use OPA to validate Terraform plans before they are applied. Write a Rego policy that prevents S3 buckets from being created or updated without versioning enabled.

The policy must handle both ways versioning can be configured:
1. Inline on the `aws_s3_bucket` resource (via the `versioning` block with `enabled = true`)
2. As a separate `aws_s3_bucket_versioning` resource (where `versioning_configuration.status` must be `"Enabled"`)

The policy must support both raw Terraform input and HCP Terraform / Terraform Enterprise input.
