# Terraform: S3 Bucket Encryption

We use OPA to validate Terraform plans before they are applied. Write a Rego policy that prevents S3 buckets from being created without server-side encryption.

The policy must handle both ways encryption can be configured:
1. Inline on the `aws_s3_bucket` resource (via the `server_side_encryption_configuration` block)
2. As a separate `aws_s3_bucket_server_side_encryption_configuration` resource

Valid encryption algorithms are `AES256` and `aws:kms`.

The policy must support both raw Terraform input and HCP Terraform / Terraform Enterprise input.
