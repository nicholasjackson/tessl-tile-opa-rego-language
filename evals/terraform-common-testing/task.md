# Terraform: Common Testing Pattern

Write a Rego policy that denies `aws_s3_bucket` resources being created without a `bucket_prefix` attribute set.

Also write a `_test.rego` file that tests the policy. The test file must use the `_test` package suffix, mock Terraform plan JSON input using `with input as`, and include both a passing case (bucket with `bucket_prefix` set) and a failing case (bucket without `bucket_prefix`).
