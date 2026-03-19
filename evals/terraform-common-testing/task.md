# Terraform: Common Testing Pattern

Write a Rego policy that denies `aws_s3_bucket` resources being created without a `bucket_prefix` attribute set.

Also write a `_test.rego` file that tests the policy. The test file must be named with the `_test.rego` suffix, use the `_test` package suffix, prefix all test functions with `test_`, mock Terraform plan JSON input using `with input as`, and include both a passing case (bucket with `bucket_prefix` set) and a failing case (bucket without `bucket_prefix`).

## Input

The policy receives a Terraform plan in the standard `terraform show -json` format:

```json
{
  "resource_changes": [
    {
      "type": "aws_s3_bucket",
      "change": {
        "actions": ["create"],
        "after": {
          "bucket_prefix": "my-prefix-"
        }
      }
    }
  ]
}
```

## Expected behaviour

- Deny `aws_s3_bucket` resources with `create` or `update` actions that are missing `bucket_prefix`
- Allow `aws_s3_bucket` resources that have `bucket_prefix` set
- Allow resources of other types regardless of attributes
- The deny message should include the resource type
