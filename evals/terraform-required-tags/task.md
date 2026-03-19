# Terraform: Required Tags Enforcement

We use OPA to validate Terraform plans before they are applied. Write a Rego policy that enforces mandatory tags on all taggable AWS resources.

Every `aws_instance`, `aws_s3_bucket`, `aws_rds_cluster`, `aws_lambda_function`, `aws_dynamodb_table`, and `aws_ebs_volume` that is being created or updated (but not deleted) must have the following tags present and non-empty:

- `Environment`
- `Owner`
- `CostCenter`
- `Project`

The policy must support both raw Terraform input and HCP Terraform / Terraform Enterprise input.
