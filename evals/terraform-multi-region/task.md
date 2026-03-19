# Terraform: Multi-Region Deployment Policies

We use OPA to validate Terraform plans before they are applied. Write a Rego policy that enforces region and data residency requirements.

The policy must:
1. Deny the plan if the AWS provider region is not in the approved set: `us-east-1`, `us-west-2`, `eu-west-1`, `eu-central-1`
2. Deny creation of `aws_s3_bucket`, `aws_rds_cluster`, or `aws_dynamodb_table` resources tagged `DataResidency = "EU"` in a non-EU region (`eu-west-1` and `eu-central-1` are EU regions)
3. Warn (but do not deny) when `aws_s3_bucket` or `aws_dynamodb_table` resources tagged `Criticality = "high"` are created without replication configured

The AWS provider region is available at `tfplan.configuration.provider_config.aws.expressions.region.constant_value`.

Replication for S3 is indicated by the presence of `r.change.after.replication_configuration`; for DynamoDB by `count(r.change.after.replica) > 0`.

The policy must support both raw Terraform input and HCP Terraform / Terraform Enterprise input.
