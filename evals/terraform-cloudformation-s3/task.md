# Terraform: CloudFormation Hook — S3 Bucket Access Control

We use OPA as a CloudFormation hook to validate resources before they are deployed. Write a Rego policy for an `AWS::S3::Bucket` hook that enforces private access control.

The policy must deny bucket creation or update when:
1. The `AccessControl` property is not `"Private"`
2. `PublicAccessBlockConfiguration.BlockPublicAcls` is not `"true"`
3. `PublicAccessBlockConfiguration.BlockPublicPolicy` is not `"true"`

The hook receives input in the CloudFormation hook format: `input.resource.type`, `input.action` (uppercase: `"CREATE"` or `"UPDATE"`), `input.resource.id`, and `input.resource.properties`.

The policy response must be a `main` object with `allow` (boolean) and `violations` (set of messages).
