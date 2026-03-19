# Terraform: Tag Compliance Policy

Write a Rego policy in the package `terraform.compliance` that validates a Terraform resource's tags. The policy should:

1. Use `object.keys(input.resource.tags)` to get the set of provided tag keys (not a comprehension)
2. Define `required_tags` as `{"environment", "owner", "cost_center"}`
3. Compute `missing_tags` using set subtraction
4. Add a `deny` violation when any required tags are missing, using `sprintf` to list the missing tags

## Input

```json
{
  "resource": {
    "type": "aws_instance",
    "name": "web-server",
    "tags": {
      "environment": "production",
      "owner": "platform-team"
    }
  }
}
```

## Expected behaviour

- All tags present → no `deny` violations
- Missing `cost_center` tag → deny message listing `{"cost_center"}`
- Empty tags → deny listing all three required tags
