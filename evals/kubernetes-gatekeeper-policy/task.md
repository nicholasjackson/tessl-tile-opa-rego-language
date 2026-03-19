# Kubernetes: Gatekeeper Policy

We use OPA Gatekeeper in our cluster. Write the Rego policy for a ConstraintTemplate that enforces required labels on Deployments. The required labels should be configurable via constraint parameters.

Also write a `_test.rego` file with tests for the policy, including both a positive case (labels present, no violation) and a negative case (labels missing, violation triggered).
