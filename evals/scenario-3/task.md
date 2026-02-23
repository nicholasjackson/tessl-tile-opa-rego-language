# Task: HTTP API Authorization Policy

Write a Rego policy for our API gateway. Every incoming request is checked by OPA before it reaches the service. Users authenticate with a JWT bearer token.

The API is defined in `openapi.yaml`. The policy should allow users to read their own salary record and allow managers to read their subordinates' salary records. All other requests should be denied.
