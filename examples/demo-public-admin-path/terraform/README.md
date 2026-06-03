# Terraform Source Shape

The committed `tfplan.json` fixture is sanitized and minimal so the demo can run without AWS credentials.

This directory is reserved for a future live Terraform source version of the same scenario. A live version should be plan-only by default, should not require `terraform apply`, and should use a disposable sandbox account if provider data lookups are needed.

Until then, use the root demo fixture:

```bash
changegate scan --plan examples/demo-public-admin-path/tfplan.json
```

