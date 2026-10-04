# CLI Reference

This page documents all command-line options for OSPA tools.

## Agent Command

The main audit agent that discovers and audits OpenStack resources.

```bash
go run ./cmd/agent [flags]
```

### Required Flags

| Flag | Description |
|------|-------------|
| `--cloud` | Cloud name from clouds.yaml |
| `--policy` | Path to policy YAML file |

### Optional Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--out` | `stdout` | Output file path |
| `--out-format` | `json` | Output format: `json` or `csv` |
| `--fix` | `false` | Enable remediation actions |
| `--all-tenants` | `false` | Audit all tenants (requires admin) |
| `--allow-actions` | `all` | Comma-separated list of allowed actions |
| `--workers` | `16` | Number of concurrent workers |
| `--verbose` | `false` | Enable verbose logging |

### Examples

```bash
# Audit only (safe mode)
go run ./cmd/agent \
  --cloud mycloud \
  --policy policies.yaml \
  --out findings.json

# With remediation enabled
go run ./cmd/agent \
  --cloud mycloud \
  --policy policies.yaml \
  --out findings.json \
  --fix

# Restrict to specific actions
go run ./cmd/agent \
  --cloud mycloud \
  --policy policies.yaml \
  --fix \
  --allow-actions log,tag

# Admin mode (all tenants)
go run ./cmd/agent \
  --cloud admin-cloud \
  --policy policies.yaml \
  --all-tenants
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OS_CLIENT_CONFIG_FILE` | Path to clouds.yaml |
| `OS_CLOUD` | Default cloud name |

---

## Server Command (Web UI)

Browser UI for profiles, dashboard, runs, and Policy Studio.

```bash
go run ./cmd/server [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:8080` | HTTP listen address |
| `--default-policy` | `examples/policies.yaml` | Default policy path shown in the UI |

```bash
go run ./cmd/server --listen :8080
```

OpenStack access in the UI is via **Profiles** (explicit Connect). The server does not auto-select `OS_CLOUD` or connect to local `clouds.yaml`. See [Web UI](../user-guide/web-ui.md).

---

## Scaffold Command

Generates boilerplate code for new services and resources.

```bash
go run ./cmd/scaffold [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `--list` | List all available services and resources |
| `--service` | Service name to generate |
| `--resources` | Comma-separated resource names |
| `--type` | OpenStack service type (optional) |

### Examples

```bash
# List available services
go run ./cmd/scaffold --list

# Generate a new service
go run ./cmd/scaffold \
  --service glance \
  --resources image,member

# With explicit service type
go run ./cmd/scaffold \
  --service glance \
  --resources image \
  --type image
```

### Generated Files

When scaffolding a service, the following files are created:

| Path | Description |
|------|-------------|
| `pkg/services/services/<service>.go` | Service implementation |
| `pkg/discovery/services/<service>.go` | Resource discoverers |
| `pkg/audit/<service>/<resource>.go` | Resource auditors |
| `pkg/audit/<service>/<resource>_test.go` | Auditor unit tests |
| `pkg/policy/validation/<service>.go` | Policy validator |
| `docs/reference/services/<service>-policy-guide.md` | Policy documentation |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error |
| `2` | Configuration error |
| `3` | Policy validation error |
| `4` | OpenStack connection error |

