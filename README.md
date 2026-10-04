# OSPA (OpenStack Policy Agent)

A policy-driven audit and remediation agent for OpenStack clouds.

**Define** policies in YAML → **Discover** resources → **Audit** against rules → **Remediate** violations.

## Features

- **Declarative policies** — YAML rules with severity, category, and composite patterns
- **Multi-service coverage** — Live auditors across most major OpenStack services
- **Safe by default** — Dry-run unless you pass `--fix` (CLI) or enable Apply (UI)
- **Web UI** — HTMX dashboard, Policy Studio, runs, and cloud **profiles** (`cmd/server`)
- **Explicit cloud connect** — UI never auto-uses `clouds.yaml` / `OS_CLOUD`; Connect requires consent
- **Extensible** — Scaffold new services and resources
- **Concurrent** — Parallel discovery and audit for large clouds

## Quick Start

### CLI agent

```bash
export OS_CLIENT_CONFIG_FILE=path/to/clouds.yaml

# Audit only (safe, no changes)
go run ./cmd/agent --cloud mycloud --policy ./examples/policies.yaml --out findings.json

# Apply remediations
go run ./cmd/agent --cloud mycloud --policy ./examples/policies.yaml --out findings.json --fix
```

### Web UI

```bash
go run ./cmd/server --listen :8080
# or: make server
```

Open http://localhost:8080 → **Profiles** → add a remote cloud or opt in to a local `clouds.yaml` entry → **Connect**. Dashboard, Runs, and Policy Studio stay idle until a profile is connected.

See the [Web UI guide](https://openstack-policy-agent.github.io/OSPA/user-guide/web-ui/).

## Supported Services

| Service | Description | Status |
|---------|-------------|--------|
| **Neutron** | Networking | ✔ Live |
| **Nova** | Compute | ✔ Live |
| **Cinder** | Block Storage | ✔ Live |
| **Glance** | Image | ✔ Live |
| **Keystone** | Identity | ✔ Live |
| **Heat** | Orchestration | ✔ Live |
| **Swift** | Object Storage | ✔ Live |
| **Octavia** | Load Balancing | ✔ Live |
| **Barbican** | Key Manager | ✔ Live |
| **Manila** | Shared File Systems | ✔ Live |
| **Trove** | Database | ✔ Live |
| **Magnum** | Container Infrastructure | ✔ Live |
| **Ironic** | Bare Metal | ✔ Live |
| **Designate** | DNS | ✔ Live |
| **Senlin** | Clustering | ◐ Stub |
| **Zaqar** | Messaging | ◐ Stub |

**Legend:** ✔ Live discovery + auditors | ◐ Scaffold / stub (not yet evaluating checks)

Per-resource detail: [resource catalog](https://openstack-policy-agent.github.io/OSPA/reference/catalog/). Check maturity notes: [`docs/Audit_Checks_Overview.md`](docs/Audit_Checks_Overview.md).

## Example Policy

```yaml
version: v1
policies:
  - neutron:
    - name: unused-security-groups
      description: Find security groups not attached to any ports
      resource: security_group
      check:
        unused: true
      action: log

    - name: dangerous-ingress-rules
      description: Flag rules allowing SSH from anywhere
      resource: security_group_rule
      check:
        direction: ingress
        protocol: tcp
        port: 22
        remote_ip_prefix: "0.0.0.0/0"
      action: log
```

## Build

```bash
make build          # bin/ospa-agent + bin/ospa-server
make server         # run the Web UI on :8080
make test           # unit tests
make test-e2e       # e2e (needs OpenStack + OS_CLOUD)
```

## Documentation

- [Getting Started](https://openstack-policy-agent.github.io/OSPA/getting-started/)
- [User Guide](https://openstack-policy-agent.github.io/OSPA/user-guide/)
- [Web UI](https://openstack-policy-agent.github.io/OSPA/user-guide/web-ui/)
- [Developer Guide](https://openstack-policy-agent.github.io/OSPA/developer-guide/)
- [Reference](https://openstack-policy-agent.github.io/OSPA/reference/)

## Extending OSPA

```bash
go run ./cmd/scaffold --list
go run ./cmd/scaffold --service glance --resources image,member
# or: make scaffold SERVICE=glance RESOURCES=image,member
```

See the [Developer Guide](https://openstack-policy-agent.github.io/OSPA/developer-guide/).

## License

Apache 2.0
