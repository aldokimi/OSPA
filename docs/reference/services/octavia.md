# Policy Guide: Octavia (octavia)

**Service Name:** `octavia`
**OpenStack Service Type:** load-balancer

## Supported Resources

### Load Balancer (`loadbalancer`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`
- Status uses `provisioning_status`.

### Listener (`listener`)
- Checks: `status`, `exempt_names`, `protocol`, `port`, `tls_ciphers`, `has_tls_container`
- Actions: `log`, `delete`
- Status uses `provisioning_status`.
- `age_gt` is unavailable — gophercloud `Listener` has no timestamps.
- Atomic AND of protocol/port/TLS fields emits `insecure_listener_tls` when posture matches (#122).

Example — find TERMINATED_HTTPS listeners without a Barbican TLS container:

```yaml
- name: missing-tls-container
  resource: listener
  check:
    protocol: TERMINATED_HTTPS
    port: 443
    has_tls_container: false
  action: log
  severity: high
  category: security
```

Example — find a specific weak cipher suite string:

```yaml
- name: weak-ciphers
  resource: listener
  check:
    tls_ciphers: "RC4-SHA"
  action: log
  severity: high
  category: security
```

### Pool (`pool`)
- Checks: `status`, `exempt_names`, `protocol`
- Actions: `log`, `delete`
- `age_gt` unavailable — Pool has no timestamps in gophercloud.

### Member (`member`)
- Checks: `status`, `age_gt`, `exempt_names`, `port`
- Actions: `log`, `delete`

### Health Monitor (`healthmonitor`)
- Checks: `status`, `exempt_names`
- Actions: `log`, `delete`
- `age_gt` unavailable — Monitor has no timestamps in gophercloud.

## Composites

### `insecure_public_listener`
Joins `loadbalancer` + `listener`. Hits when a listener is world-open
(`allowed_cidrs` empty or `0.0.0.0/0` / `::/0`) and insecure
(HTTP, plaintext 80/443, or TERMINATED_HTTPS/HTTPS without `default_tls_container_ref`).

```yaml
composites:
  - octavia:
    - name: insecure-public-listener
      service: octavia
      resources: [loadbalancer, listener]
      check:
        pattern: insecure_public_listener
      action: log
      severity: critical
      category: security
```
