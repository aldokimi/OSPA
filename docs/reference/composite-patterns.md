# Composite Pattern Library

Reusable semantic patterns that correlate multiple resources (or multi-field
outcomes) into high-signal compliance findings.

## Status

| Pattern | Service | Inputs required | Status |
|---------|---------|-----------------|--------|
| `public_sensitive_service_exposure` | neutron | SG rule fields (atomic) | Atomic observation (#102) |
| `bidirectional_world_exposure` | neutron | SG rule fields (atomic approx.) | Atomic observation (#102); peer-rule composite TBD |
| `shared_network_world_exposure` | neutron | `network` + `port` + `security_group_rule` | **Registered** `CompositeAuditor` |
| `high_privilege_no_mfa` | keystone | live `has_admin_role` + `mfa_enabled` | Atomic observation (#105) |
| `expired_password_no_mfa` | keystone | user atomics | Atomic observation (#111) |
| `idle_no_keypair` | nova | instance atomics | Atomic observation (#108) |
| `unencrypted_volume_backup_risk` | cinder | volume atomics | Atomic observation (#110) |
| `stale_secret_material` | barbican | secret `age_gt` (+ `secret_type`) | Atomic observation (#100) |
| `risky_dns_exposure` | designate | recordset `record_type` | Atomic observation (#101) |
| `failed_stack_root_cause` | heat | stack + resource linkage (`StackName`, status reasons) | **Registered** (#104/#114) |
| `public_image_cross_tenant_exposure` | glance | image + member | **Registered** (#113) |

## AND-in-one-rule vs true composites

Prefer a **single-rule AND** of atomics when all fields live on one resource.
Use a registered `CompositeAuditor` when correlation needs **cross-resource
identity** (membership, parent/child, network↔port↔SG).

## Policy shape

```yaml
composites:
  - neutron:
    - name: shared-network-world-exposure
      description: Shared networks with world-open security group rules
      service: neutron
      resources: [network, port, security_group_rule]
      check:
        pattern: shared_network_world_exposure
      action: log
      severity: critical
      category: security
```

Boolean shorthand is also accepted: `shared_network_world_exposure: true`.

## Implementing a new pattern

1. Document inputs in this table.
2. Prefer atomic observation if single-resource.
3. Otherwise implement/extend `pkg/audit/<service>/composite.go` and
   `audit.RegisterComposite`.
4. Add unit tests with synthetic `discovery.Job` maps.
5. Update `docs/Audit_Checks_Overview.md` gap catalog status.
