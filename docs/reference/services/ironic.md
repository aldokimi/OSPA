# Policy Guide: Ironic (ironic)

This guide explains how to write policies for Ironic resources in OSPA.

## Service Overview

**Service Name:** `ironic`
**Display Name:** Ironic
**OpenStack Service Type:** baremetal

## Supported Resources


### Node

**Resource Type:** `node`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** status, age_gt, unused, exempt_names, console_enabled, boot_interface

#### Security & Domain Checks

| Check | Severity | Category | Type | Description |
|-------|----------|----------|------|-------------|
| **`console_enabled`** | high | security | bool | Match `ConsoleEnabled` (e.g. `true` to require/find enabled serial console) |
| **`boot_interface`** | high | security | string | Match boot interface (e.g. `pxe` for legacy PXE provisioning) |

Driver_info secrets / TLS material inside `driver_info` are not modeled as first-class checks (map values vary by driver) — treat detailed credential scraping as an API-audit model caution.


### Port

**Resource Type:** `port`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** age_gt, exempt_names


### Driver

**Resource Type:** `driver`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** exempt_names


### Chassis

**Resource Type:** `chassis`

**Allowed Actions:** log, delete, tag
**Allowed Checks:** age_gt, exempt_names




## Policy Structure

All policies for Ironic follow this structure:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - ironic:
    - name: rule-name
      description: Rule description
      resource: <resource_type>
      severity: critical|high|medium|low
      category: security|compliance|cost|hygiene
      check:
        # Check conditions (see below)
      action: log|delete|tag
```

## Check Conditions

### Common Check Conditions

The following check conditions are available for most resources:

#### Status Check

Check resources by their status:

```yaml
check:
  status: active|inactive|available|unavailable|DOWN|UP
```

**Example:**
```yaml
- name: find-inactive-resources
  description: Find inactive ironic resources
  resource: <resource_type>
  check:
    status: inactive
  action: log
```

#### Age Check

Find resources older than a specified age:

```yaml
check:
  age_gt: 30d  # Options: 7d, 30d, 90d, 1h, 24h, etc.
```

**Supported units:**
- `d` or `day` or `days` - Days
- `h` or `hour` or `hours` - Hours
- `m` or `min` or `minute` or `minutes` - Minutes

**Example:**
```yaml
- name: find-old-resources
  description: Find resources older than 30 days
  resource: <resource_type>
  check:
    age_gt: 30d
  action: log
```

#### Unused Check

Find resources that are not being used:

```yaml
check:
  unused: true
```

**Example:**
```yaml
- name: find-unused-resources
  description: Find unused ironic resources
  resource: <resource_type>
  check:
    unused: true
  action: log
```

#### Exemptions

Exclude specific resources from checks:

```yaml
check:
  status: active
  exempt_names:
    - default
    - system-resource
```

**Example:**
```yaml
- name: find-active-except-default
  description: Find active resources except default ones
  resource: <resource_type>
  check:
    status: active
    exempt_names:
      - default
  action: log
```

## Actions

### Log Action

Log violations without taking any action:

```yaml
action: log
```

**Example:**
```yaml
- name: audit-resources
  description: Audit ironic resources
  resource: <resource_type>
  check:
    status: inactive
  action: log
```

### Delete Action

Delete non-compliant resources (use with caution):

```yaml
action: delete
```

**Example:**
```yaml
- name: cleanup-old-resources
  description: Delete resources older than 90 days
  resource: <resource_type>
  check:
    age_gt: 90d
  action: delete
```

**Note:** The `--fix` flag must be set when running the agent for delete actions to take effect.

### Tag Action

Tag non-compliant resources with metadata:

```yaml
action: tag
tag_name: audit-tag-name
action_tag_name: "Display Name for Tag"
```

**Example:**
```yaml
- name: tag-old-resources
  description: Tag resources older than 30 days
  resource: <resource_type>
  check:
    age_gt: 30d
  action: tag
  tag_name: audit-old-resource
  action_tag_name: "Old Resource"
```

## Resource-Specific Examples


### Node Examples


#### Find Inactive Node Resources

```yaml
- name: find-inactive-node
  description: Find inactive node resources
  resource: node
  check:
    status: inactive
  action: log
```

#### Find Old Node Resources

```yaml
- name: find-old-node
  description: Find node resources older than 30 days
  resource: node
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Node Resources

```yaml
- name: cleanup-unused-node
  description: Delete unused node resources
  resource: node
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Port Examples


#### Find Inactive Port Resources

```yaml
- name: find-inactive-port
  description: Find inactive port resources
  resource: port
  check:
    status: inactive
  action: log
```

#### Find Old Port Resources

```yaml
- name: find-old-port
  description: Find port resources older than 30 days
  resource: port
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Port Resources

```yaml
- name: cleanup-unused-port
  description: Delete unused port resources
  resource: port
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Driver Examples


#### Find Inactive Driver Resources

```yaml
- name: find-inactive-driver
  description: Find inactive driver resources
  resource: driver
  check:
    status: inactive
  action: log
```

#### Find Old Driver Resources

```yaml
- name: find-old-driver
  description: Find driver resources older than 30 days
  resource: driver
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Driver Resources

```yaml
- name: cleanup-unused-driver
  description: Delete unused driver resources
  resource: driver
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```


### Chassis Examples


#### Find Inactive Chassis Resources

```yaml
- name: find-inactive-chassis
  description: Find inactive chassis resources
  resource: chassis
  check:
    status: inactive
  action: log
```

#### Find Old Chassis Resources

```yaml
- name: find-old-chassis
  description: Find chassis resources older than 30 days
  resource: chassis
  check:
    age_gt: 30d
  action: log
```

#### Cleanup Unused Chassis Resources

```yaml
- name: cleanup-unused-chassis
  description: Delete unused chassis resources
  resource: chassis
  check:
    unused: true
    exempt_names:
      - default
  action: delete
```



## Complete Policy Example

Here's a complete policy file example for Ironic:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - ironic:
    - name: audit-node
      description: Audit node resources
      resource: node
      severity: medium
      category: hygiene
      check:
        status: active
      action: log
    - name: cleanup-old-node
      description: Find node resources older than 90 days
      resource: node
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
    - name: audit-port
      description: Audit port resources
      resource: port
      severity: medium
      category: hygiene
      check:
        status: active
      action: log
    - name: cleanup-old-port
      description: Find port resources older than 90 days
      resource: port
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
    - name: audit-driver
      description: Audit driver resources
      resource: driver
      severity: medium
      category: hygiene
      check:
        status: active
      action: log
    - name: cleanup-old-driver
      description: Find driver resources older than 90 days
      resource: driver
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
    - name: audit-chassis
      description: Audit chassis resources
      resource: chassis
      severity: medium
      category: hygiene
      check:
        status: active
      action: log
    - name: cleanup-old-chassis
      description: Find chassis resources older than 90 days
      resource: chassis
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - default
      action: log
```

## OpenStack Documentation References

For more information about Ironic resources and their properties:

- **OpenStack Ironic API Documentation:** https://docs.openstack.org/api-ref/ironic/
- **Ironic Service Guide:** https://docs.openstack.org/ironic/latest/
- **OpenStack Security Guide:** https://docs.openstack.org/security-guide/

## Testing Your Policy

1. **Validate the policy:**
   ```bash
   go run ./cmd/agent --cloud "$OS_CLOUD" --policy your-policy.yaml --out /dev/null
   ```

2. **Run in audit mode (safe):**
   ```bash
   go run ./cmd/agent --cloud "$OS_CLOUD" --policy your-policy.yaml --out findings.json
   ```

3. **Apply remediations (use with caution):**
   ```bash
   go run ./cmd/agent --cloud "$OS_CLOUD" --policy your-policy.yaml --out findings.json --fix
   ```

## Notes

- All check conditions are optional, but at least one should be specified
- Multiple check conditions are combined with AND logic (all must match)
- The `exempt_names` list allows you to exclude specific resources by name
- Age checks use the resource's `UpdatedAt` timestamp, falling back to `CreatedAt` if not available
- Status values are case-sensitive and should match OpenStack API responses exactly
- Use `severity` and `category` to classify findings for prioritization

## Troubleshooting

**Policy validation fails:**
- Ensure service name matches exactly: `ironic`
- Verify resource type is supported: `{node Bare metal nodes [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`, `{port Node ports [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`, `{driver Drivers [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`, `{chassis Chassis [status age_gt unused exempt_names] [] [log delete tag] {false false false}}`
- Check YAML syntax is correct

**No resources found:**
- Verify resources exist in your OpenStack project
- Use `--all-tenants` flag if resources are in other projects (requires admin)
- Check OpenStack API endpoints are accessible

**Actions not working:**
- Ensure `--fix` flag is set for delete/tag actions
- Verify you have permissions to modify resources
- Check action-specific requirements (e.g., `tag_name` for tag action)

## See Also

- [OSPA Development Guide](../../developer-guide/index.md)
- [OSPA Architecture Guide](../../developer-guide/architecture.md)
- [Example Policies](https://github.com/OpenStack-Policy-Agent/OSPA/blob/main/examples/policies.yaml)
