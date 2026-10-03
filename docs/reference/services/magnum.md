# Policy Guide: Magnum (magnum)

This guide explains how to write policies for Magnum resources in OSPA.

## Service Overview

**Service Name:** `magnum`
**Display Name:** Magnum
**OpenStack Service Type:** container-infra

## Supported Resources


### Cluster

**Resource Type:** `cluster`

**Allowed Actions:** log, delete
**Allowed Checks:** status, age_gt, exempt_names

Cluster status is the API's `status` field (e.g. `CREATE_COMPLETE`,
`CREATE_FAILED`, `UPDATE_IN_PROGRESS`, `DELETE_COMPLETE`, `COOK_COMPLETE`).
There is no "in use" signal for a cluster, so `unused` is not offered.


### ClusterTemplate

**Resource Type:** `cluster_template`

**Allowed Actions:** log, delete
**Allowed Checks:** age_gt, exempt_names

A cluster template is a static definition of the images/labels used to
build clusters. The API exposes no status for it, so `status` is not
offered; `created_at`/`updated_at` are available, so `age_gt` applies.


### Bay

**Resource Type:** `bay`

**Allowed Actions:** log, delete
**Allowed Checks:** status, age_gt, exempt_names

A bay is a node/cluster of nodes that provides access to the cluster's
infrastructure. Its status is e.g. `DEFAULT`, `ERROR`, `IN_PROGRESS`,
`UNREACHABLE`. Bays are deprecated upstream in favor of registries.
There is no "in use" signal, so `unused` is not offered.


### Baymodel

**Resource Type:** `baymodel`

**Allowed Actions:** log, delete
**Allowed Checks:** age_gt, exempt_names

A bay model is a blueprint for bays. It has no status field, so only
`age_gt` (from `created_at`/`updated_at`) and `exempt_names` apply.
Bay models are deprecated upstream in favor of registries.




## Policy Structure

All policies for Magnum follow this structure:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - magnum:
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
  description: Find inactive magnum resources
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
  description: Find unused magnum resources
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
  description: Audit magnum resources
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


### Cluster Examples


#### Find Failed Clusters

```yaml
- name: find-failed-clusters
  description: Find clusters whose creation or update failed
  resource: cluster
  check:
    status: CREATE_FAILED
  action: log
```

#### Find Old Clusters

```yaml
- name: find-old-clusters
  description: Find clusters older than 30 days
  resource: cluster
  check:
    age_gt: 30d
  action: log
```

#### Delete Old Failed Clusters

```yaml
- name: delete-old-failed-clusters
  description: Delete failed clusters that are older than 90 days
  resource: cluster
  check:
    status: CREATE_FAILED
    age_gt: 90d
  action: delete
```


### ClusterTemplate Examples


#### Find Old Cluster Templates

```yaml
- name: find-old-templates
  description: Find cluster templates older than 30 days
  resource: cluster_template
  check:
    age_gt: 30d
  action: log
```

#### Find Old Templates Except System Ones

```yaml
- name: find-old-templates-except-system
  description: Find old cluster templates, exempting system ones
  resource: cluster_template
  check:
    age_gt: 30d
    exempt_names:
      - system-*
  action: log
```


### Bay Examples


#### Find Error Bays

```yaml
- name: find-error-bays
  description: Find bays in an error or unreachable state
  resource: bay
  check:
    status: ERROR
  action: log
```

#### Find Old Bays

```yaml
- name: find-old-bays
  description: Find bays older than 30 days
  resource: bay
  check:
    age_gt: 30d
  action: log
```

#### Find Error Bays Except System Ones

```yaml
- name: find-error-bays-except-system
  description: Find error bays, exempting system ones
  resource: bay
  check:
    status: ERROR
    exempt_names:
      - system-*
  action: log
```


### Baymodel Examples


#### Find Old Bay Models

```yaml
- name: find-old-models
  description: Find bay models older than 30 days
  resource: baymodel
  check:
    age_gt: 30d
  action: log
```

#### Find Old Models Except System Ones

```yaml
- name: find-old-models-except-system
  description: Find old bay models, exempting system ones
  resource: baymodel
  check:
    age_gt: 30d
    exempt_names:
      - system-*
  action: log
```



## Complete Policy Example

Here's a complete policy file example for Magnum:

```yaml
version: v1
defaults:
  workers: 50
  output: findings.json
policies:
  - magnum:
    - name: find-failed-clusters
      description: Find clusters whose creation or update failed
      resource: cluster
      severity: high
      category: hygiene
      check:
        status: CREATE_FAILED
      action: log
    - name: cleanup-old-clusters
      description: Find clusters older than 90 days
      resource: cluster
      severity: low
      category: cost
      check:
        age_gt: 90d
        exempt_names:
          - system-*
      action: log
    - name: find-old-templates
      description: Find cluster templates older than 90 days
      resource: cluster_template
      severity: low
      category: cost
      check:
        age_gt: 90d
      action: log
    - name: find-error-bays
      description: Find bays in an error state
      resource: bay
      severity: medium
      category: hygiene
      check:
        status: ERROR
      action: log
    - name: find-old-models
      description: Find bay models older than 90 days
      resource: baymodel
      severity: low
      category: cost
      check:
        age_gt: 90d
      action: log
```

## OpenStack Documentation References

For more information about Magnum resources and their properties:

- **OpenStack Magnum API Documentation:** https://docs.openstack.org/api-ref/magnum/
- **Magnum Service Guide:** https://docs.openstack.org/magnum/latest/
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
- Ensure service name matches exactly: `magnum`
- Verify resource type is supported: `{cluster Container clusters [status age_gt exempt_names] [] [log delete] {false false false}}`, `{cluster_template Cluster templates [age_gt exempt_names] [] [log delete] {false false false}}`, `{bay Bays (deprecated) [status age_gt exempt_names] [] [log delete] {false false false}}`, `{baymodel Bay models (deprecated) [age_gt exempt_names] [] [log delete] {false false false}}`
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
