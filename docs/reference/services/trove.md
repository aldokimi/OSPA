# Policy Guide: Trove (trove)

**Service Name:** `trove`
**OpenStack Service Type:** database

## Supported Resources

### Instance (`instance`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`

TLS/transport security is **not** exposed on the instance list/detail payload
used by OSPA (gophercloud `instances.Instance` has no TLS/cert fields). Treat
TLS posture as an **API-audit model availability** gap until configuration-group
or access metadata is modeled.

### Cluster (`cluster`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`

### Backup (`backup`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`

Retention/compliance is expressed with `age_gt`. When a backup exceeds the
threshold, observations use `backup_retention_exceeded` (API has no dedicated
retention-window field).

```yaml
policies:
  - trove:
    - name: backups-older-than-30d
      description: Backups outside retention window
      service: trove
      resource: backup
      check:
        age_gt: 30d
      action: log
      severity: medium
      category: compliance
```

### Datastore (`datastore`)
- Checks: `exempt_names`
- Actions: `log`

Datastore list resources have no status/timestamps in the API used by OSPA.
