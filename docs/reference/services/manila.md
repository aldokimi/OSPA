# Policy Guide: Manila (manila)

**Service Name:** `manila`
**OpenStack Service Type:** shared-file-systems

## Supported Resources

### Share (`share`)
- Checks: `status`, `age_gt`, `unused`, `exempt_names`, `is_public`
- Note: encryption-at-rest/in-transit is not exposed on the share API (API-audit model gap).
- Actions: `log`, `delete`

### Share Snapshot (`share_snapshot`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`

### Share Network (`share_network`)
- Checks: `age_gt`, `exempt_names`
- Actions: `log`

### Share Server (`share_server`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`
