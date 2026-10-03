# Policy Guide: Octavia (octavia)

**Service Name:** `octavia`
**OpenStack Service Type:** load-balancer

## Supported Resources

### Load Balancer (`loadbalancer`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`

### Listener (`listener`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`

### Pool (`pool`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`

### Member (`member`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`

### Health Monitor (`healthmonitor`)
- Checks: `status`, `age_gt`, `exempt_names`
- Actions: `log`, `delete`
