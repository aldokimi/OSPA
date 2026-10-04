# OSPA Audit Checks Overview

> **Objective:** Analyze existing checks and identify gaps in the OSPA project for service-specific audit checks concerning OpenStack services.

## Introduction

OSPA (OpenStack Policy Agent) is designed to conduct policy-driven audits and remediation within OpenStack environments. One of the crucial aspects of OSPA is ensuring that audit checks are not only effective but also tailored to the specifics of each OpenStack service. This document provides an analysis of the current status of various services supported by OSPA, discusses implemented checks, and identifies gaps where additional checks are necessary.

## Analysis per Service

> **Note:** This overview reflects what the service policy guides in `docs/reference/services/*` declare as supported resources and check conditions.
>
> **Gap philosophy (important):** The absence of a check in a policy guide is a *gap* only if the underlying API/audit model can support it. When the API cannot provide required fields/state (or remediation is impossible), we call that out explicitly.

### 1. Neutron (`neutron` / network)
- **Supported Resources:** `network`, `security_group`, `security_group_rule`, `floating_ip`, `subnet`, `router`, `port`
- **Existing Checks (declared):**
  - `network`: `shared_network` (high, security)
  - `security_group`: (no additional checks beyond common `status/age_gt/unused/exempt_names`)
  - `security_group_rule`: `direction` (medium), `ethertype` (low), `protocol` (medium), `port` (high), `remote_ip_prefix` (critical; open-to-world when `0.0.0.0/0` or `::/0`), `port_range_wide` (high), `exempt_names` (low)
  - `port`: `no_security_group` (high, security)
  - `floating_ip`: `unassociated` (medium, cost)
  - plus common checks: `status`, `age_gt`, `unused`, `exempt_names`
- **Gaps / enhancements (audit-model + composite):**
  - Missing **composite exposure correlation**: we currently list rule fields, but we don’t correlate them into actionable “publicly reachable insecure ports/protocols” outcomes.
  - Missing **world exposure on sensitive ports** composite(s) (combine `remote_ip_prefix` open-to-world + `port`/`protocol`/`direction`).
  - Missing **direction-aware risk escalation** (separate ingress vs egress composites; escalate if both are wide-open).
  - Missing **cross-resource composites** (e.g., “shared_network=true + ingress world exposure rules”); requires correlating `network` ↔ `security_group_rule` scope through membership.
  - Some OpenStack Security Guide items in the Neutron policy guide are explicitly **configuration-plane / manual-only** (TLS/auth/control-plane permissions). These are not audit-model gaps unless new inputs are added.

### 2. Nova (`nova` / compute)
- **Supported Resources (declared):** `instance`, `keypair`, `flavor`, `hypervisor`
- **Existing Checks (declared):**
  - `instance`: `image_name` (deprecated/banned images), `no_keypair` (no SSH keypair), plus common `status/age_gt/unused/exempt_names`
  - `keypair`: common `age_gt/unused/exempt_names`
  - `flavor`: `is_public` (public), plus `exempt_names`
  - `hypervisor`: `status`, `exempt_names`
- **Gaps / enhancements:**
  - **Missing public compute chain composites:** “public flavor + instance exists on public networks” is not auditable unless Nova audit objects include tenancy/network bindings.
  - **Missing idle+no-keypair remediation intent:** we can flag the combination, but it is not expressed as a composite check in the overview.
  - **Metadata/auth posture is not represented:** OpenStack Security Guide items about TLS/auth between services are listed in policy guides as manual checks; adding them to OSPA would require config-plane inputs (not present in the audit model today).


### 3. Cinder (`volumev3` / block storage)
- **Supported Resources (declared):** `volume`, `snapshot`, `backup`, `qos`
- **Existing Checks (declared):**
  - `volume`: `encrypted` (high), `attached` (medium), `has_backup` (medium), plus common `status/age_gt/unused/exempt_names`
  - `snapshot`: `encrypted` (high), plus common `status/age_gt/unused/exempt_names`
  - `backup`: common `status/age_gt/exempt_names`
  - `qos`: `exempt_names` only (no QoS posture fields in the current policy guide)
- **Gaps / enhancements (audit-model + composite):**
  - **Backup lifecycle semantics missing:** we only have “has_backup” at the volume level, but not retention window/compliance or backup-to-volume matching.
  - **QoS posture checks missing:** current `qos` policy guide exposes only `exempt_names` → composite checks can’t be expressed without the relevant QoS fields being modeled.
  - **Correlation opportunity:** “encrypted=false + has_backup=true” could drive a composite “unencrypted volume with insufficient cryptographic controls” narrative, but requires richer audit fields (encryption state on snapshots/backups).

### 4. Glance (`glance` / image)
- **Supported Resources (declared):** `image`, `member`
- **Existing Checks (declared):**
  - `image`: `visibility` (high), plus `status/age_gt/unused/exempt_names`
  - `member`: common `status/age_gt/unused/exempt_names` (no member-specific security check fields)
- **Gaps / enhancements (composite semantics):**
  - **Cross-tenant exposure correlation missing:** we can detect public images via `image.visibility`, but we don’t correlate image visibility + member scope to precisely classify *who can access what*.
  - **Composite posture classification:** candidate composites like “public image + sensitive tags/member scope present” are not expressible without additional member/image linkage fields in the audit model.


### 5. Keystone (`keystone` / identity)
- **Supported Resources (declared):** `user`, `role`, `project`, `domain`, `group`, `service`
- **Existing Checks (declared):**
  - `user`: `password_expired` (high), `mfa_enabled` (high), `has_admin_role` (high), plus common `status/age_gt/unused/exempt_names`
  - `role/project/domain/group/service`: common `status/age_gt/unused/exempt_names` only (no role-relationship security checks in current guide)
- **Gaps / enhancements (composite + implementation constraints):**
  - **Composite “admin + no MFA” not realized as a composite check in the overview**. This is a prime candidate, but note: the audit implementation comment indicates `has_admin_role` requires enumerating role assignments via a client and is treated as a pending observation, so composite depends on fully auditable `has_admin_role` data.
  - **Missing “password_expired + no MFA” correlation** to prioritize high-risk accounts (requires both fields, which exist).
  - **Scope/relationship gaps:** no checks describe MFA for service users/groups at scale, or admin-role inheritance models.


### 6. Heat (`heat` / orchestration)
- **Supported Resources (declared):** `stack`, `resource`, `template`, `snapshot`
- **Existing Checks (declared):**
  - `stack`: `status`, `age_gt`, `exempt_names` (log/delete in guide)
  - `resource`: `status`, `age_gt`, `exempt_names` (log only; remediation only through parent stack)
  - `template`: `exempt_names` (log only)
  - `snapshot`: `age_gt`, `exempt_names` (log only)
- **Gaps / enhancements (composite + model limitations):**
  - **Failed stack + failed resources correlation**: a composite “stack CREATE/UPDATE failed because sub-resources failed” is not expressible unless we have cross-resource linking/exposed failure reason fields in the audit model.
  - **Orphaned components**: `unused` is not offered because Heat lacks an API “in use” signal in the policy guide → gaps should be framed as *API-audit model limitations*, not missing composites.


### 7. Swift (`swift` / object-store)
- **Supported Resources (declared):** `account`, `container`, `object`
- **Existing Checks (declared):**
  - `account`: `quota_set` (log only)
  - `container`: `unused`, `exempt_names` (no status/age in guide)
  - `object`: `age_gt`, `exempt_names` (no status)
- **Gaps / enhancements (model/field availability):**
  - Missing *object/container security semantics* (ACL/metadata/retention flags). Adding them requires the audit model to expose the corresponding Swift fields.
  - Composite “policy-driven exposure” checks (e.g., *public container + old object*) aren’t possible until we model *visibility/exposure* fields in the audit model.


### 8. Octavia (`octavia` / load-balancer)
- **Supported Resources (declared):** `loadbalancer`, `listener`, `pool`, `member`, `healthmonitor`
- **Existing Checks (declared):**
  - all: `status`, `age_gt`, `exempt_names`
  - no protocol/cipher/port checks are currently modeled in the policy guide
- **Gaps / enhancements (composite readiness):**
  - Security guide intent around listener TLS/protocol hardening is not represented as auditable checks in the current guide. Implementing it would require listener/pool fields for TLS configuration, cipher suites, and port exposure in the audit model.
  - Candidate composites (once fields exist): *public LB + listener port=443 + TLS min version too low*, *insecure protocol present + wide world access*.


### 9. Barbican (`barbican` / key-manager)
- **Supported Resources (declared):** `secret`, `container`, `order`
- **Existing Checks (declared):**
  - `secret`: `status`, `age_gt`, `unused`, `exempt_names`
  - `container`: `status`, `age_gt`, `unused`, `exempt_names`
  - `order`: `status`, `age_gt`, `exempt_names`
- **Gaps / enhancements (semantic gaps + rotation requirements):**
  - **Semantic risk classification is missing:** we don’t classify secret types (e.g., key/cert/password) and map them to different risk levels.
  - **Rotation freshness semantics are missing:** `age_gt` exists, but there’s no explicit “last rotated” field or lifecycle metadata exposed in the current policy guide.
  - **Composite prerequisites:** rotation risk composites often need pairing “secret-type + age + active usage / policy.” Current audit model does not expose usage/lifecycle fields beyond status/age.


### 10. Manila (`manila` / shared-file-systems)
- **Supported Resources (declared):** `share`, `share_snapshot`, `share_network`, `share_server`
- **Existing Checks (declared):**
  - `share`: `status`, `age_gt`, `unused`, `exempt_names`
  - `share_snapshot`: `status`, `age_gt`, `exempt_names`
  - `share_network`: `age_gt`, `exempt_names`
  - `share_server`: `status`, `age_gt`, `exempt_names`
- **Gaps / enhancements (model field availability):**
  - Encryption posture checks are not represented in the current policy guide. If the Manila audit model exposes encryption-at-rest/in-transit fields, we can add semantic composites; otherwise we should mark this as an *API-audit model availability* gap.


### 11. Trove (`trove` / database)
- **Supported Resources (declared):** `instance`, `cluster`, `backup`, `datastore`
- **Existing Checks (declared):**
  - `instance`: `status`, `age_gt`, `exempt_names`
  - `cluster`: `status`, `age_gt`, `exempt_names`
  - `backup`: `age_gt`, `exempt_names`
  - `datastore`: `age_gt`, `exempt_names`
- **Gaps / enhancements (semantic + model prerequisites):**
  - Backup retention windows/compliance semantics are not expressed; `backup` only has `age_gt` + `exempt_names`.
  - TLS/transport security exposure is not represented unless audit model includes TLS settings/cert metadata.


### 12. Magnum (`magnum` / container-infra)
- **Supported Resources (declared):** `cluster`, `cluster_template`, `bay`, `baymodel`
- **Existing Checks (declared):**
  - `cluster`: `status`, `age_gt`, `exempt_names`
  - `cluster_template`: `age_gt`, `exempt_names`
  - `bay`: `status`, `age_gt`, `exempt_names`
  - `baymodel`: `age_gt`, `exempt_names`
- **Gaps / enhancements (semantic posture):**
  - Template/policy-level security configuration checks are missing: the current policy guide exposes only age/status/hygiene for these resources.
  - Composite “insecure template inputs” patterns would require auditable fields for insecure networking, privileged containers, weak cluster settings, etc.


### 13. Ironic (`ironic` / baremetal)
- **Supported Resources (declared):** `node`, `port`, `driver`, `chassis`
- **Existing Checks (declared):** all: `status`, `age_gt`, `unused`, `exempt_names`
- **Gaps / enhancements (model field availability):**
  - Insecure provisioning / provisioning-time parameters are not represented in the current policy guide. If the Ironic audit model exposes PXE/TLS/driver/provisioning settings, we can add semantic composites; otherwise this should be explicitly an *API-audit model availability* gap.


### 14. Designate (`designate` / dns)
- **Supported Resources (declared):** `zone`, `recordset`, `record`
- **Existing Checks (declared):**
  - `zone`/`recordset`: `status`, `age_gt`, `unused`, `exempt_names`
  - `record`: `status`, `age_gt`, `exempt_names` (no `unused` in guide)
- **Gaps / enhancements (semantic need):**
  - DNS exposure security checks (public record posture, risky record types/values) are not expressed because the current policy guide exposes only lifecycle/hygiene checks.
  - Once audit model includes record-level “value/type/target” fields, we can add composites like *A/AAAA to public IPs + zone exposure*.


### 15. Senlin (`senlin` / clustering)
- **Supported Resources (declared):** `cluster`, `profile`, `node`, `policy`
- **Existing Checks (declared):**
  - `cluster`: `status`, `age_gt`, `exempt_names`
  - `node`: `status`, `age_gt`, `exempt_names`
  - `profile`: `age_gt`, `exempt_names`
  - `policy`: `age_gt`, `exempt_names`
- **Gaps / enhancements (relationship/semantic needs):**
  - Senlin policy composition security (what profile/policy implies for runtime) is not represented; adding composites requires audit fields for policy definitions/constraints, not just lifecycle metadata.


### 16. Zaqar (`zaqar` / messaging)
- **Supported Resources (declared):** `queue`, `message`, `subscription`
- **Existing Checks (declared):** all: `status`, `age_gt`, `exempt_names`
- **Gaps / enhancements (data sensitivity + model limitations):**
  - Message payload/content risk checks are not represented; implementing them safely requires either metadata-level fields (e.g., content type) or a sanitized audit-model surface. Without payload metadata, we can’t add meaningful semantic checks.


## Scaffolding Insights

The scaffolding tool provided within OSPA enables the generation of template checks for resources. However, it has some limitations:
- Manual intervention is often required to customize templates for more complex resource relationships.
- Composite/semantic checks are harder because they require consistent audit-model fields and cross-resource linking/identity (not just per-resource conditions).

## Key Gaps Across OSPA

### 1) Semantic/composite correlation gaps (the biggest opportunity)
- Many policy guides correctly enumerate *atomic* checks, but OSPA lacks a standard approach for translating those low-level fields into **high-signal compliance outcomes**.
- This especially affects cases where risk emerges only when multiple fields co-occur (e.g., Neutron world exposure + sensitive ports + ingress/egress direction).

### 2) Composite checks are constrained by audit-model availability
- If the audit layer does not expose the fields needed for correlation (e.g., Heat sub-resource failure reasons; Swift object/container visibility; Barbican secret lifecycle/usage; Octavia TLS/cipher exposure), we should explicitly mark those as **API-audit model gaps** rather than “missing check logic”.

### 3) Lifecycle hygiene is not consistently expressed as auditable “unused/orphaned” signals
- Some services don’t offer an “in use” signal (Heat/Magnum guides explicitly omit `unused`). Where that’s the case, remediation ideas should be reframed toward status-based cleanup, age-based teardown, or higher-level dependency checks.

## Gap catalog (composite pattern → candidate check type)

- **Public exposure + critical ports** → `public_sensitive_service_exposure` (Neutron: remote_ip_prefix open + protocol/port)
- **Ingress + egress wide-open** → `bidirectional_world_exposure` escalation
- **Shared scope + exposure rules** → `shared_network_world_exposure` (Neutron cross-correlating network sharing with rule posture; requires relationship inputs)
- **Admin + no MFA** → `high_privilege_no_mfa` (Keystone; composite depends on fully auditable has_admin_role data)
- **Rotation freshness risk** → `stale_secret_material` (Barbican; needs secret rotation lifecycle fields)
- **Public image distribution + access scope** → `public_image_cross_tenant_exposure` (Glance; needs member scope semantics)
- **Failed stack + failed sub-resources** → `failed_stack_root_cause` (Heat; needs sub-resource failure aggregation fields)

## Recommendations
1. Adopt the “gap philosophy”: treat missing checks as gaps only when the audit-model supports it; otherwise label as **API-audit model availability**.
2. Implement a core composite-check pattern library (atomic → semantic translation) and reuse it across services.
3. Prioritize composites with the highest audit-model likelihood:
   - Neutron world exposure + sensitive ports (strong field support)
   - Keystone admin role + MFA (partially supported; verify has_admin_role auditable inputs)
   - Glance public visibility + member scope (if member scope is auditable)
4. Extend scaffolding/generator to scaffold composite rules with explicit “inputs required” documentation.
5. Add a regular checkpoint cadence tied to OSG updates, and verify check coverage by comparing policy guide allowed checks vs implemented/composite catalogs.

## References
- [OpenStack Security Guide](https://docs.openstack.org/security-guide/)
- [OSPA Documentation](https://openstack-policy-agent.github.io/OSPA/)
- [OpenStack API Documentation (Nova)](https://docs.openstack.org/api-ref/nova/)
 

