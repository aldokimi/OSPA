#!/usr/bin/env bash
# Create fixtures on local DevStack, audit/manage them with OSPA policies.
#
# Usage:
#   export OS_CLOUD=devstack
#   ./scripts/devstack-manage-test.sh
#
# Optional:
#   OSPA_MANAGE_POLICY=examples/policies/devstack-manage.yaml
#   SKIP_CLI=1   # skip the cmd/agent pass

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CLOUD="${OS_CLOUD:-devstack}"
POLICY="${OSPA_MANAGE_POLICY:-$ROOT/examples/policies/devstack-manage.yaml}"
export OS_CLOUD="$CLOUD"
export OSPA_MANAGE_POLICY="$POLICY"

echo "==> DevStack manage test (OS_CLOUD=$OS_CLOUD)"
echo "    policy: $POLICY"

echo "==> Go scenario: create → audit → apply delete → re-audit"
go test -tags=e2e ./e2e/scenario/... -count=1 -timeout 30m -v -run 'CreateAuditManage|CLIAgentManage'

if [[ "${SKIP_CLI:-0}" != "1" ]]; then
  echo "==> CLI agent dry-run against manage policy"
  go build -o /tmp/ospa-agent ./cmd/agent
  set +e
  /tmp/ospa-agent --cloud "$OS_CLOUD" --policy "$POLICY" --out /tmp/ospa-devstack-manage.json
  cli_rc=$?
  set -e
  # Agent exits 2 when violations are found; that is success for this gate.
  if [[ "$cli_rc" -ne 0 && "$cli_rc" -ne 2 ]]; then
    echo "CLI agent failed with exit $cli_rc" >&2
    exit "$cli_rc"
  fi
  test -s /tmp/ospa-devstack-manage.json
  echo "    findings written to /tmp/ospa-devstack-manage.json (agent exit $cli_rc)"
fi

echo "==> DevStack manage test PASSED"
