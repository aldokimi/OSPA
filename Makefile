.PHONY: scaffold help build server test test-e2e test-devstack-manage

help:
	@echo "OSPA Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  scaffold              - Run the scaffold tool (use: make scaffold SERVICE=glance RESOURCES=image,member)"
	@echo "  build                 - Build the agent and UI server"
	@echo "  test                  - Run unit tests"
	@echo "  test-e2e              - Run e2e tests (needs OS_CLOUD for live runs)"
	@echo "  test-devstack-manage  - Create DevStack resources and manage them via OSPA policy"

scaffold:
	@if [ -z "$(SERVICE)" ]; then \
		echo "Error: SERVICE is required"; \
		echo "Usage: make scaffold SERVICE=glance RESOURCES=image,member [DISPLAY_NAME=Glance] [TYPE=image]"; \
		exit 1; \
	fi
	@go run ./cmd/scaffold \
		--service $(SERVICE) \
		--display-name $(or $(DISPLAY_NAME),$(shell echo $(SERVICE) | sed 's/^./\U&/')) \
		--resources $(RESOURCES) \
		--type $(or $(TYPE),$(SERVICE)) \
		$(if $(FORCE),--force,)

build:
	go build -o bin/ospa-agent ./cmd/agent
	go build -o bin/ospa-server ./cmd/server

server:
	go run ./cmd/server --listen :8080 --default-policy examples/policies.yaml

test:
	go test ./...

test-e2e:
	go test -tags=e2e ./e2e/...

test-devstack-manage:
	@test -n "$$OS_CLOUD" || { echo "OS_CLOUD is required (e.g. export OS_CLOUD=devstack)"; exit 1; }
	./scripts/devstack-manage-test.sh

