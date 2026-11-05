# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Brad Hager and contributors

GO        ?= go
PKG       := github.com/bhager42/teslachargingmonitor
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -s -w \
	-X $(PKG)/internal/buildinfo.Version=$(VERSION) \
	-X $(PKG)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(PKG)/internal/buildinfo.Date=$(DATE)

# Run helper tools with the project toolchain from go.mod, not the tool's own.
TOOLCHAIN := $(shell sed -n 's/^toolchain //p' go.mod)
GORUN     := GOTOOLCHAIN=$(TOOLCHAIN) $(GO) run

export CGO_ENABLED = 0
export GOFLAGS     = -mod=readonly

.PHONY: all build sim test cover fuzz soak e2e image image-test lint fmt vet vuln headers licenses check clean

all: check build

build: ## Build the tcmon binary into ./bin
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/tcmon ./cmd/tcmon
	$(GO) build -trimpath -ldflags '-s -w' -o bin/wcsim ./cmd/wcsim

sim: ## Run the Wall Connector simulator (SCENARIO=idle SPEED=1)
	$(GO) run ./cmd/wcsim -scenario $(or $(SCENARIO),idle) -speed $(or $(SPEED),1)

test: ## Run unit tests with the race detector
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

cover: ## Run tests with coverage report
	$(GO) test -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -n 1

E2E_BROWSERS ?= chromium

e2e: build ## Browser tests (Playwright + axe); E2E_BROWSERS=chromium,firefox,webkit
	cd e2e && npm ci --no-audit --no-fund && TCMON_E2E_BROWSERS=$(E2E_BROWSERS) npx playwright test

SOAK_POLLS ?= 3000

soak: ## Poll the simulator SOAK_POLLS times; fails on goroutine/heap growth
	TCMON_SOAK_POLLS=$(SOAK_POLLS) $(GO) test -run '^TestSoak$$' -count=1 -v ./internal/poller

FUZZTIME ?= 60s
# package:target pairs (packages under internal/)
FUZZ_TARGETS := wallconnector:FuzzDecode wallconnector:FuzzParseAddress wallconnector:FuzzParseFirmware \
	alerts:FuzzRules alerts:FuzzParseQuietHours notify:FuzzEmail energy:FuzzCosts \
	auth:FuzzCheckPolicy store:FuzzDeviceNormalize web:FuzzParseClock

fuzz: ## Run every fuzz target for FUZZTIME each
	@for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; name=$${t#*:}; \
		echo "== $$pkg $$name"; \
		$(GO) test -run='^$$' -fuzz="^$$name$$" -fuzztime=$(FUZZTIME) ./internal/$$pkg || exit 1; \
	done

fmt: ## Format code
	gofmt -s -w .

vet:
	$(GO) vet ./...

lint: vet ## golangci-lint v2 built with the go.mod toolchain (see CONTRIBUTING.md)
	golangci-lint run

vuln: ## govulncheck
	$(GORUN) golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

headers: ## Verify SPDX license headers
	./scripts/check-headers.sh

licenses: ## Verify dependency licenses are AGPL-compatible
	$(GORUN) github.com/google/go-licenses/v2@v2.0.1 check ./... \
		--disallowed_types=forbidden,restricted,unknown --ignore $(PKG)

check: headers lint test ## Everything CI runs that is fast

IMAGE ?= tcmon:dev

image: ## Build the container image (IMAGE=tcmon:dev)
	docker buildx build --load --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
		--build-arg SOURCE_DATE_EPOCH=$$(git log -1 --format=%ct) -t $(IMAGE) .

image-test: ## Structure and smoke tests for IMAGE (needs Docker; run as root for the UID test)
	scripts/image-test.sh $(IMAGE)

clean:
	rm -rf bin coverage.out
