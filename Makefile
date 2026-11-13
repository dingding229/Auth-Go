.PHONY: docker-build dev-server dev-web build test test-sdks lint docs test-pack build-stubs build-pack tools-image

VERSION ?= 1.0.0
COMMIT ?= unknown
BUILD_TIME ?= unknown
LDFLAGS = -s -w -X authgo/internal/buildinfo.Version=$(VERSION) -X authgo/internal/buildinfo.Commit=$(COMMIT) -X authgo/internal/buildinfo.BuiltAt=$(BUILD_TIME)

dev-server:
	cd server && go run ./cmd/authgo

dev-web:
	cd web && npm run dev

# Build one self-contained application binary; pack remains an explicit tools target.
build:
	cd web && npm ci && npm run build && npm run test:dist
	rm -rf server/internal/webui/dist
	mkdir -p server/internal/webui/dist bin
	cp -R web/dist/. server/internal/webui/dist/
	test -s server/internal/webui/dist/index.html
	cd server && CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o ../bin/authgo ./cmd/authgo

docker-build:
	docker build -f Dockerfile --build-arg VERSION="$(VERSION)" --build-arg COMMIT="$(COMMIT)" --build-arg BUILD_TIME="$(BUILD_TIME)" -t authgo:$(VERSION) .

test: test-sdks test-pack
	cd server && go test -count=1 ./...
	cd web && npm run build && npm run typecheck && npm test && npm run test:dist
	cd sdk/go && go test ./...
	sh scripts/check-examples.sh

lint:
	@test -z "$$(cd pack && gofmt -l .)" || (echo '请先执行 pack gofmt'; exit 1)
	cd pack && go vet ./...
	@test -z "$$(gofmt -l sdk/go examples)" || (echo '请先执行 SDK/示例 gofmt'; exit 1)
	cd sdk/go && go vet ./...
	sh scripts/check-examples.sh
	@test -z "$$(cd server && gofmt -l .)" || (echo '请先执行 gofmt'; exit 1)
	cd server && go vet ./...
	cd web && npm run lint && npm run typecheck

# Pin the OpenAPI 3.1 generator; generated documents are committed, not build-time dependencies.
docs:
	cd server && go run github.com/swaggo/swag/v2/cmd/swag@v2.0.0-rc6 init --v3.1 -g internal/apidocs/api.go --parseInternal --output internal/apidocs/generated --outputTypes json,yaml

# Official SDK toolchains run in isolated Docker containers; no package publishing.
test-sdks:
	sh sdk/conformance/run.sh

# Run like the other Go targets.
test-pack: build-stubs
	cd pack && GOMAXPROCS=2 go test -p 1 ./...

# Production pack embeds both static launchers.
build-stubs:
	mkdir -p pack/stubs
	cd sdk/go && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ../../pack/stubs/authgo-stub-linux-amd64 ./cmd/authgo-stub
	cd sdk/go && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o ../../pack/stubs/authgo-stub-linux-arm64 ./cmd/authgo-stub

build-pack: build-stubs
	mkdir -p bin
	cd pack && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../bin/authgo-pack ./cmd/authgo-pack

# No registry login/push. The default exporter preserves both architectures in OCI.
# For a local single-arch COPY source: TOOLS_PLATFORMS=linux/amd64 TOOLS_OUTPUT=type=docker.
TOOLS_IMAGE ?= authgo-tools
TOOLS_VERSION ?= $(VERSION)
TOOLS_PLATFORMS ?= linux/amd64,linux/arm64
TOOLS_OUTPUT ?= type=oci,dest=bin/authgo-tools-$(TOOLS_VERSION).oci.tar

tools-image:
	@test -n "$(TOOLS_IMAGE)" && test -n "$(TOOLS_VERSION)" || (echo 'TOOLS_IMAGE and TOOLS_VERSION are required'; exit 1)
	mkdir -p bin
	docker buildx build --file deploy/tools.Dockerfile --platform "$(TOOLS_PLATFORMS)" --tag "$(TOOLS_IMAGE):$(TOOLS_VERSION)" --output "$(TOOLS_OUTPUT)" .
