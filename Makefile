GO ?= go
GOFLAGS := -v
PKG := ./...
TESTS := ".*"
GOIMPORTS := ../../../../bin/goimports
GOLINT := ../../../../bin/golint
GLOCK := ../../../../bin/glock
BINDATA := ../../../../bin/go-bindata

.PHONY: build
build: docs.go test
	$(GO) install $(GOFLGS) -v

$(GLOCK):
	go get -v github.com/robfig/glock

.PHONY: setup
setup: $(GLOCK)
	$(GLOCK) sync github.com/dcoker/secrets
	$(GLOCK) install github.com/dcoker/secrets

.PHONY: test
test:
	$(GO) test $(GOFLAGS) -i $(PKG)
	$(GO) test $(GOFLAGS) $(PKG)

docs.go: docs 
	$(BINDATA) -o docs.go -ignore=\\.gitignore docs/...
	gofmt -s -w docs.go

.PHONY: check
check:
	$(GO) tool vet . 2>&1
	$(GO) tool vet --shadow . 2>&1
	$(GOLINT) $(PKG)

.PHONY: fmt
fmt:
	gofmt -s -w .
	$(GOIMPORTS) -w .

.PHONY: clean
clean:
	$(GO) clean $(GOFLAGS) -i $(PKG)

docker-build:
	docker build -f Dockerfile.e2e .
