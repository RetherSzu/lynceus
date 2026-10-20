BINARY  := dfirflow
MAIN    := ./cmd/dfirflow
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
MODULE  := $(shell head -1 go.mod | cut -d' ' -f3)

.PHONY: build build-windows build-linux release test lint vet clean

## build: compile pour l'OS courant
build:
    go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(MAIN)

## build-windows: cross-compile Windows x64 (.exe)
build-windows:
    GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-windows-x64.exe $(MAIN)

## build-linux: cross-compile Linux x64
build-linux:
    GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY)-linux-x64 $(MAIN)

## release: tous les binaires + archives prêtes à distribuer
release: build-windows build-linux
    cd bin && zip -q $(BINARY)-windows-x64.zip $(BINARY)-windows-x64.exe && tar -czf $(BINARY)-linux-x64.tar.gz $(BINARY)-linux-x64

## test: tous les tests du module
test:
    go test ./... -v

## vet: analyse statique
vet:
    go vet ./...

## lint: golangci-lint (si installé)
lint:
    golangci-lint run ./...

clean:
    rm -rf bin/