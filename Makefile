.PHONY: test lint build run

test:
	go test -race ./...

lint:
	golangci-lint run

build:
	CGO_ENABLED=0 go build -trimpath -o bin/bridge ./cmd/bridge

# Runs the bridge with config.yaml and the secrets in .env from the repository root, both of which .gitignore keeps out of commits
run:
	set -a; [ ! -f .env ] || . ./.env; set +a; go run ./cmd/bridge --config config.yaml --log-level debug
