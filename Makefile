.PHONY: setup build run test clean fmt vet \
       services_crypto_test services_metadata_test \
       services_auth_user_test services_auth_session_test \
       handler_test auth_middleware_test \
       local_connector_test

# ── Build & Run ───────────────────────────────────────────────

setup:
	@./setup.sh


build:
	go build -tags "fts5" -o docops .

run:
	go run -tags "fts5" main.go

clean:
	rm -f docops

# ── Code Quality & Formatting ─────────────────────────────────

fmt:
	go fmt ./...

vet:
	go vet -tags "fts5" ./...

# ── Test All ──────────────────────────────────────────────────

test:
	go test -tags "fts5" -v ./...

# ── Test by Package ───────────────────────────────────────────

services_crypto_test:
	go test -v ./services/crypto/

services_metadata_test:
	go test -tags "fts5" -v ./services/metadata/

services_auth_user_test:
	go test -v ./services/auth/ -run TestUser

services_auth_session_test:
	go test -v ./services/auth/ -run TestSession

handler_test:
	go test -tags "fts5" -v ./handlers/

auth_middleware_test:
	go test -v ./middleware/

local_connector_test:
	go test -v ./connectors/local/