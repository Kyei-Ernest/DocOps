.PHONY: run store_test crypto_test build

run:
	go run -tags "fts5" main.go

services_metadata_test:
	go test -tags "fts5" -v ./services/metadata/

services_crypto_test:
	go test -v ./services/crypto/

services_auth_user_test:package middleware

	go test -v ./services/auth/

services_auth_session_test:
	go test -v ./services/auth/

auth_handler_test:
	go test -v ./handlers/

auth_middleware_test:
	go test -v ./middleware/

local_connector_test:
	go test -v ./connectors/local/

build:
	go build -tags "fts5" -o docops .