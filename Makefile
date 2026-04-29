.PHONY: run store_test crypto_test build

run:
	go run -tags "fts5" main.go

store_test:
	go test -tags "fts5" -v ./services/metadata/

crypto_test:
	go test -v ./services/crypto/

auth_user_test:
	go test -v ./services/auth/

session_test:
	go test -v ./services/auth/

build:
	go build -tags "fts5" -o docops .