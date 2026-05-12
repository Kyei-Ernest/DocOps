package main

import "fmt"

func main() {
    type contextKey struct{ name string }

    var (
	// KEKKey is the context key under which the session KEK ([]byte) is stored.
	KEKKey = &contextKey{"kek"}

	// UserIDKey is the context key under which the authenticated user ID (string) is stored.
	UserIDKey = &contextKey{"userID"}
)

fmt.Println(KEKKey.name, UserIDKey.name)
}