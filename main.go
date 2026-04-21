package main

import (
	"fmt"
	"log"
	"net/http"
	
	"github.com/Kyei-Ernest/DocOps/services/crypto"
	//"github.com/Kyei-Ernest/DocOps/database"

	
)

func main() {
	//database.Migrations()
	
	//if err := database.Init(); err != nil {
    //    panic(err)
    //}
    //defer database.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "welcome to the docops project")
	})
	http.HandleFunc("/decode", crypto.DecryptHandler)
	http.HandleFunc("/encode", crypto.EncryptHandler)


	log.Fatal(http.ListenAndServe(":8080", nil))
}
