package main

import (
	"fmt"
	"net/http"
	"os"
)

const addr string = ":3000"

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-type", "application/json")
		fmt.Fprint(w, `{"message":"hello, world"}`)
	})

	fmt.Println("server is listening on", addr)
	err := http.ListenAndServe(addr, nil)
	fmt.Fprintf(os.Stderr, "failed to start a server: %v\n", err)
}
