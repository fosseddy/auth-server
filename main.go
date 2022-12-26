package main

import (
	"fmt"
	"net/http"
	"os"
	"io"
	"encoding/json"
)

const addr string = ":3000"

func main() {
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotImplemented)
			return;
		}

		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusNotImplemented)
			return;
		}

		rbody, _ := io.ReadAll(r.Body)
		rbodyjson := map[string]any{}
		json.Unmarshal(rbody, &rbodyjson) // handle error

		wbody := map[string]any{
			"data": map[string]string{
				"token": "sadf7as0d9f7a90s7df",
			},
		}
		wbodyjson, _ := json.Marshal(wbody) // handle error

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(wbodyjson)
	})

	fmt.Println("server is listening on", addr)
	err := http.ListenAndServe(addr, nil)
	fmt.Fprintf(os.Stderr, "failed to start a server: %v\n", err)
}
