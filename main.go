package main

import (
	"fmt"
	"net/http"
	"os"
	"io"
	"encoding/json"
)

const addr string = ":3000"

type handler struct {
	msg string
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uri := r.URL.String()
	method := r.Method

	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if uri != "/register" && method != http.MethodPost {
		w.WriteHeader(http.StatusNotImplemented)
		return
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
}

func main() {
	h := handler{"hello, world\n"}
	s := http.Server{Addr: addr, Handler: h}

	fmt.Println("server is listening on", s.Addr)
	err := s.ListenAndServe()
	fmt.Fprintf(os.Stderr, "failed to start a server: %v\n", err)
}
