package main

import (
	"fmt"
	"net/http"
	"os"
	"io"
	"encoding/json"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"time"
)

const addr string = ":3000"

type handler struct {}

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

type user struct {
	id int
	username string
	password string
}

func main() {
	db, err := sql.Open("mysql", "art:123@/auth-server")
	if err != nil {
		panic(err)
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	rows, err := db.Query("select * from user")
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	users := []user{}
	for rows.Next() {
		u := user{}
		err := rows.Scan(&u.id, &u.username, &u.password)
		if err != nil {
			panic(err)
		}
		users = append(users, u)
	}

	err = rows.Err()
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", users)

	h := handler{}
	s := http.Server{Addr: addr, Handler: h}

	fmt.Println("server is listening on", s.Addr)
	err = s.ListenAndServe()
	fmt.Fprintf(os.Stderr, "failed to start a server: %v\n", err)
}
