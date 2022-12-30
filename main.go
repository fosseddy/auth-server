package main

import (
	"fmt"
	"net/http"
	"os"
	"database/sql"
	_"github.com/go-sql-driver/mysql"
	"time"
	"log"
	"strings"
)

type handler struct {
	db *sql.DB
}

func loadenv() {
	data, err := os.ReadFile(".env")
	if err != nil {
		log.Fatal(err)
	}

	lines := strings.Split(string(data), "\n")
	tmp := []string{}
	for _, ln := range(lines) {
		ln = strings.Trim(ln, " ")
		if ln == "" {
			continue
		}
		tmp = append(tmp, ln)
	}

	lines = tmp
	if len(lines) == 0 {
		log.Fatal(".env is empty")
	}
	for _, ln := range(lines) {
		k, v, found := strings.Cut(ln, "=")
		if !found {
			log.Fatal("wrong line in .env file: ", ln)
		}

		k = strings.Trim(k, " ")
		v = strings.Trim(v, " ")

		err := os.Setenv(k, v)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(r.URL.String()))
}

func connectDatabase() *sql.DB {
	connStr := fmt.Sprintf(
		"%s:%s@/%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_USERPWD"),
		os.Getenv("DB_NAME"),
	)

	db, err := sql.Open("mysql", connStr)
	if err != nil {
		log.Fatal(err)
	}

	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	return db
}

func main() {
	loadenv()

	h := handler{db: connectDatabase()}
	s := http.Server{Addr: ":" + os.Getenv("PORT"), Handler: h}
	err := s.ListenAndServe()
	log.Fatal(err)
}
