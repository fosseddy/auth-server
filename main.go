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
	"encoding/json"
	"regexp"
)

// at least 3 chars long, starts with alpha then [a-zA-Z0-9_]
var	usernameRegexp = regexp.MustCompile(`^[a-zA-Z]{1}\w{2,}$`)

type handler struct {
	db *sql.DB
	body map[string]any
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

func allowMethods(w http.ResponseWriter, r *http.Request,
		methods ...string) bool {
	allowed := false
	for _, m := range methods {
		if r.Method == m {
			allowed = true
			break
		}
	}
	if !allowed {
		w.Header().Set("Allow", strings.Join(methods, ", "))
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
	return allowed
}

func register(h handler, w http.ResponseWriter, r *http.Request) {
	body := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		err, ok := err.(*json.UnmarshalTypeError)
		if ok {
			w.Write([]byte(fmt.Sprintf(
				`{"message":"%s must be %s"}`, err.Field, err.Type.String(),
			)))
		} else {
			w.Write([]byte(`{"message":"invalid json"}`))
		}
		return
	}

	body.Username = strings.Trim(body.Username, " ")
	body.Password = strings.Trim(body.Password, " ")

	if !usernameRegexp.MatchString(body.Username) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(
			`{"message":"username must start with a letter and ` +
			`be at least 3 characters long"}`,
		))
		return
	}
	if len(body.Password) < 3 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(
			`{"message":"password must be at least 3 characters long"}`,
		))
		return
	}

	// validate user

	// hash password

	// create user

	// generate token?

	w.WriteHeader(http.StatusCreated)
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	m := r.Method
	if m == http.MethodPost || m == http.MethodPut ||
			m == http.MethodDelete || m == http.MethodPatch {
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"message":"wrong content type"}`))
			return
		}
	}

	switch r.URL.String() {
	case "/register":
		if allowMethods(w, r, http.MethodPost) {
			register(h, w, r)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"api route does not exist"}`))
	}
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
