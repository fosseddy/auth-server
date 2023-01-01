package main

import (
	_"github.com/go-sql-driver/mysql"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"io"
	"time"
	"log"
	"strings"
	"encoding/json"
	"encoding/base64"
	"regexp"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// at least 3 chars long, starts with alpha then [a-zA-Z0-9_]
var	usernameRegexp = regexp.MustCompile(`^[a-zA-Z]{1}\w{2,}$`)

type handler struct {
	db *sql.DB
}

func expectMethod(m string, w http.ResponseWriter, r *http.Request) bool {
	match := r.Method == m
	if !match {
		w.Header().Set("Allow", m)
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
	return match
}

func writeData(w http.ResponseWriter, status int, data any) {
	w.WriteHeader(status)
	if data == nil {
		return
	}
	m := map[string]any{"data": data}
	b, err := json.Marshal(m)
	if err != nil {
		writeServerErr(w, err)
		return
	}
	w.Write(b)
}

func writeServerErr(w http.ResponseWriter, err error) {
	log.Printf("%#v\n", err)
	w.WriteHeader(http.StatusInternalServerError)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	m := map[string]any{"error": map[string]any{"code": status, "message": msg}}
	b, err := json.Marshal(m)
	if err != nil {
		writeServerErr(w, err)
		return
	}
	w.WriteHeader(status)
	w.Write(b)
}

func readBody(body io.Reader, target any) error {
	err := json.NewDecoder(body).Decode(target)
	if err != nil {
		msg := "invalid json"
		err, ok := err.(*json.UnmarshalTypeError)
		if ok {
			msg = err.Field + " must be " + err.Type.String()
		}
		return errors.New(msg)
	}
	return nil
}

func register(h handler, w http.ResponseWriter, r *http.Request) {
	body := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{}
	err := readBody(r.Body, &body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	body.Username = strings.TrimSpace(body.Username)
	body.Password = strings.TrimSpace(body.Password)

	if !usernameRegexp.MatchString(body.Username) {
		writeErr(w, http.StatusBadRequest, "username must start with a letter and be at least 3 characters long")
		return
	}
	if len(body.Password) < 3 {
		writeErr(w, http.StatusBadRequest, "password must be at least 3 characters long")
		return
	}

	row := h.db.QueryRow("SELECT id FROM user WHERE username = ?", body.Username)
	err = row.Err()
	if err != nil {
		writeServerErr(w, err)
		return
	}
	err = row.Scan()
	if err != sql.ErrNoRows {
		writeErr(w, http.StatusBadRequest, "username already exists")
		return
	}

	saltBytes := make([]byte, 32)
	_, err = rand.Read(saltBytes)
	if err != nil {
		writeServerErr(w, err)
		return
	}
	salt := base64.URLEncoding.EncodeToString(saltBytes)
	password := fmt.Sprintf("%x", sha256.Sum256([]byte(body.Password + salt)))

	_, err = h.db.Exec("INSERT INTO user (username, salt, password) VALUES (?, ?, ?)", body.Username, salt, password)
	if err != nil {
		writeServerErr(w, err)
		return
	}

	// @Todo(art): login user?

	writeData(w, http.StatusCreated, nil)
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// @Todo(art): handle it later
	//if r.Header.Get("Content-Type") != "application/json" {
	//	w.WriteHeader(http.StatusBadRequest)
	//	w.Write([]byte(`{"message":"wrong content type"}`))
	//	return
	//}

	switch r.URL.String() {
	case "/register":
		if expectMethod(http.MethodPost, w, r) {
			register(h, w, r)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"api route does not exist"}`))
	}
}

func loadenv() {
	data, err := os.ReadFile(".env")
	if err != nil {
		log.Fatalf("%#v\n", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, ln := range(lines) {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}

		k, v, found := strings.Cut(ln, "=")
		if !found {
			log.Println("wrong line in .env file: ", ln)
			continue
		}

		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)

		err := os.Setenv(k, v)
		if err != nil {
			log.Fatalf("%#v\n", err)
		}
	}
}

func connectDatabase() *sql.DB {
	connStr := fmt.Sprintf("%s:%s@/%s", os.Getenv("DB_USER"), os.Getenv("DB_USERPWD"), os.Getenv("DB_NAME"))
	db, err := sql.Open("mysql", connStr)
	if err != nil {
		log.Fatalf("%#v\n", err)
	}

	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	err = db.Ping()
	if err != nil {
		log.Fatalf("%#v\n", err)
	}

	return db
}

func main() {
	loadenv()

	h := handler{db: connectDatabase()}
	s := http.Server{Addr: ":" + os.Getenv("PORT"), Handler: h}
	err := s.ListenAndServe()
	log.Fatalf("%#v\n", err)
}
