package main

import (
	_"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v4"
	"fmt"
	"os"
	"io"
	"time"
	"log"
	"strings"
	"regexp"
	"errors"
	"net/http"
	"database/sql"
	"encoding/json"
	"encoding/base64"
	"crypto/rand"
	"crypto/sha256"
)

type handler struct {
	db *sql.DB
}

// at least 3 chars long; starts with alpha then word
var usernameRegexp = regexp.MustCompile(`^[a-zA-Z]{1}\w{2,}$`)
// 2 parts separated by +; first is word(includes -) at least 2 chars long; second is word at least 3 chars long
var appdeviceRegexp = regexp.MustCompile(`^[\w-]{2,}\+\w{3,}$`)

func expectMethod(m string, w http.ResponseWriter, r *http.Request) bool {
	match := r.Method == m
	if !match {
		w.Header().Set("Allow", m)
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
	return match
}

func validateCredentials(username, password string) error {
	if !usernameRegexp.MatchString(username) {
		return errors.New("username must start with a letter and be at least 3 characters long")
	}
	if len(password) < 3 {
		return errors.New("password must be at least 3 characters long")
	}
	return nil
}

func writeServerErr(w http.ResponseWriter, err error) {
	log.Println(err.Error())
	log.Printf("%#v\n", err)
	log.Println("-------------------------")
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

func createSalt() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func createHash(password, salt string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(password + salt)))
}

func hashPassword(password string) (string, string, error) {
	salt, err := createSalt()
	if err != nil {
		return "", "", err
	}
	hash := createHash(password, salt)
	return hash, salt, nil
}

func createToken(userId int64) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 26).Unix(),
		"user": userId,
	})
	return tok.SignedString([]byte(os.Getenv("JWT_SECRET")))
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

	err = validateCredentials(body.Username, body.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	row := h.db.QueryRow("SELECT id FROM user WHERE username = ?", body.Username)
	userId := -1
	err = row.Scan(&userId)
	if err != nil && err != sql.ErrNoRows {
		writeServerErr(w, err)
		return
	}
	if userId != -1 {
		writeErr(w, http.StatusBadRequest, "user already exists")
		return
	}

	hash, salt, err := hashPassword(body.Password)
	if err != nil {
		writeServerErr(w, err)
		return
	}

	_, err = h.db.Exec("INSERT INTO user (username, salt, password) VALUES (?, ?, ?)", body.Username, salt, hash)
	if err != nil {
		writeServerErr(w, err)
		return
	}

	writeData(w, http.StatusCreated, nil)
}

func login(h handler, w http.ResponseWriter, r *http.Request) {
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

	err = validateCredentials(body.Username, body.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	row := h.db.QueryRow("SELECT * FROM user WHERE username = ?", body.Username)
	user := struct {
		id int64
		username string
		salt string
		password string
	}{}

	err = row.Scan(&user.id, &user.username, &user.salt, &user.password)
	if err != nil {
		if err == sql.ErrNoRows {
			writeErr(w, http.StatusBadRequest, "user does not exist")
			return
		}
		writeServerErr(w, err)
		return
	}

	hash := createHash(body.Password, user.salt)
	if hash != user.password {
		writeErr(w, http.StatusBadRequest, "wrong password")
		return
	}

	tok, err := createToken(user.id)
	if err != nil {
		writeServerErr(w, err)
		return
	}

	writeData(w, http.StatusOK, tok)
}

func checkToken(h handler, w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		writeErr(w, http.StatusBadRequest, "no authorization header")
		return
	}

	scheme, token, found := strings.Cut(auth, " ")
	if !found {
		writeErr(w, http.StatusBadRequest, "wrong authorization header value")
		return
	}
	if scheme != "Bearer" {
		writeErr(w, http.StatusBadRequest, "wrong authentication scheme")
		return
	}

	claims := struct {
		User int64 `json:"user"`
		jwt.RegisteredClaims
	}{}
	_, err := jwt.ParseWithClaims(token, &claims, func (t *jwt.Token) (any, error) {
		 _, ok := t.Method.(*jwt.SigningMethodHMAC)
		 if !ok {
			 return nil, fmt.Errorf("unexpected signing method %v\n", t.Header["alg"])
		 }
		 return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	row := h.db.QueryRow("SELECT id FROM user WHERE id = ?", claims.User)
	userId := -1
	err = row.Scan(&userId)
	if err != nil {
		if err == sql.ErrNoRows {
			writeErr(w, http.StatusBadRequest, "user does not exist")
			return
		}
		writeServerErr(w, err)
		return
	}

	writeData(w, http.StatusOK, nil)
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodPost {
		if r.Header.Get("Content-Type") != "application/json" {
			writeErr(w, http.StatusBadRequest, "wrong content type")
			return
		}
	}

	switch r.URL.String() {
	case "/register":
		if expectMethod(http.MethodPost, w, r) {
			register(h, w, r)
		}
	case "/login":
		if expectMethod(http.MethodPost, w, r) {
			login(h, w, r)
		}
	case "/check-token":
		if expectMethod(http.MethodGet, w, r) {
			checkToken(h, w, r)
		}
	default:
		writeErr(w, http.StatusNotFound, "api route does not exist")
	}
}

func loadenv() {
	data, err := os.ReadFile(".env")
	if err != nil {
		log.Fatalf("%#v\n", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, ln := range lines {
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
