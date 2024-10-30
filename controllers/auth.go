// auth.html
package controllers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"

	"literary-lions/database"

	"github.com/google/uuid"
	"github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var SessionStore = make(map[string]int) // Session store to map session IDs to user IDs
var SessionMutex sync.Mutex             // Mutex to prevent race conditions on session store
const csrfCookieName = "csrf_token"

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost) // GenerateFromPassword returns a byte slice so we need to cast to a string
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func GenerateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func SetCSRFCookie(w http.ResponseWriter, token string) {
	cookie := http.Cookie{ // Create a cookie with the CSRF token
		Name:     csrfCookieName,
		Value:    token,
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	}
	http.SetCookie(w, &cookie)
}

func GenerateAndSetCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	cookieToken, err := GetCSRFCookie(r) // Get the CSRF token from the cookie
	if err == nil {
		return cookieToken, nil
	}

	csrfToken, err := GenerateCSRFToken() // Generate a new CSRF token
	if err != nil {
		return "", err
	}
	SetCSRFCookie(w, csrfToken)

	return csrfToken, nil
}

func GetCSRFCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(csrfCookieName) // Get the CSRF token from the cookie
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			renderModalWithMessage(w, r, "Unable to parse form data", true, false)
			return
		}

		formToken := r.FormValue("csrf_token") // Get the CSRF token from the form
		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			renderModalWithMessage(w, r, "Invalid CSRF token.", true, false)
			return
		}

		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if !isValidEmail(email) { // Check if the email is valid
			renderModalWithMessage(w, r, "Invalid email format.", true, false)
			return
		}

		if len(password) < 8 {
			renderModalWithMessage(w, r, "Password must be at least 8 characters long.", true, false)
			return
		}

		hashedPassword, err := HashPassword(password)
		if err != nil {
			renderModalWithMessage(w, r, "Error hashing password.", true, false)
			return
		}

		_, err = database.DB.Exec(`INSERT INTO users (email, username, password) VALUES (?, ?, ?)`, email, username, hashedPassword)
		if err != nil {
			if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrConstraint {
				renderModalWithMessage(w, r, "Email or username already exists.", true, false)
				return
			}
			renderModalWithMessage(w, r, "Error registering user.", true, false)
			return
		}

		renderModalWithMessage(w, r, "Registration successful! Welcome!", true, true)
	}
}

func isValidEmail(email string) bool {
	const emailRegexPattern = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegexPattern)
	return re.MatchString(email)
}

func renderModalWithMessage(w http.ResponseWriter, r *http.Request, message string, isRegistering bool, isSuccess bool) {
	csrfToken, _ := GenerateAndSetCSRFToken(w, r) // Generate and set the CSRF token

	tmpl := template.Must(template.ParseFiles(
		"views/home.html",
		"views/auth.html",
		"views/categories.html",
		"views/create_post.html",
	))

	data := map[string]interface{}{
		"ShowModal":         true, // Keeps the modal open
		"CsrfToken":         csrfToken,
		"IsRegistering":     isRegistering,
		"RegistrationError": "",
		"LoginError":        "",
		"SuccessMessage":    "",
	}

	if isSuccess { // Set the success message
		data["SuccessMessage"] = message
	} else if isRegistering {
		data["RegistrationError"] = message
	} else {
		data["LoginError"] = message
	}

	log.Printf("Rendering modal with message: %s", message)
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template rendering error: %v", err)
		http.Error(w, "Error rendering page", http.StatusInternalServerError)
	}
}

func GenerateSessionID() (string, error) {
	sessionID := uuid.New().String() // Generate a new UUID
	return sessionID, nil
}

func SetSessionCookie(w http.ResponseWriter, userID int) error {
	sessionID, err := GenerateSessionID() // Now generates a UUID
	if err != nil {
		return err
	}

	SessionMutex.Lock()              // Lock the session store
	SessionStore[sessionID] = userID // Add the user ID to the session store
	SessionMutex.Unlock()            // Unlock the session store

	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true, // Secure the cookie
	}
	http.SetCookie(w, cookie)

	return nil
}

func CheckPasswordHash(password, hashedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) // Compare the password with the hashed password
	if err != nil {
		return errors.New("incorrect password")
	}
	return nil
}

func CreateSession(userID int) (string, error) {
	sessionID := uuid.New().String()
	expirationTime := time.Now().Add(24 * time.Hour) // Set the expiration time to 24 hours from now

	log.Printf("CreateSession: Inserting session for user ID %d with session ID %s", userID, sessionID)
	_, err := database.DB.Exec("INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)", sessionID, userID, expirationTime)
	if err != nil {
		log.Printf("CreateSession: Error inserting session into database: %v", err)
		return "", err
	}

	SessionMutex.Lock()
	SessionStore[sessionID] = userID
	SessionMutex.Unlock()

	log.Printf("CreateSession: Session created for user ID %d with session ID %s", userID, sessionID)
	return sessionID, nil
}

func GetSession(r *http.Request) (int, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return 0, fmt.Errorf("session cookie not found")
	}

	sessionID := cookie.Value
	SessionMutex.Lock()
	userID, exists := SessionStore[sessionID]
	SessionMutex.Unlock()

	if !exists {
		return 0, fmt.Errorf("invalid session ID")
	}
	return userID, nil
}

func LoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			log.Println("Error parsing form:", err)
			renderModalWithMessage(w, r, "Unable to parse form", false, false)
			return
		}

		formToken := r.FormValue("csrf_token")
		cookieToken, err := GetCSRFCookie(r) // Get the CSRF token from the cookie
		if err != nil || formToken != cookieToken {
			log.Println("Invalid CSRF token")
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		email := r.FormValue("email") // 	Get the email and password from the form
		password := r.FormValue("password")
		userID, err := Authenticate(email, password)
		if err != nil {
			log.Println("Authentication failed:", err)
			renderModalWithMessage(w, r, "Invalid email or password.", false, false)
			return
		}

		sessionID, err := CreateSession(userID) // 	Create a new session for the user
		if err != nil {
			log.Println("Error creating session:", err)
			http.Error(w, "Error creating session", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "session_id",
			Value:   sessionID,
			Expires: time.Now().Add(24 * time.Hour),
			Path:    "/",
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id") // Retrieve the session cookie and clear it
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	sessionID := cookie.Value
	SessionMutex.Lock()
	_, sessionExists := SessionStore[sessionID]
	if sessionExists {
		delete(SessionStore, sessionID)
	}
	SessionMutex.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1, // Expire immediately
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func Authenticate(email, password string) (int, error) {
	var userID int
	var storedPassword string

	err := database.DB.QueryRow("SELECT id, password FROM users WHERE email = ?", email).Scan(&userID, &storedPassword) // Get the user ID and password from the database
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, errors.New("invalid credentials")
		}
		return 0, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password)); err != nil {
		return 0, errors.New("invalid credentials")
	}

	return userID, nil
}

func VerifySession(sessionID string) (int, error) {
	SessionMutex.Lock()
	defer SessionMutex.Unlock()

	userID, exists := SessionStore[sessionID]
	if !exists {
		return 0, errors.New("invalid session")
	}

	return userID, nil
}
