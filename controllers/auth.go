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

// SessionStore stores session data (sessionID -> userID)
var SessionStore = make(map[string]int) // In-memory store: sessionID -> userID
var SessionMutex sync.Mutex             // Mutex to prevent race conditions on session store

const csrfCookieName = "csrf_token"

// HashPassword hashes the user's password using bcrypt
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// GenerateCSRFToken generates a new random CSRF token
func GenerateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SetCSRFCookie sets the CSRF token as an HTTP-only cookie
func SetCSRFCookie(w http.ResponseWriter, token string) {
	cookie := http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour), // Set an expiration time
	}
	http.SetCookie(w, &cookie)
}

func GenerateAndSetCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	// Check if the CSRF cookie already exists
	cookieToken, err := GetCSRFCookie(r)
	if err == nil {
		// Return the existing CSRF token from the cookie
		return cookieToken, nil
	}

	// If no valid CSRF token exists, generate a new one
	csrfToken, err := GenerateCSRFToken()
	if err != nil {
		return "", err
	}
	SetCSRFCookie(w, csrfToken)

	return csrfToken, nil
}

// GetCSRFCookie retrieves the CSRF token from the request's cookies
func GetCSRFCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(csrfCookieName)
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

		formToken := r.FormValue("csrf_token")
		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			renderModalWithMessage(w, r, "Invalid CSRF token.", true, false)
			return
		}

		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if !isValidEmail(email) {
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

		// Registration successful, render success message
		renderModalWithMessage(w, r, "Registration successful! Welcome!", true, true) // Success message
	}
}

// isValidEmail checks if the provided email has a valid format
func isValidEmail(email string) bool {
	// Simple email regex pattern
	const emailRegexPattern = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegexPattern)
	return re.MatchString(email)
}

func renderModalWithMessage(w http.ResponseWriter, r *http.Request, message string, isRegistering bool, isSuccess bool) {
	csrfToken, _ := GenerateAndSetCSRFToken(w, r)

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

	if isSuccess {
		// Set success message (will display in green)
		data["SuccessMessage"] = message
	} else if isRegistering {
		// Set registration error
		data["RegistrationError"] = message
	} else {
		// Set login error
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

	SessionMutex.Lock()
	SessionStore[sessionID] = userID
	SessionMutex.Unlock()

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
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return errors.New("incorrect password")
	}
	return nil
}

func CreateSession(userID int) (string, error) {
	sessionID := uuid.New().String()
	expirationTime := time.Now().Add(24 * time.Hour)

	// Insert the session into the database
	log.Printf("CreateSession: Inserting session for user ID %d with session ID %s", userID, sessionID)
	_, err := database.DB.Exec("INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)", sessionID, userID, expirationTime)
	if err != nil {
		log.Printf("CreateSession: Error inserting session into database: %v", err)
		return "", err
	}

	// Store the session in the in-memory session store
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

	// Retrieve session ID from the cookie
	sessionID := cookie.Value

	// Lock the session store before accessing
	SessionMutex.Lock()
	userID, exists := SessionStore[sessionID]
	SessionMutex.Unlock()

	if !exists {
		return 0, fmt.Errorf("invalid session ID")
	}

	// Return the user ID from the session
	return userID, nil
}

// Updated login handler
func LoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			log.Println("Error parsing form:", err)
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		// Get CSRF token and validate
		formToken := r.FormValue("csrf_token")
		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			log.Println("Invalid CSRF token")
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		// Authenticate the user
		email := r.FormValue("email")
		password := r.FormValue("password")
		userID, err := Authenticate(email, password)
		if err != nil {
			log.Println("Authentication failed:", err)
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
			return
		}

		// Create session
		sessionID, err := CreateSession(userID)
		if err != nil {
			log.Println("Error creating session:", err)
			http.Error(w, "Error creating session", http.StatusInternalServerError)
			return
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "session_id",
			Value:   sessionID,
			Expires: time.Now().Add(24 * time.Hour),
			Path:    "/",
		})

		// Redirect to homepage
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session cookie and clear it
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	sessionID := cookie.Value

	// Attempt to lock and delete the session from the in-memory store
	SessionMutex.Lock()
	_, sessionExists := SessionStore[sessionID]
	if sessionExists {
		delete(SessionStore, sessionID)
	}
	SessionMutex.Unlock()

	// Always remove the session cookie, even if the session doesn't exist
	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1, // Expire immediately
	})

	// Redirect to the homepage or login page after logout
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Authenticate checks if the user's email and password are valid
func Authenticate(email, password string) (int, error) {
	var userID int
	var storedPassword string

	// Assuming database.DB is your DB connection
	err := database.DB.QueryRow("SELECT id, password FROM users WHERE email = ?", email).Scan(&userID, &storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, errors.New("invalid credentials")
		}
		return 0, err
	}

	// Check if password matches (you'll likely use bcrypt for hashing)
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
