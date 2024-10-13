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

func LoginUser(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request with method: %s, URL: %s", r.Method, r.URL.Path)

	if r.Method != http.MethodPost {
		log.Printf("Invalid request method: %s. Redirecting to /", r.Method)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing form: %v", err)
		renderModalWithMessage(w, r, "Unable to parse form data", false, false)
		return
	}

	log.Println("Successfully parsed login form.")

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			renderModalWithMessage(w, r, "Unable to parse form data", false, false)
			return
		}

		// Validate CSRF token
		formToken := r.FormValue("csrf_token")
		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			renderModalWithMessage(w, r, "Invalid CSRF token.", false, false)
			return
		}

		// Extract form data
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Check for empty fields
		if email == "" || password == "" {
			renderModalWithMessage(w, r, "Email and password cannot be empty.", false, false)
			return
		}

		// Retrieve user info from database
		row := database.DB.QueryRow(`SELECT id, password FROM users WHERE email = ?`, email)
		var id int
		var storedHashedPassword string
		err = row.Scan(&id, &storedHashedPassword)
		if err == sql.ErrNoRows {
			renderModalWithMessage(w, r, "Invalid email or password.", false, false)
			return
		} else if err != nil {
			renderModalWithMessage(w, r, "Error retrieving user. Please try again.", false, false)
			return
		}

		// Check password
		if err := bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(password)); err != nil {
			renderModalWithMessage(w, r, "Invalid email or password.", false, false)
			return
		}

		// Successful login
		sessionID, err := CreateSession(id)
		if err != nil {
			renderModalWithMessage(w, r, "Error creating session.", true, true)
			return
		}

		// Set session cookie and redirect
		http.SetCookie(w, &http.Cookie{
			Name:  "session_id",
			Value: sessionID,
			Path:  "/",
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session cookie and clear it
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther) // Redirect to home if cookie is not found
		return
	}

	// Lock and delete the session from the in-memory store
	SessionMutex.Lock()
	delete(SessionStore, cookie.Value)
	SessionMutex.Unlock()

	// Set the cookie to expire immediately
	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1, // Expire immediately
	})

	// Redirect to the homepage or login page after logout
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
