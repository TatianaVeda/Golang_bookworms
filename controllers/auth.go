package controllers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	"literary-lions/database"

	"golang.org/x/crypto/bcrypt"
)

// SessionStore stores session data (sessionID -> userID)
var sessionStore = make(map[string]int) // In-memory store: sessionID -> userID
var sessionMutex sync.Mutex             // Mutex to prevent race conditions on session store

// Generate a CSRF token for forms
func generateCSRFToken() string {
	token := make([]byte, 32)
	rand.Read(token)
	return base64.URLEncoding.EncodeToString(token)
}

// Store CSRF tokens in memory (for simplicity)
var csrfTokens = map[string]bool{}

// Add this logic when generating the CSRF token in the GET request:
func RegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()

		csrfToken := r.FormValue("csrf_token")
		if !csrfTokens[csrfToken] {
			log.Printf("Invalid CSRF token: %s", csrfToken)
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		delete(csrfTokens, csrfToken)

		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password") // <-- Correctly fetching the user-supplied password

		// Check if the username or email already exists
		var exists bool
		err := database.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = ? OR username = ?)", email, username).Scan(&exists)
		if err != nil {
			log.Printf("Database query error: %v", err)
			http.Error(w, "Database query error", http.StatusInternalServerError)
			return
		}

		if exists {
			// If user already exists, return an error message
			log.Printf("Email or username already in use: %s, %s", email, username)
			http.Error(w, "Email or username already in use", http.StatusConflict)
			return
		}

		// Hash the password using bcrypt
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		// Insert user into the database
		_, err = database.DB.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", username, email, hashedPassword)
		if err != nil {
			fmt.Fprintf(w, "Error registering user: %v", err)
			return
		}

		// Redirect to login page after successful registration
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	} else if r.Method == http.MethodGet {
		csrfToken := generateCSRFToken()
		log.Printf("Generated CSRF token: %s", csrfToken)
		csrfTokens[csrfToken] = true

		tmpl := template.Must(template.ParseFiles("views/register.html"))
		tmpl.Execute(w, map[string]interface{}{
			"CsrfToken": csrfToken,
		})
	}
}

func GenerateSessionID() (string, error) {
	bytes := make([]byte, 16) // 128-bit session ID
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// SetSessionCookie sets the session cookie and stores session data
func SetSessionCookie(w http.ResponseWriter, userID int) error {
	sessionID, err := GenerateSessionID()
	if err != nil {
		return err
	}

	// Store the session ID with the userID
	sessionMutex.Lock()
	sessionStore[sessionID] = userID
	sessionMutex.Unlock()

	// Set the session ID in a cookie
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true, // Secure the cookie
	}
	http.SetCookie(w, cookie)

	return nil
}

// GetUserIDFromSession retrieves the user ID associated with the session cookie

func LoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()

		// CSRF token validation
		csrfToken := r.FormValue("csrf_token")
		log.Printf("Submitted CSRF token: %s", csrfToken)
		if !csrfTokens[csrfToken] {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		delete(csrfTokens, csrfToken)

		email := r.FormValue("email")
		password := r.FormValue("password")

		// Query for user in the database by email
		row := database.DB.QueryRow(`SELECT id, password FROM users WHERE email = ?`, email)

		var userID int
		var storedHash string
		err := row.Scan(&userID, &storedHash)
		if err == sql.ErrNoRows {
			log.Printf("No user found with email: %s", email)
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
			return
		} else if err != nil {
			log.Printf("Database query error: %v", err)
			http.Error(w, "Database query error", http.StatusInternalServerError)
			return
		}

		// Print stored hash and provided password for debugging
		log.Printf("Stored hashed password: %s", storedHash)
		log.Printf("Provided password: %s", password)

		// Compare the stored hashed password with the provided password
		err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
		if err != nil {
			log.Printf("Password comparison failed for email: %s", email)
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
			return
		}

		// If successful, set session cookie and log in the user
		err = SetSessionCookie(w, userID)
		if err != nil {
			http.Error(w, "Error setting session cookie", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
}
