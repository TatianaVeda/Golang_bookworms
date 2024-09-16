package controllers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sync"
	"time"

	"literary-lions/database"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// SessionStore stores session data (sessionID -> userID)
var SessionStore = make(map[string]int) // In-memory store: sessionID -> userID
var SessionMutex sync.Mutex             // Mutex to prevent race conditions on session store

const csrfCookieName = "csrf_token"

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

// RegisterUser handles user registration and CSRF token validation
func RegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()

		// CSRF token validation
		formToken := r.FormValue("csrf_token")
		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			fmt.Printf("Invalid CSRF token. Form token: %s, Cookie token: %s\n", formToken, cookieToken)
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		// Extract form data
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		// Insert user into the database
		_, err = database.DB.Exec(`INSERT INTO users (email, username, password) VALUES (?, ?, ?)`, email, username, hashedPassword)
		if err != nil {
			// Handle unique constraint errors (e.g., duplicate email or username)
			if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrConstraint {
				// Re-render home page with registration error
				tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
				data := map[string]interface{}{
					"RegistrationError": "The email or username already exists. Please try again.",
					"CsrfToken":         formToken,
					"ShowModal":         true, // Keep the modal open
					"IsRegistering":     true, // Ensure the Register tab is active
				}
				fmt.Printf("Template Data: %+v\n", data)
				tmpl.Execute(w, data)
				return
			}

			// General error handling
			fmt.Fprintf(w, "Error registering user: %v", err)
			return
		}

		// Re-render home page with success message
		tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
		data := map[string]interface{}{
			"RegistrationSuccess": true,
			"CsrfToken":           formToken,
			"ShowModal":           true,
			"IsRegistering":       false, // After successful registration, go back to login tab
		}
		tmpl.Execute(w, data)

	} else {
		// Get or generate CSRF token
		csrfToken, err := GenerateAndSetCSRFToken(w, r)
		if err != nil {
			http.Error(w, "Error generating CSRF token", http.StatusInternalServerError)
			return
		}

		// Render the registration template with the CSRF token
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
	SessionMutex.Lock()
	SessionStore[sessionID] = userID
	SessionMutex.Unlock()

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

// LoginUser handles user login and CSRF token validation
func LoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form", http.StatusInternalServerError)
			return
		}

		// CSRF token validation
		formToken := r.FormValue("csrf_token")
		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		// Extract form data and authenticate
		email := r.FormValue("email")
		password := r.FormValue("password")
		row := database.DB.QueryRow(`SELECT id, password FROM users WHERE email = ?`, email)

		var id int
		var hashedPassword string
		err = row.Scan(&id, &hashedPassword)
		if err == sql.ErrNoRows || bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) != nil {
			// Invalid login attempt, re-render the home page with error message
			tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
			data := map[string]interface{}{
				"LoginError":    "Invalid email or password.",
				"CsrfToken":     formToken,
				"ShowModal":     true,  // Keep the modal open
				"IsRegistering": false, // Ensure the Login tab is active
			}
			tmpl.Execute(w, data)
			return
		}

		// Set session cookie on successful login
		err = SetSessionCookie(w, id)
		if err != nil {
			fmt.Fprintf(w, "Error setting session: %v", err)
			return
		}

		// Re-render home page with login success message
		tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
		data := map[string]interface{}{
			"LoginSuccess": true,
			"IsLoggedIn":   true,
			"CsrfToken":    formToken,
			"ShowModal":    false, // Close the modal upon successful login
		}
		tmpl.Execute(w, data)

	} else {
		// Get or generate CSRF token
		csrfToken, err := GenerateAndSetCSRFToken(w, r)
		if err != nil {
			http.Error(w, "Error generating CSRF token", http.StatusInternalServerError)
			return
		}

		// Render the login template with the CSRF token
		tmpl := template.Must(template.ParseFiles("views/login.html"))
		tmpl.Execute(w, map[string]interface{}{
			"CsrfToken": csrfToken,
		})
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Get session cookie
	cookie, err := r.Cookie("session_id")

	if err == nil {
		fmt.Println("Found session cookie:", cookie.Value)

		SessionMutex.Lock()
		delete(SessionStore, cookie.Value) // Remove session from store
		SessionMutex.Unlock()
		fmt.Println("Session deleted from store:", cookie.Value)

		// Clear the cookie by setting it to expire immediately
		http.SetCookie(w, &http.Cookie{
			Name:   "session_id",
			Value:  "",
			MaxAge: -1,  // Immediate expiration
			Path:   "/", // Ensure the path matches
		})
		fmt.Println("Session cookie cleared, user logged out.")
	} else {
		fmt.Println("No session cookie found.")
	}

	// Redirect to home page after logout
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
