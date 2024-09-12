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
		if err := r.ParseForm(); err != nil {
			fmt.Println("Error parsing form:", err)
		}

		// Retrieve CSRF token from form and cookie
		formToken := r.FormValue("csrf_token")
		fmt.Printf("Form submitted with CSRF token: %s\n", formToken)

		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			fmt.Printf("Invalid CSRF token. Form token: %s, Cookie token: %s\n", formToken, cookieToken) // Debugging line
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		// Extract form data
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Hash the password using bcrypt
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		// Insert user into the database
		_, err = database.DB.Exec(`INSERT INTO users (email, username, password) VALUES (?, ?, ?)`, email, username, hashedPassword)
		if err != nil {
			fmt.Fprintf(w, "Error registering user: %v", err)
			return
		}

		// Redirect to login page after successful registration
		http.Redirect(w, r, "/login", http.StatusSeeOther)

	} else {
		// Generate and set a CSRF token in a cookie
		csrfToken, _ := GenerateCSRFToken()
		fmt.Printf("Generated CSRF token for form: %s\n", csrfToken) // Debugging line
		SetCSRFCookie(w, csrfToken)

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
			fmt.Println("Error parsing form:", err) // Debugging line
			http.Error(w, "Error parsing form", http.StatusInternalServerError)
			return
		}

		// Debug: Print all form values
		for key, values := range r.Form {
			fmt.Printf("Form field: %s, values: %v\n", key, values)
		}

		// Retrieve CSRF token from form and cookie
		formToken := r.FormValue("csrf_token")
		fmt.Printf("Form submitted with CSRF token: %s\n", formToken) // Debugging line

		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			fmt.Printf("Invalid CSRF token. Form token: %s, Cookie token: %s\n", formToken, cookieToken) // Debugging line
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		// Extract form data
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Query for user by email
		row := database.DB.QueryRow(`SELECT id, password FROM users WHERE email = ?`, email)

		var id int
		var hashedPassword string
		err = row.Scan(&id, &hashedPassword)
		if err == sql.ErrNoRows {
			fmt.Fprintf(w, "Invalid email or password")
			return
		}

		// Compare the hashed password
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			fmt.Fprintf(w, "Invalid email or password")
			return
		}

		// Set session or login cookie here (omitted for brevity)
		// Example: http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "some_value"})
		err = SetSessionCookie(w, id)
		if err != nil {
			fmt.Fprintf(w, "Error setting session: %v", err)
			return
		}

		// Redirect to home page after successful login
		http.Redirect(w, r, "/home", http.StatusSeeOther)

	} else {
		// Generate and set a CSRF token in a cookie
		csrfToken, _ := GenerateCSRFToken()
		fmt.Printf("Generated CSRF token for form: %s\n", csrfToken)
		SetCSRFCookie(w, csrfToken)

		// Render the login template with the CSRF token
		tmpl := template.Must(template.ParseFiles("views/login.html"))
		tmpl.Execute(w, map[string]interface{}{
			"CsrfToken": csrfToken,
		})
	}
}
