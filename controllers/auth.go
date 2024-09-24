package controllers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sync"
	"time"

	"literary-lions/database"
	"literary-lions/utils"

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
			utils.HandleError(w, http.StatusBadRequest, "Unable to parse form data")
			return
		}

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

		// Hash the password using the modular HashPassword function
		hashedPassword, err := HashPassword(password)
		if err != nil {
			utils.HandleError(w, http.StatusInternalServerError, "Error hashing password")
			return
		}

		// Insert user into the database
		_, err = database.DB.Exec(`INSERT INTO users (email, username, password) VALUES (?, ?, ?)`, email, username, hashedPassword)
		if err != nil {
			if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrConstraint {
				tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
				data := map[string]interface{}{
					"RegistrationError": "The email or username already exists. Please try again.",
					"CsrfToken":         formToken,
					"ShowModal":         true, // Keep the modal open
					"IsRegistering":     true, // Ensure the Register tab is active
				}
				tmpl.Execute(w, data)
				return
			}

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
		csrfToken, err := GenerateAndSetCSRFToken(w, r)
		if err != nil {
			utils.HandleError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}

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

func CheckPasswordHash(password, hashedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return errors.New("incorrect password")
	}
	return nil
}

func LoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			utils.HandleError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		// Validate CSRF token
		formToken := r.FormValue("csrf_token")
		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			utils.RenderErrorPage(w, http.StatusForbidden, "Invalid CSRF token. Please try again.")
			return
		}

		// Extract form data and authenticate the user
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Retrieve user information from the database
		row := database.DB.QueryRow(`SELECT id, password FROM users WHERE email = ?`, email)
		var id int
		var storedHashedPassword string
		err = row.Scan(&id, &storedHashedPassword)

		// Handle incorrect login attempt
		if err == sql.ErrNoRows || CheckPasswordHash(password, storedHashedPassword) != nil {
			tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
			data := map[string]interface{}{
				"LoginError":    "Invalid email or password.",
				"CsrfToken":     formToken,
				"ShowModal":     true,
				"IsRegistering": false,
			}
			tmpl.Execute(w, data)
			return
		}

		// Set session cookie on successful login
		err = SetSessionCookie(w, id)
		if err != nil {
			utils.HandleError(w, http.StatusInternalServerError, "Error setting session cookie")
			return
		}

		// Render home page on successful login
		tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
		data := map[string]interface{}{
			"LoginSuccess": true,
			"IsLoggedIn":   true,
			"CsrfToken":    formToken,
			"ShowModal":    false,
		}
		tmpl.Execute(w, data)
	} else if r.Method == http.MethodGet {
		csrfToken, err := GenerateAndSetCSRFToken(w, r)
		if err != nil {
			utils.HandleError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		tmpl := template.Must(template.ParseFiles("views/login.html"))
		tmpl.Execute(w, map[string]interface{}{
			"CsrfToken": csrfToken,
		})
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		utils.HandleError(w, http.StatusBadRequest, "Session not found or already expired.")
		return
	}

	SessionMutex.Lock()
	delete(SessionStore, cookie.Value)
	SessionMutex.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		MaxAge: -1,
		Path:   "/",
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
