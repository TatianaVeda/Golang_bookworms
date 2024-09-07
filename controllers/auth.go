package controllers

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"literary-lions/database"

	"golang.org/x/crypto/bcrypt"
)

// Generate a CSRF token for forms
func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// Store CSRF tokens in memory (for simplicity)
var csrfTokens = map[string]bool{}

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		csrfToken := generateCSRFToken()
		csrfTokens[csrfToken] = true

		tmpl := template.Must(template.ParseFiles("views/register.html"))
		tmpl.Execute(w, map[string]interface{}{
			"CsrfToken": csrfToken,
		})
	} else if r.Method == http.MethodPost {
		r.ParseForm()

		// CSRF token validation
		csrfToken := r.FormValue("csrf_token")
		if !csrfTokens[csrfToken] {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		delete(csrfTokens, csrfToken)

		if r.Method == "POST" {
			r.ParseForm()
			username := r.FormValue("username")
			email := r.FormValue("email")
			password := r.FormValue("password")

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
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {
			tmpl := template.Must(template.ParseFiles("views/register.html"))
			tmpl.Execute(w, nil)
		}
	}
}

func SetSessionCookie(w http.ResponseWriter, sessionID string) {
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    sessionID, // The session ID generated during login
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,  // This helps prevent access to cookies via JavaScript
		Secure:   false, // Set this to true if using HTTPS
	}
	http.SetCookie(w, cookie)
}

func LoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		csrfToken := generateCSRFToken()
		csrfTokens[csrfToken] = true

		tmpl := template.Must(template.ParseFiles("views/login.html"))
		tmpl.Execute(w, map[string]interface{}{
			"CsrfToken": csrfToken,
		})
	} else if r.Method == http.MethodPost {
		r.ParseForm()

		// CSRF token validation
		csrfToken := r.FormValue("csrf_token")
		if !csrfTokens[csrfToken] {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		delete(csrfTokens, csrfToken)

		if r.Method == "POST" {
			r.ParseForm()
			email := r.FormValue("email")
			password := r.FormValue("password")

			// Query for user
			row := database.DB.QueryRow(`SELECT id, password FROM users WHERE email = ?`, email)

			var id int
			var hashedPassword string
			err := row.Scan(&id, &hashedPassword)
			if err == sql.ErrNoRows {
				fmt.Fprintf(w, "Invalid email or password")
				return
			}

			// Compare hashed password
			err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
			if err != nil {
				http.Error(w, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			// Generate session ID
			sessionID := generateCSRFToken() // This is just for demonstration, you should generate a secure session token
			cookie := &http.Cookie{
				Name:     "session_id",
				Value:    sessionID,
				Expires:  time.Now().Add(24 * time.Hour),
				HttpOnly: true,
			}
			http.SetCookie(w, cookie)

			http.Redirect(w, r, "/home", http.StatusSeeOther)
		} else {
			tmpl := template.Must(template.ParseFiles("views/login.html"))
			tmpl.Execute(w, nil)
		}
	}
}
