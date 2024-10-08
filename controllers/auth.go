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
	"literary-lions/utils"

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
			log.Println("RegisterUser: Unable to parse form data") // Additional logging
			renderModalWithError(w, r, "Unable to parse form data", true)
			return
		}

		// CSRF token validation
		formToken := r.FormValue("csrf_token")
		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			log.Println("RegisterUser: CSRF token validation failed") // Detailed error logging
			renderModalWithError(w, r, "Invalid CSRF token", true)
			return
		}

		// Extract form data
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Validate email and password
		if !isValidEmail(email) {
			log.Println("RegisterUser: Invalid email format")
			renderModalWithError(w, r, "Invalid email format", true)
			return
		}
		if len(password) < 8 {
			log.Println("RegisterUser: Password too short")
			renderModalWithError(w, r, "Password must be at least 8 characters long", true)
			return
		}

		// Hash password
		hashedPassword, err := HashPassword(password)
		if err != nil {
			log.Printf("RegisterUser: Error hashing password: %v", err)
			renderModalWithError(w, r, "Error hashing password", true)
			return
		}

		// Insert user into the database
		log.Printf("RegisterUser: Inserting user - Email: %s, Username: %s", email, username)
		_, err = database.DB.Exec(`INSERT INTO users (email, username, password) VALUES (?, ?, ?)`, email, username, hashedPassword)
		if err != nil {
			log.Printf("RegisterUser: Database insertion error: %v", err)
			if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrConstraint {
				renderModalWithError(w, r, "The email or username already exists. Please try again.", true)
				return
			}
			renderModalWithError(w, r, "Error registering user", true)
			return
		}

		// Retrieve the newly inserted user ID
		var userID sql.NullInt64
		err = database.DB.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&userID)
		if err != nil {
			log.Printf("RegisterUser: Error retrieving user ID after registration: %v", err)
			renderModalWithError(w, r, "Error retrieving user after registration.", true)
			return
		}

		// Create a new session for the user
		sessionID, err := CreateSession(int(userID.Int64)) // Convert to int
		if err != nil {
			log.Printf("RegisterUser: Error creating session: %v", err)
			renderModalWithError(w, r, "Error creating session.", true)
			return
		}

		// Set the session cookie
		log.Printf("RegisterUser: Setting session cookie for user ID %d", userID.Int64)
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
		})

		// Redirect to the home page after successful registration
		log.Printf("RegisterUser: Successfully registered and logged in user ID %d", userID.Int64)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// isValidEmail checks if the provided email has a valid format
func isValidEmail(email string) bool {
	// Simple email regex pattern
	const emailRegexPattern = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegexPattern)
	return re.MatchString(email)
}

// Function to render the modal with error or success message
func renderModalWithError(w http.ResponseWriter, r *http.Request, message string, isRegistering bool) {
	csrfToken, _ := GenerateAndSetCSRFToken(w, r)

	tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
	data := map[string]interface{}{
		"ShowModal":     true,    // Keeps the modal open
		"ErrorMessage":  message, // Error message to display
		"CsrfToken":     csrfToken,
		"IsRegistering": isRegistering, // Controls whether it's the login or register tab
	}
	tmpl.Execute(w, data)
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
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		log.Println("LoginUser: Invalid method")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			log.Println("LoginUser: Error parsing form data")
			utils.HandleError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		// Validate CSRF token
		formToken := r.FormValue("csrf_token")
		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			log.Println("LoginUser: Invalid CSRF token")
			utils.RenderErrorPage(w, http.StatusForbidden, "Invalid CSRF token. Please try again.")
			return
		}

		// Extract form data
		email := r.FormValue("email")
		password := r.FormValue("password")
		log.Printf("LoginUser: Attempting login for email: %s", email)

		// Retrieve user information from the database
		row := database.DB.QueryRow(`SELECT id, password FROM users WHERE email = ?`, email)
		var id int
		var storedHashedPassword string
		err = row.Scan(&id, &storedHashedPassword)
		if err == sql.ErrNoRows {
			log.Println("LoginUser: No such user")
			http.Redirect(w, r, "/?login_error=Invalid email or password.", http.StatusSeeOther)
			return
		} else if err != nil {
			log.Printf("LoginUser: Error retrieving user: %v", err)
			utils.HandleError(w, http.StatusInternalServerError, "Error retrieving user")
			return
		}

		// Check the password
		log.Println("LoginUser: Checking password")
		if CheckPasswordHash(password, storedHashedPassword) != nil {
			log.Println("LoginUser: Incorrect password")
			http.Redirect(w, r, "/?login_error=Invalid email or password.", http.StatusSeeOther)
			return
		}

		log.Printf("LoginUser: Login successful for user ID %d", id)

		// Create session using the new function and set the session cookie
		sessionID, err := CreateSession(id)
		if err != nil {
			log.Printf("LoginUser: Error creating session: %v", err)
			utils.HandleError(w, http.StatusInternalServerError, "Error creating session")
			return
		}

		// Set session cookie on successful login
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
