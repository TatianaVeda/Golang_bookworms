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
			// Corrected the call to match the expected signature
			renderRegistrationError(w, r, "Unable to parse form data", "", "", "", "")
			return
		}

		// CSRF token validation
		formToken := r.FormValue("csrf_token")
		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			renderRegistrationError(w, r, "Invalid CSRF token", "", "", "", "")
			return
		}

		// Extract form data
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Error variables
		var emailError, passwordError string

		// Validate each field and capture errors
		if !isValidEmail(email) {
			emailError = "Invalid email format"
		}
		if len(password) < 8 {
			passwordError = "Password must be at least 8 characters long"
		}

		// If errors exist, show them in the modal
		if emailError != "" || passwordError != "" {
			// Updated the call to match the function signature
			renderRegistrationError(w, r, "", username, email, emailError, passwordError)
			return
		}

		// Hash the password
		hashedPassword, err := HashPassword(password)
		if err != nil {
			renderRegistrationError(w, r, "Error hashing password", "", "", "", "")
			return
		}

		// Attempt to insert the user into the database
		_, err = database.DB.Exec(`INSERT INTO users (email, username, password) VALUES (?, ?, ?)`, email, username, hashedPassword)
		if err != nil {
			if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.Code == sqlite3.ErrConstraint {
				// Updated the call to match the function signature
				renderRegistrationError(w, r, "The email or username already exists. Please try again.", username, email, "Email or username already in use", "")
				return
			}
			renderRegistrationError(w, r, "Error registering user", "", "", "", "")
			return
		}

		// On success, show the green success message
		renderModalWithError(w, r, "Registration successful! Please log in.", true, true, "", "", "", "")
	}
}

func renderRegistrationError(w http.ResponseWriter, r *http.Request, message string, username string, email string, emailError string, passwordError string) {
	csrfToken, _ := GenerateAndSetCSRFToken(w, r)

	// Template data structure
	data := map[string]interface{}{
		"ShowModal":     true,
		"ErrorMessage":  message,       // Error message for the modal
		"CsrfToken":     csrfToken,     // Include CSRF token
		"IsRegistering": true,          // Indicates that the register tab should be active
		"Username":      username,      // Pre-fill username field
		"Email":         email,         // Pre-fill email field
		"EmailError":    emailError,    // Email-specific error message
		"PasswordError": passwordError, // Password-specific error message
	}

	// Render the combined template with the registration form
	tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("renderRegistrationError: Template execution failed: %v", err)
	}
}

func renderSuccessMessage(w http.ResponseWriter, r *http.Request, successMessage string) {
	csrfToken, _ := GenerateAndSetCSRFToken(w, r)
	data := map[string]interface{}{
		"ShowModal":      true,
		"IsRegistering":  true,
		"CsrfToken":      csrfToken,
		"SuccessMessage": successMessage, // Green success message for successful registration
	}
	tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("renderSuccessMessage: Template execution failed: %v", err)
	}
}

func renderModalWithError(w http.ResponseWriter, r *http.Request, message string, isSuccess bool, isRegistering bool, username string, email string, emailError string, passwordError string) {
	csrfToken, _ := GenerateAndSetCSRFToken(w, r)

	// Choose the message color based on success flag
	messageColor := "red"
	if isSuccess {
		messageColor = "green"
	}

	// Create the template data
	data := map[string]interface{}{
		"ShowModal":     true,
		"CsrfToken":     csrfToken,
		"Message":       message,
		"MessageColor":  messageColor,
		"IsRegistering": isRegistering,
		"Username":      username,
		"Email":         email,
		"EmailError":    emailError,
		"PasswordError": passwordError,
	}

	// Render the template
	tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("renderModalWithError: Template execution failed: %v", err)
	}
}

// isValidEmail checks if the provided email has a valid format
func isValidEmail(email string) bool {
	// Simple email regex pattern
	const emailRegexPattern = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegexPattern)
	return re.MatchString(email)
}

func GenerateSessionID() (string, error) {
	sessionID := uuid.New().String() // Generate a new UUID
	return sessionID, nil
}

func SetSessionCookie(w http.ResponseWriter, userID int) error {
	sessionID, err := GenerateSessionID() // Generates a UUID
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
		HttpOnly: true,
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
			tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
			data := map[string]interface{}{
				"LoginError":    "Invalid email or password.",
				"CsrfToken":     formToken,
				"ShowModal":     true,
				"IsRegistering": false,
			}
			tmpl.Execute(w, data)
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

		log.Printf("LoginUser: Login successful for user ID %d", id)

		// Set session cookie on successful login
		err = SetSessionCookie(w, id)
		if err != nil {
			log.Printf("LoginUser: Error setting session cookie: %v", err)
			utils.HandleError(w, http.StatusInternalServerError, "Error setting session cookie")
			return
		}
		fmt.Printf("This is sessionStore: %v", w)

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
			log.Println("LoginUser: Error generating CSRF token")
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
