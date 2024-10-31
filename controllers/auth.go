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
		log.Println("RegisterUser: Handling POST request")

		if err := r.ParseForm(); err != nil {
			renderModalWithMessage(w, r, "Unable to parse form data", "register")
			return
		}

		formToken := r.FormValue("csrf_token")
		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			renderModalWithMessage(w, r, "Invalid CSRF token.", "register")
			return
		}

		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		if !isValidEmail(email) {
			renderModalWithMessage(w, r, "Invalid email format.", "register")
			return
		}

		if len(password) < 8 {
			renderModalWithMessage(w, r, "Password must be at least 8 characters long.", "register")
			return
		}

		hashedPassword, err := HashPassword(password)
		if err != nil {
			renderModalWithMessage(w, r, "Error hashing password.", "register")
			return
		}

		// Attempt to insert user into the database
		_, err = database.DB.Exec(`INSERT INTO users (email, username, password) VALUES (?, ?, ?)`, email, username, hashedPassword)
		if err != nil {
			if sqliteErr, ok := err.(sqlite3.Error); ok {
				if sqliteErr.Code == sqlite3.ErrConstraint {
					log.Printf("RegisterUser: Duplicate entry error - %v", sqliteErr)
					renderModalWithMessage(w, r, "Email or username already exists.", "register")
				} else {
					log.Printf("RegisterUser: SQLite error - %v", sqliteErr)
					renderModalWithMessage(w, r, "Database error during registration.", "register")
				}
			} else {
				log.Printf("RegisterUser: General database error - %v", err)
				renderModalWithMessage(w, r, "Error registering user.", "register")
			}
			return
		}

		// Redirect to the homepage or success page after successful registration
		log.Println("RegisterUser: Registration successful, redirecting to homepage")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		// Redirect if the request is not a POST (likely a direct URL access)
		log.Println("RegisterUser: Received GET request; redirecting to homepage")
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func isValidEmail(email string) bool {
	const emailRegexPattern = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(emailRegexPattern)
	return re.MatchString(email)
}

func renderModalWithMessage(w http.ResponseWriter, r *http.Request, message string, modalType string) {
	csrfToken, err := GenerateAndSetCSRFToken(w, r)
	if err != nil {
		log.Printf("CSRF token generation error: %v", err)
		http.Error(w, "Error generating CSRF token", http.StatusInternalServerError)
		return
	}

	// Parse the main template to render modal within the home page
	tmpl, err := template.ParseFiles(
		"views/home.html",
		"views/auth.html",
		"views/categories.html",
		"views/create_post.html",
	)
	if err != nil {
		log.Printf("Template parsing error: %v", err)
		http.Error(w, "Error loading templates", http.StatusInternalServerError)
		return
	}

	// Pass the data to the template with specific modal type and error messages
	data := map[string]interface{}{
		"ShowModal":         true,
		"CsrfToken":         csrfToken,
		"IsRegistering":     modalType == "register",
		"LoginError":        "",
		"RegistrationError": "",
		"SuccessMessage":    "",
	}

	switch modalType {
	case "register":
		data["RegistrationError"] = message
	case "login":
		data["LoginError"] = message
	case "success":
		data["SuccessMessage"] = message
	}

	log.Printf("Rendering modal (type: %s) with message: %s", modalType, message)

	// Execute the main template with data
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

func RenderSimpleLoginPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("views/auth.html")
	if err != nil {
		http.Error(w, "Error loading login page", http.StatusInternalServerError)
		return
	}

	csrfToken, _ := GenerateAndSetCSRFToken(w, r)
	data := map[string]interface{}{
		"CsrfToken": csrfToken,
		"ShowModal": false,
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Error rendering login page", http.StatusInternalServerError)
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
	expirationTime := time.Now().Add(24 * time.Hour)

	_, err := database.DB.Exec("INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)", sessionID, userID, expirationTime)
	if err != nil {
		log.Printf("CreateSession: Error inserting session into database: %v", err)
		return "", err
	}

	SessionMutex.Lock()
	SessionStore[sessionID] = userID
	SessionMutex.Unlock()

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
			renderModalWithMessage(w, r, "Unable to parse form", "login")
			return
		}

		formToken := r.FormValue("csrf_token")
		cookieToken, err := GetCSRFCookie(r)
		if err != nil || formToken != cookieToken {
			renderModalWithMessage(w, r, "Invalid CSRF token", "login")
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")
		userID, err := Authenticate(email, password)
		if err != nil {
			renderModalWithMessage(w, r, "Invalid email or password.", "login")
			return
		}

		sessionID, err := CreateSession(userID)
		if err != nil {
			renderModalWithMessage(w, r, "Error creating session", "login")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "session_id",
			Value:   sessionID,
			Expires: time.Now().Add(24 * time.Hour),
			Path:    "/",
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
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

	err := database.DB.QueryRow("SELECT id, password FROM users WHERE email = ?", email).Scan(&userID, &storedPassword)
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
