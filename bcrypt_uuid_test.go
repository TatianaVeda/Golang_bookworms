package main

import (
	"database/sql"
	"literary-lions/controllers"
	"literary-lions/database"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func TestPasswordHashing(t *testing.T) {
	password := "testpassword"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Error hashing password: %v", err)
	}

	// Compare with correct password
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		t.Error("Password verification failed with correct password")
	}

	// Compare with incorrect password
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte("wrongpassword"))
	if err == nil {
		t.Error("Password verification succeeded with incorrect password")
	}
}

func setupTestDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", ":memory:") // In-memory SQLite database
	if err != nil {
		return nil, err
	}

	// Create the users table
	createTableQuery := `
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        password TEXT NOT NULL
    );`
	_, err = db.Exec(createTableQuery)
	if err != nil {
		return nil, err
	}

	// Insert a test user into the database
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	insertUserQuery := `INSERT INTO users (email, password) VALUES ('testuser@example.com', ?);`
	_, err = db.Exec(insertUserQuery, hashedPassword)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func TestSessionCreation(t *testing.T) {
	// Step 1: Set up the test database
	var err error
	database.DB, err = setupTestDB() // Assign the test DB to the global database.DB
	if err != nil {
		t.Fatalf("Failed to set up test DB: %v", err)
	}

	// Step 2: Create a GET request to generate the CSRF token
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Generate CSRF token by simulating the request
	controllers.GenerateAndSetCSRFToken(w, req)
	result := w.Result()
	csrfCookie := result.Cookies()[0] // Assuming the CSRF token is the first cookie set

	// Step 3: Create a valid POST request with form data and the CSRF token
	form := url.Values{}
	form.Add("email", "testuser@example.com")
	form.Add("password", "testpassword")
	form.Add("csrf_token", csrfCookie.Value) // Include the CSRF token in the form

	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Set the CSRF cookie in the request
	req.AddCookie(csrfCookie)

	w = httptest.NewRecorder()

	// Step 4: Simulate the login request
	controllers.LoginUser(w, req)

	// Step 5: Check that a session ID cookie was set
	result = w.Result()
	cookies := result.Cookies()
	if len(cookies) == 0 {
		t.Fatalf("No cookies were set by the LoginUser function")
	}

	// Assuming the session cookie is the first one set
	sessionCookie := cookies[0]
	if sessionCookie.Name != "session_id" {
		t.Fatalf("Expected session_id cookie, got %v", sessionCookie.Name)
	}

	// Validate that the session ID is a valid UUID
	_, err = uuid.Parse(sessionCookie.Value)
	if err != nil {
		t.Fatalf("Invalid UUID for session ID: %v", err)
	}

	t.Logf("Session ID: %v", sessionCookie.Value)
}

func TestSessionRetrieval(t *testing.T) {
	// Mock HTTP request with a session ID
	sessionID := uuid.New().String()
	req := httptest.NewRequest("GET", "/myposts", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: sessionID,
	})

	// Simulate storing the session in SessionStore
	controllers.SessionMutex.Lock()
	controllers.SessionStore[sessionID] = 123 // Mock user ID
	controllers.SessionMutex.Unlock()

	// Simulate checking session
	userID, err := controllers.GetUserIDFromSession(req)
	if err != nil {
		t.Fatalf("Error retrieving session: %v", err)
	}

	if userID != 123 {
		t.Fatalf("Expected user ID 123, got %d", userID)
	}

	t.Logf("Session ID: %v, User ID: %d", sessionID, userID)
}

func TestInvalidSession(t *testing.T) {
	// Mock request without a session ID
	req := httptest.NewRequest("GET", "/myposts", nil)

	// Try to retrieve session, should result in error
	_, err := controllers.GetUserIDFromSession(req)
	if err == nil {
		t.Fatalf("Expected error for missing session ID, got nil")
	}

	t.Log("Successfully handled missing session ID")
}
