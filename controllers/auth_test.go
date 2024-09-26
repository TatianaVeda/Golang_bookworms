package controllers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRegisterUser_InvalidEmail(t *testing.T) {
	// Prepare a POST request with an invalid email
	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("email", "invalid-email")
	form.Add("password", "strongpassword")

	req := httptest.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Create a response recorder to capture the HTTP response
	rr := httptest.NewRecorder()

	// Call the RegisterUser function
	RegisterUser(rr, req)

	// Check the response code
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, but got %d", http.StatusBadRequest, rr.Code)
	}

	// Check the response body for a specific validation message
	expectedMessage := "Invalid email format"
	if !strings.Contains(rr.Body.String(), expectedMessage) {
		t.Errorf("Expected error message '%s', but got '%s'", expectedMessage, rr.Body.String())
	}
}

func TestRegisterUser_ShortPassword(t *testing.T) {
	// Prepare a POST request with a short password
	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("email", "test@example.com")
	form.Add("password", "123") // Short password

	req := httptest.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Create a response recorder to capture the HTTP response
	rr := httptest.NewRecorder()

	// Call the RegisterUser function
	RegisterUser(rr, req)

	// Check the response code
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, but got %d", http.StatusBadRequest, rr.Code)
	}

	// Check the response body for a specific validation message
	expectedMessage := "Password must be at least 8 characters long"
	if !strings.Contains(rr.Body.String(), expectedMessage) {
		t.Errorf("Expected error message '%s', but got '%s'", expectedMessage, rr.Body.String())
	}
}
