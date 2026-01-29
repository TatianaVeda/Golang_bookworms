package controllers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	wd, _ := os.Getwd()
	if err := os.Chdir(filepath.Join(wd, "..")); err != nil {
		os.Exit(1)
	}
	defer os.Chdir(wd)
	os.Exit(m.Run())
}

func csrfTokenAndCookie(t *testing.T) (token string, cookie *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	token, err := GenerateAndSetCSRFToken(rec, req)
	if err != nil {
		t.Fatalf("csrf setup: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			return token, c
		}
	}
	t.Fatal("csrf_token cookie not set")
	return "", nil
}

func TestRegisterUser_InvalidEmail(t *testing.T) {
	token, csrfCookie := csrfTokenAndCookie(t)
	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("email", "invalid-email")
	form.Add("password", "strongpassword")
	form.Add("csrf_token", token)

	req := httptest.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)

	rr := httptest.NewRecorder()
	RegisterUser(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, rr.Code)
	}
	const expectedMessage = "Invalid email format"
	if !strings.Contains(rr.Body.String(), expectedMessage) {
		t.Errorf("Expected body to contain %q, got %q", expectedMessage, rr.Body.String())
	}
}

func TestRegisterUser_ShortPassword(t *testing.T) {
	token, csrfCookie := csrfTokenAndCookie(t)
	form := url.Values{}
	form.Add("username", "testuser")
	form.Add("email", "test@example.com")
	form.Add("password", "123")
	form.Add("csrf_token", token)

	req := httptest.NewRequest("POST", "/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)

	rr := httptest.NewRecorder()
	RegisterUser(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, rr.Code)
	}
	const expectedMessage = "Password must be at least 8 characters long"
	if !strings.Contains(rr.Body.String(), expectedMessage) {
		t.Errorf("Expected body to contain %q, got %q", expectedMessage, rr.Body.String())
	}
}
