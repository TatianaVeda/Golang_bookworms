package utils

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleErrorWithoutLogging(t *testing.T) {
	// Create a response recorder to capture the HTTP response
	rr := httptest.NewRecorder()

	// Call HandleError without an internal error
	HandleError(rr, http.StatusBadRequest, "Test error message")

	// Check the response code
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status code %d, but got %d", http.StatusBadRequest, rr.Code)
	}

	// Check the response body
	expectedMessage := "Test error message\n"
	if rr.Body.String() != expectedMessage {
		t.Errorf("Expected response body '%s', but got '%s'", expectedMessage, rr.Body.String())
	}
}

func TestHandleErrorWithLogging(t *testing.T) {
	// Create a response recorder to capture the HTTP response
	rr := httptest.NewRecorder()

	// Simulate an internal error
	internalError := errors.New("Internal server error")

	// Call HandleError with an internal error
	HandleError(rr, http.StatusInternalServerError, "An error occurred", internalError)

	// Check the response code
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status code %d, but got %d", http.StatusInternalServerError, rr.Code)
	}

	// Check the response body
	expectedMessage := "An error occurred\n"
	if rr.Body.String() != expectedMessage {
		t.Errorf("Expected response body '%s', but got '%s'", expectedMessage, rr.Body.String())
	}

	// Here you can also check that the error was logged (if using a mock logger or log capture tool)
}
