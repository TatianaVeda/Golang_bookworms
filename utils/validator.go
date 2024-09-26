package utils

import (
	"errors"
	"regexp"
)

// ValidateEmail checks if the provided email is in a valid format
func ValidateEmail(email string) error {
	// Basic regex for email validation
	re := regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`)
	if !re.MatchString(email) {
		return errors.New("invalid email format")
	}
	return nil
}

// ValidatePassword checks the password strength (e.g., length)
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}
	// Optionally add more strength checks, like requiring numbers, symbols, etc.
	return nil
}

// ValidateNonEmptyFields ensures no required fields are empty
func ValidateNonEmptyFields(fields map[string]string) error {
	for field, value := range fields {
		if value == "" {
			return errors.New(field + " cannot be empty")
		}
	}
	return nil
}
