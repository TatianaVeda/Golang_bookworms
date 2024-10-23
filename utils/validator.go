package utils

import (
	"errors"
	"regexp"
)

func ValidateEmail(email string) error {
	// Basic regex for email validation
	re := regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`)
	if !re.MatchString(email) {
		return errors.New("invalid email format")
	}
	return nil
}

func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	return nil
}

func ValidateNonEmptyFields(fields map[string]string) error {
	for field, value := range fields {
		if value == "" {
			return errors.New(field + " cannot be empty")
		}
	}
	return nil
}
