package database

import (
	"fmt"
	"net/http"
)

func GetSession(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return "", fmt.Errorf("session cookie not found")
	}

	sessionID := cookie.Value
	SessionMutex.Lock()
	userID, exists := SessionStore[sessionID]
	SessionMutex.Unlock()

	if !exists {
		return "", fmt.Errorf("invalid session ID")
	}

	var username string
	err = DB.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
	if err != nil {
		return "", fmt.Errorf("error fetching username: %v", err)
	}

	return username, nil
}

func GetUserID(username string) (int, error) {
	var userID int
	err := DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	return userID, err
}
