package controllers

import (
	"database/sql"
	"fmt"
	"literary-lions/database"
	"log"
	"net/http"
)

func GetUserIDFromSession(r *http.Request) (int, error) {
	sessionCookie, err := r.Cookie("session_id") // 	Get the session ID from the cookie
	if err != nil {
		log.Printf("GetUserIDFromSession: No session ID found in cookies: %v", err)
		return 0, fmt.Errorf("no session ID found")
	}

	var userID int
	err = database.DB.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", sessionCookie.Value).Scan(&userID) // 	Get the user ID from the database
	if err != nil {
		log.Printf("GetUserIDFromSession: Error querying database: %v", err)
		return 0, fmt.Errorf("invalid session")
	}

	log.Printf("GetUserIDFromSession: Retrieved user ID %d for session ID %s", userID, sessionCookie.Value)
	return userID, nil
}

func GetUserIDFromSessionID(sessionID string) (int, error) {
	var userID int

	err := database.DB.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", sessionID).Scan(&userID) // 	Get the user ID from the database
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("GetUserIDFromSessionID: No user found for session ID: %s", sessionID)
			return 0, nil
		}
		log.Printf("GetUserIDFromSessionID: Error querying database: %v", err)
		return 0, err
	}

	log.Printf("GetUserIDFromSessionID: Retrieved user ID %d for session ID %s", userID, sessionID)
	return userID, nil
}

func GetUsernameFromSession(r *http.Request) (string, error) {
	userID, err := GetSession(r) // 	Get the user ID from the session
	if err != nil {
		return "", fmt.Errorf("unable to get session: %v", err)
	}

	username := database.GetUserNameByID(userID) // 	Get the username from the database
	if username == "Unknown" {
		return "", fmt.Errorf("error: user not found for ID %d", userID)
	}

	return username, nil
}

func RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // 	Check if the user is logged in
		cookie, err := r.Cookie("session_id") // 	Get the session ID from the cookie
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}

		SessionMutex.Lock()
		_, sessionExists := SessionStore[cookie.Value]
		SessionMutex.Unlock()

		if !sessionExists {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r) // 	If the user is logged in, serve the request
	})
}
