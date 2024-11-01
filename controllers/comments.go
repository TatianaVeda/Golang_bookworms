package controllers

import (
	"database/sql"
	"fmt"
	"literary-lions/database"
	"log"
	"net/http"
	"strconv"
)

func CreateComment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	// Insert the comment into the database
	if database.DB == nil {
		log.Println("Database connection is not initialized")
		http.Error(w, "Database connection is not initialized", http.StatusInternalServerError)
		return
	}

	userID, err := GetUserIDFromSession(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Parse form values
	postID := r.FormValue("post_id")
	commentBody := r.FormValue("body")
	log.Println("Creating comment for post ID:", postID, "Comment Body:", commentBody)

	// Validate form inputs
	if postID == "" || commentBody == "" {
		http.Error(w, "Post ID and comment body cannot be empty", http.StatusBadRequest)
		return
	}

	// Convert post ID to an integer for database use
	postIDInt, err := strconv.Atoi(postID)
	if err != nil {
		http.Error(w, "Invalid PostID, error converting postID to int", http.StatusBadRequest)
		return
	}
	// Insert the comment into the database

	result, err := database.DB.Exec("INSERT INTO comments (user_id, post_id, body) VALUES (?, ?, ?)", userID, postIDInt, commentBody)
	if err != nil {
		log.Printf("Error posting comment: %v, UserID: %d, PostID: %d, Body: %s", err, userID, postIDInt, commentBody)
		http.Error(w, "Error posting comment.", http.StatusInternalServerError)
		return
	}

	// Get the last inserted comment ID (for potential debugging purposes)
	commentID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Error retrieving last insert ID for comment: %v", err)
	} else {
		log.Printf("Successfully inserted comment with ID: %d for post ID: %d", commentID, postIDInt)
	}

	// Redirect back to the post after adding the comment
	http.Redirect(w, r, fmt.Sprintf("/posts?post_id=%s", postID), http.StatusSeeOther)
}

func LikeComment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	// get user ID
	userID, err := GetUserIDFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// get comment ID
	commentID := r.FormValue("comment_id")
	likeType := r.FormValue("like_type") // 1 for like, -1 for dislike

	if likeType != "1" && likeType != "-1" {
		http.Error(w, "Invalid like type", http.StatusBadRequest)
		return
	}
	if commentID == "" || likeType == "" {
		http.Error(w, "Incorrect data, Comment ID and like type are required", http.StatusBadRequest)
		return
	}

	// Convert commentID to int
	commentIDInt, err := strconv.Atoi(commentID)
	if err != nil {
		http.Error(w, "Invalid comment ID", http.StatusBadRequest)
		return
	}

	// Check if the user has already liked this comment

	var existingLikeType int
	err = database.DB.QueryRow("SELECT like_type FROM comment_likes WHERE user_id = ? AND comment_id = ?", userID, commentIDInt).Scan(&existingLikeType)
	if err == sql.ErrNoRows {
		// If the user hasn't liked this comment yet, add a like/dislike
		_, err = database.DB.Exec("INSERT INTO comment_likes (user_id, comment_id, like_type) VALUES (?, ?, ?)", userID, commentIDInt, likeType)
	} else if existingLikeType == -1 && likeType == "1" {
		// If the user likes on dislike, update the entry
		_, err = database.DB.Exec("UPDATE comment_likes SET like_type = 1 WHERE user_id = ? AND comment_id = ?", userID, commentIDInt)
	} else if existingLikeType == 1 && likeType == "-1" {
		// If the user dislikes on like, update the entry
		_, err = database.DB.Exec("UPDATE comment_likes SET like_type = -1 WHERE user_id = ? AND comment_id = ?", userID, commentIDInt)
	} else if existingLikeType == 1 && likeType == "1" {
		// If the user likes on already existed like, delete record
		_, err = database.DB.Exec("DELETE FROM comment_likes WHERE user_id = ? AND comment_id = ?", userID, commentIDInt)
	} else if existingLikeType == -1 && likeType == "-1" {
		// If the user dislikes on already existed dislike, delete record
		_, err = database.DB.Exec("DELETE FROM comment_likes WHERE user_id = ? AND comment_id = ?", userID, commentIDInt)
	}

	if err != nil {
		log.Printf("Error liking comment: %v", err)
		http.Error(w, "Error processing like", http.StatusInternalServerError)
		return
	}
	var postID int
	err = database.DB.QueryRow("SELECT post_id FROM comments WHERE id = ?", commentIDInt).Scan(&postID)
	if err != nil {
		log.Printf("Error retrieving post ID for comment ID %d: %v", commentIDInt, err)
		http.Error(w, "Error retrieving post information.", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
}
