package controllers

import (
	"html/template"
	"literary-lions/database"
	"log"
	"net/http"
)

// ShowPosts displays all the posts
func ShowPosts(w http.ResponseWriter, r *http.Request) {
	rows, err := database.DB.Query("SELECT id, title, body, user_id FROM posts")
	if err != nil {
		log.Printf("Error fetching posts: %v", err)
		http.Error(w, "Error fetching posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	posts := []map[string]interface{}{}

	for rows.Next() {
		var id, userID int
		var title, body string
		err := rows.Scan(&id, &title, &body, &userID)
		if err != nil {
			log.Printf("Error scanning post: %v", err)
			continue
		}
		post := map[string]interface{}{
			"id":     id,
			"title":  title,
			"body":   body,
			"userID": userID,
		}
		posts = append(posts, post)
	}

	tmpl := template.Must(template.ParseFiles("views/posts.html"))
	tmpl.Execute(w, posts)
}

func GetUserIDFromSession(r *http.Request) (int, error) {
	// For now, return a dummy user ID (replace with actual logic in the future)
	return 1, nil
}

// CreatePost handles the post creation form
func CreatePost(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl := template.Must(template.ParseFiles("views/create_post.html"))
		tmpl.Execute(w, nil)
	} else if r.Method == http.MethodPost {
		userID, err := GetUserIDFromSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther) // Redirect if no session
			return
		}
		r.ParseForm()
		title := r.FormValue("title")
		body := r.FormValue("body")

		// Insert into database
		_, err = database.DB.Exec("INSERT INTO posts (title, body, user_id) VALUES (?, ?, ?)", title, body, userID)
		if err != nil {
			http.Error(w, "Error creating post", http.StatusInternalServerError)
			return
		}

		// Redirect to posts list
		http.Redirect(w, r, "/posts", http.StatusSeeOther)
	}
}

// CreateComment handles posting a comment on a post
func CreateComment(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		postID := r.FormValue("post_id")
		commentBody := r.FormValue("body")

		// Insert comment into the database
		_, err := database.DB.Exec("INSERT INTO comments (body, post_id, user_id) VALUES (?, ?, ?)", commentBody, postID, 1) // Assuming user_id = 1 for now
		if err != nil {
			http.Error(w, "Error posting comment", http.StatusInternalServerError)
			log.Printf("Error posting comment: %v", err)
			return
		}

		http.Redirect(w, r, "/posts", http.StatusSeeOther)
	}
}

// MyPostsHandler displays posts created by the logged-in user
func MyPostsHandler(w http.ResponseWriter, r *http.Request) {
	// Assuming user_id can be derived from session (for demo purposes, user_id is hardcoded as 1)
	userID := 1 // For now, using a hardcoded user ID

	// Fetch posts created by the user
	rows, err := database.DB.Query("SELECT id, title, body FROM posts WHERE user_id = ?", userID)
	if err != nil {
		log.Printf("Error fetching user's posts: %v", err)
		http.Error(w, "Error fetching posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	posts := []map[string]interface{}{}

	for rows.Next() {
		var id int
		var title, body string
		err := rows.Scan(&id, &title, &body)
		if err != nil {
			log.Printf("Error scanning post: %v", err)
			continue
		}
		post := map[string]interface{}{
			"id":    id,
			"title": title,
			"body":  body,
		}
		posts = append(posts, post)
	}

	tmpl := template.Must(template.ParseFiles("views/myposts.html"))
	tmpl.Execute(w, posts)
}

// LikePostHandler handles liking a post
func LikePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Get user ID from session
		userID, err := GetUserIDFromSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Parse form data
		r.ParseForm()
		postID := r.FormValue("post_id")

		// Check if user has already liked this post
		var count int
		err = database.DB.QueryRow("SELECT COUNT(*) FROM likes_dislikes WHERE post_id = ? AND user_id = ? AND like_type = 1", postID, userID).Scan(&count)
		if err != nil {
			http.Error(w, "Error checking like status", http.StatusInternalServerError)
			return
		}

		if count == 0 {
			// Insert a new like
			_, err = database.DB.Exec("INSERT INTO likes_dislikes (user_id, post_id, like_type) VALUES (?, ?, 1)", userID, postID)
			if err != nil {
				http.Error(w, "Error liking post", http.StatusInternalServerError)
				return
			}
		}

		http.Redirect(w, r, "/posts", http.StatusSeeOther)
	}
}

// DislikePostHandler handles disliking a post
func DislikePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Parse form data
		r.ParseForm()
		postID := r.FormValue("post_id")
		userID := 1 // For now, hardcoding user_id. Replace with session-based user_id when sessions are implemented.

		// Check if user has already disliked this post
		var count int
		err := database.DB.QueryRow("SELECT COUNT(*) FROM likes_dislikes WHERE post_id = ? AND user_id = ? AND like_type = -1", postID, userID).Scan(&count)
		if err != nil {
			http.Error(w, "Error checking dislike status", http.StatusInternalServerError)
			return
		}

		if count == 0 {
			// Insert a new dislike
			_, err = database.DB.Exec("INSERT INTO likes_dislikes (user_id, post_id, like_type) VALUES (?, ?, -1)", userID, postID)
			if err != nil {
				http.Error(w, "Error disliking post", http.StatusInternalServerError)
				return
			}
		}

		http.Redirect(w, r, "/posts", http.StatusSeeOther)
	}
}
