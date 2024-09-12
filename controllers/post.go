package controllers

import (
	"fmt"
	"html/template"
	"literary-lions/database"
	"log"
	"net/http"
)

// ShowPosts displays all the posts
func ShowPosts(w http.ResponseWriter, r *http.Request) {
	// Query to get posts along with their like and dislike counts
	query := `
        SELECT 
            posts.id, posts.title, posts.body, 
            COALESCE(SUM(CASE WHEN like_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
            COALESCE(SUM(CASE WHEN like_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count
        FROM posts
        LEFT JOIN likes_dislikes ON posts.id = likes_dislikes.post_id
        GROUP BY posts.id
    `
	rows, err := database.DB.Query(query)
	if err != nil {
		log.Printf("Error fetching posts: %v", err)
		http.Error(w, "Error fetching posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	posts := []map[string]interface{}{}

	for rows.Next() {
		var id, likeCount, dislikeCount int
		var title, body string
		err := rows.Scan(&id, &title, &body, &likeCount, &dislikeCount)
		if err != nil {
			log.Printf("Error scanning posts: %v", err)
			http.Error(w, "Error scanning posts", http.StatusInternalServerError)
			return
		}

		post := map[string]interface{}{
			"ID":           id,
			"Title":        title,
			"Body":         body,
			"LikeCount":    likeCount,
			"DislikeCount": dislikeCount,
		}

		posts = append(posts, post)
	}

	tmpl := template.Must(template.ParseFiles("views/posts.html"))
	tmpl.Execute(w, posts)
}

func GetUserIDFromSession(r *http.Request) (int, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		log.Println("No session cookie found")
		return 0, err // No session
	}

	sessionID := cookie.Value
	log.Printf("Session ID from cookie: %s", sessionID)

	SessionMutex.Lock()
	userID, ok := SessionStore[sessionID]
	SessionMutex.Unlock()

	if !ok {
		log.Println("Invalid session ID")
		return 0, fmt.Errorf("invalid session ID")
	}

	log.Printf("User ID from session: %d", userID)
	return userID, nil
}

// Pre-parsed template for better efficiency
var createPostTemplate = template.Must(template.ParseFiles("views/create_post.html"))

func CreatePost(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Serve the create post form
		err := createPostTemplate.Execute(w, nil)
		if err != nil {
			log.Printf("Error rendering template: %v", err)
			http.Error(w, "Error rendering page", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		// Get user ID from session
		userID, err := GetUserIDFromSession(r)
		if err != nil {
			log.Printf("User session not found: %v", err)
			http.Redirect(w, r, "/login", http.StatusSeeOther) // Redirect if no session
			return
		}

		// Parse the form
		r.ParseForm()
		title := r.FormValue("title")
		body := r.FormValue("body")

		// Validate that title and body are not empty
		if title == "" || body == "" {
			http.Error(w, "Title and Body cannot be empty", http.StatusBadRequest)
			return
		}

		// Insert the post into the database
		_, err = database.DB.Exec("INSERT INTO posts (title, body, user_id) VALUES (?, ?, ?)", title, body, userID)
		if err != nil {
			log.Printf("Error inserting post into database: %v", err)
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
		userID, err := GetUserIDFromSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		r.ParseForm()
		postID := r.FormValue("post_id")
		commentBody := r.FormValue("body")

		_, err = database.DB.Exec("INSERT INTO comments (body, post_id, user_id) VALUES (?, ?, ?)", commentBody, postID, userID)
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
	// Get the user ID from the session
	userID, err := GetUserIDFromSession(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

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
		userID, err := GetUserIDFromSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		r.ParseForm()
		postID := r.FormValue("post_id")

		var count int
		err = database.DB.QueryRow("SELECT COUNT(*) FROM likes_dislikes WHERE post_id = ? AND user_id = ? AND like_type = 1", postID, userID).Scan(&count)
		if err != nil {
			http.Error(w, "Error checking like status", http.StatusInternalServerError)
			return
		}

		if count == 0 {
			_, err = database.DB.Exec("INSERT INTO likes_dislikes (user_id, post_id, like_type) VALUES (?, ?, 1)", userID, postID)
			if err != nil {
				http.Error(w, "Error liking post", http.StatusInternalServerError)
				return
			}
		}

		http.Redirect(w, r, "/posts", http.StatusSeeOther)
	}
}

func DislikePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		userID, err := GetUserIDFromSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		r.ParseForm()
		postID := r.FormValue("post_id")

		var count int
		err = database.DB.QueryRow("SELECT COUNT(*) FROM likes_dislikes WHERE post_id = ? AND user_id = ? AND like_type = -1", postID, userID).Scan(&count)
		if err != nil {
			http.Error(w, "Error checking dislike status", http.StatusInternalServerError)
			return
		}

		if count == 0 {
			_, err = database.DB.Exec("INSERT INTO likes_dislikes (user_id, post_id, like_type) VALUES (?, ?, -1)", userID, postID)
			if err != nil {
				http.Error(w, "Error disliking post", http.StatusInternalServerError)
				return
			}
		}

		http.Redirect(w, r, "/posts", http.StatusSeeOther)
	}
}
