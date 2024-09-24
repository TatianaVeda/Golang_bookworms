package controllers

import (
	"fmt"
	"html/template"
	"literary-lions/database"
	"literary-lions/utils"
	"log"
	"net/http"
)

func ShowPosts(w http.ResponseWriter, r *http.Request) {
	// Modify the query to include likeCount and dislikeCount
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
		utils.HandleError(w, http.StatusInternalServerError, "Internal Server Error")
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
			utils.HandleError(w, http.StatusInternalServerError, "Internal Server Error")
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

var createPostTemplate = template.Must(template.ParseFiles("views/create_post.html"))

func CreatePost(w http.ResponseWriter, r *http.Request) {
	// Retrieve and validate the session
	cookie, err := r.Cookie("session_id")
	if err != nil {
		utils.HandleError(w, http.StatusUnauthorized, "Session not found.")
		return
	}

	// Check if the session exists in the session store
	SessionMutex.Lock()
	userID, sessionExists := SessionStore[cookie.Value]
	SessionMutex.Unlock()

	if !sessionExists {
		utils.HandleError(w, http.StatusUnauthorized, "Invalid session.")
		return
	}

	// At this point, the user is authenticated, and you can allow them to create a post.
	// Add the rest of your CreatePost logic here...

	// For example:
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			utils.HandleError(w, http.StatusBadRequest, "Unable to parse form data")
			return
		}

		// Get the form values and create the post
		title := r.FormValue("title")
		body := r.FormValue("body")

		// Insert post into the database (assuming you have a DB set up)
		_, err := database.DB.Exec(`INSERT INTO posts (user_id, title, body) VALUES (?, ?, ?)`, userID, title, body)
		if err != nil {
			utils.HandleError(w, http.StatusInternalServerError, "Error creating post")
			return
		}

		// Success! Redirect or return success response
		http.Redirect(w, r, "/myposts", http.StatusSeeOther)
	} else {
		// Render the post creation form (GET request)
		tmpl := template.Must(template.ParseFiles("views/create_post.html"))
		tmpl.Execute(w, nil)
	}
}

func RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Retrieve and validate the session
		cookie, err := r.Cookie("session_id")
		if err != nil {
			utils.HandleError(w, http.StatusUnauthorized, "Session not found.")
			return
		}

		// Check if the session exists in the session store
		SessionMutex.Lock()
		_, sessionExists := SessionStore[cookie.Value]
		SessionMutex.Unlock()

		if !sessionExists {
			utils.HandleError(w, http.StatusUnauthorized, "Invalid session.")
			return
		}

		// Proceed to the next handler if session is valid
		next.ServeHTTP(w, r)
	})
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
			log.Printf("Error posting comment: %v", err)
			utils.HandleError(w, http.StatusInternalServerError, "Internal Server Error")
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
		utils.HandleError(w, http.StatusInternalServerError, "Internal Server Error")
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
			utils.HandleError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		if count == 0 {
			_, err = database.DB.Exec("INSERT INTO likes_dislikes (user_id, post_id, like_type) VALUES (?, ?, 1)", userID, postID)
			if err != nil {
				utils.HandleError(w, http.StatusInternalServerError, "Internal Server Error")
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
			utils.HandleError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		if count == 0 {
			_, err = database.DB.Exec("INSERT INTO likes_dislikes (user_id, post_id, like_type) VALUES (?, ?, -1)", userID, postID)
			if err != nil {
				utils.HandleError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
		}

		http.Redirect(w, r, "/posts", http.StatusSeeOther)
	}
}
