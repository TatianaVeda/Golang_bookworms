// posts.go
package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"literary-lions/database"
	"literary-lions/structs"
	"literary-lions/utils"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//var db *sql.DB

type Post struct {
	ID        int
	Title     string
	Body      string // Change Content to Body
	UserID    int
	CreatedAt time.Time
}

func PostsHandler(db *sql.DB, templates *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if the user is logged in
		isLoggedIn := false
		if _, err := r.Cookie("session_id"); err == nil {
			isLoggedIn = true
		}

		// Retrieve the category ID from the URL query parameter
		categoryID := r.URL.Query().Get("category")
		if categoryID == "" {
			log.Println("Category ID is missing in the request")
			utils.RenderErrorPage(w, http.StatusBadRequest, "Category ID is required for filtering.")
			return
		}

		// Convert the category ID to an integer
		categoryIDInt, err := strconv.Atoi(categoryID)
		if err != nil {
			log.Printf("Invalid category ID: %s", categoryID)
			utils.RenderErrorPage(w, http.StatusBadRequest, "Invalid Category ID.")
			return
		}

		// Fetch the category name based on the category ID
		var categoryName string
		err = db.QueryRow("SELECT name FROM categories WHERE id = ?", categoryIDInt).Scan(&categoryName)
		if err != nil {
			log.Printf("Error fetching category name for ID %d: %v", categoryIDInt, err)
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error fetching category name.")
			return
		}

		// Log the fetched category name for debugging
		log.Printf("CategoryName: %s", categoryName)

		// Fetch posts belonging to the category
		query := `
            SELECT posts.id, posts.title, posts.body, users.username, posts.created_at 
            FROM posts
            JOIN users ON posts.user_id = users.id
            WHERE posts.category_id = ?
            ORDER BY posts.created_at DESC
        `
		rows, err := db.Query(query, categoryIDInt)
		if err != nil {
			log.Printf("Error fetching posts for category %d: %v", categoryIDInt, err)
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error fetching posts.")
			return
		}
		defer rows.Close()

		// Prepare posts for rendering
		var posts []structs.Post
		for rows.Next() {
			var post structs.Post
			err := rows.Scan(&post.ID, &post.Title, &post.Body, &post.UserName, &post.CreatedAt)
			if err != nil {
				log.Printf("Error scanning post for category '%s': %v", categoryID, err)
				continue
			}
			// getting comments for posts
			post.Comments, err = FetchCommentsForPost(db, post.ID) // fetching comments
			if err != nil {
				log.Printf("Error fetching comments for post ID %d: %v", post.ID, err)
			}

			posts = append(posts, post)
		}

		// Log posts for debugging
		log.Printf("Posts: %+v", posts)

		// Check for errors after iterating
		if err = rows.Err(); err != nil {
			log.Printf("Error iterating through posts for category '%s': %v", categoryID, err)
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error processing posts.")
			return
		}
		/* 	// Логика для получения постов
		posts, err = database.FetchAllPosts() // функция для получения всех постов
		if err != nil {
			http.Error(w, "Unable to fetch posts", http.StatusInternalServerError)
			return
		}

		// Для каждого поста нужно получить комментарии
		for i, post := range posts {
			comments, err := FetchCommentsForPost(db, post.ID)
			if err != nil {
				http.Error(w, "Unable to fetch comments", http.StatusInternalServerError)
				return
			}
			posts[i].Comments = comments // Добавляем комментарии к каждому посту
		} */

		// Render the template with posts and login status
		err = templates.ExecuteTemplate(w, "posts.html", map[string]interface{}{
			"Posts":        posts,
			"CategoryName": categoryName,
			"IsLoggedIn":   isLoggedIn, // Pass login status for conditional display
		})

		if err != nil {
			log.Printf("Template execution error for category '%s': %v", categoryID, err)
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error rendering posts template.")
		}
	}
}

func ShowPosts(w http.ResponseWriter, r *http.Request) {
	categoryID := r.URL.Query().Get("category")
	var rows *sql.Rows
	var err error
	var categoryName string
	isLoggedIn := false

	// Check if a valid session cookie is present
	cookie, sessErr := r.Cookie("session_id")
	if sessErr == nil {
		sessionID := cookie.Value
		// Verify session ID is valid in session store
		sessionUserID, sessionErr := VerifySession(sessionID)
		if sessionErr == nil && sessionUserID > 0 {
			isLoggedIn = true
		}
	}

	// Default categoryID to 0 if not provided
	categoryIDInt := 0
	if categoryID != "" {
		categoryIDInt, err = strconv.Atoi(categoryID)
		if err != nil {
			http.Error(w, "Invalid Category ID", http.StatusBadRequest)
			return
		}
	}

	// Prepare SQL query for posts with likes/dislikes
	query := `
    SELECT posts.id, posts.title, posts.body, users.username, categories.name, 
           IFNULL(likes_table.likes, 0) AS LikeCount, 
           IFNULL(likes_table.dislikes, 0) AS DislikeCount
    FROM posts
    JOIN users ON posts.user_id = users.id
    JOIN categories ON posts.category_id = categories.id
    LEFT JOIN (
        SELECT post_id,
            SUM(CASE WHEN like_type = 1 THEN 1 ELSE 0 END) AS likes,
            SUM(CASE WHEN like_type = -1 THEN 1 ELSE 0 END) AS dislikes
        FROM likes_dislikes
        GROUP BY post_id
    ) AS likes_table ON posts.id = likes_table.post_id`

	if categoryIDInt > 0 {
		query += " WHERE posts.category_id = ? ORDER BY posts.created_at DESC"
		rows, err = database.DB.Query(query, categoryIDInt)
		if err != nil {
			http.Error(w, "Error fetching posts", http.StatusInternalServerError)
			log.Printf("Database query error: %v", err)
			return
		}

		err = database.DB.QueryRow("SELECT name FROM categories WHERE id = ?", categoryIDInt).Scan(&categoryName)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		query += " ORDER BY posts.created_at DESC"
		rows, err = database.DB.Query(query)
		if err != nil {
			http.Error(w, "Error fetching posts", http.StatusInternalServerError)
			log.Printf("Database query error: %v", err)
			return
		}
		categoryName = "All Categories"
	}

	defer rows.Close()

	var posts []structs.Post
	for rows.Next() {
		var post structs.Post
		err := rows.Scan(&post.ID, &post.Title, &post.Body, &post.UserName, &post.CategoryName, &post.LikeCount, &post.DislikeCount)
		if err != nil {
			log.Printf("Error scanning posts: %v", err)
			continue
		}

		// Fetch comments for the post
		commentRows, err := database.DB.Query("SELECT body, user_id FROM comments WHERE post_id = ?", post.ID)
		if err != nil {
			log.Printf("Error fetching comments for post ID %d: %v", post.ID, err)
			continue
		}
		defer commentRows.Close()

		var comments []structs.Comment
		for commentRows.Next() {
			var comment structs.Comment
			err := commentRows.Scan(&comment.Body, &comment.UserName)
			if err == nil {
				comments = append(comments, comment)
			} else {
				log.Printf("Error scanning comment for post ID %d: %v", post.ID, err)
			}
		}
		post.Comments = comments
		posts = append(posts, post)
	}

	if err = rows.Err(); err != nil {
		http.Error(w, "Error processing posts", http.StatusInternalServerError)
		return
	}

	tmpl := template.Must(template.ParseFiles("views/posts.html"))
	err = tmpl.Execute(w, map[string]interface{}{
		"Posts":        posts,
		"CategoryID":   categoryIDInt,
		"CategoryName": categoryName,
		"IsLoggedIn":   isLoggedIn,
	})
	if err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

func GetUserIDFromSession(r *http.Request) (int, error) {
	// Retrieve session ID from the cookie
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		log.Printf("GetUserIDFromSession: No session ID found in cookies: %v", err)
		return 0, fmt.Errorf("no session ID found")
	}

	// Query the sessions table to get the associated user ID
	var userID int
	err = database.DB.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", sessionCookie.Value).Scan(&userID)
	if err != nil {
		log.Printf("GetUserIDFromSession: Error querying database: %v", err)
		return 0, fmt.Errorf("invalid session")
	}

	log.Printf("GetUserIDFromSession: Retrieved user ID %d for session ID %s", userID, sessionCookie.Value)
	return userID, nil
}

// GetUserIDFromSessionID takes a session ID and retrieves the corresponding user ID from the sessions table.
func GetUserIDFromSessionID(sessionID string) (int, error) {
	var userID int

	// Query the database for the user ID associated with the given session ID
	err := database.DB.QueryRow("SELECT user_id FROM sessions WHERE session_id = ?", sessionID).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			// If no user is found for the session ID, log and return a not found error
			log.Printf("GetUserIDFromSessionID: No user found for session ID: %s", sessionID)
			return 0, nil
		}
		// Log and return any other errors encountered during the query
		log.Printf("GetUserIDFromSessionID: Error querying database: %v", err)
		return 0, err
	}

	// Log the retrieved user ID for debugging
	log.Printf("GetUserIDFromSessionID: Retrieved user ID %d for session ID %s", userID, sessionID)

	return userID, nil
}

func GetUsernameFromSession(r *http.Request) (string, error) {
	// Retrieve the user ID from the session
	userID, err := GetSession(r)
	if err != nil {
		return "", fmt.Errorf("unable to get session: %v", err)
	}

	// Fetch the username based on the user ID
	username := database.GetUserNameByID(userID) // Only capture the username
	if username == "Unknown" {
		return "", fmt.Errorf("error: user not found for ID %d", userID)
	}

	return username, nil
}

func ProfileHandler(templates *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the session user ID instead of username
		userID, err := GetSession(r)
		if err != nil {
			fmt.Println("Get session error:", err)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		fmt.Printf("Session retrieved successfully. UserID: %d\n", userID)

		// Fetch the username using the user ID
		username := database.GetUserNameByID(userID)
		if username == "Unknown" {
			http.Error(w, "Error fetching username", http.StatusInternalServerError)
			return
		}

		// Get the username from the query string (if provided), otherwise use session username
		profileUsername := r.URL.Query().Get("username")
		if profileUsername == "" {
			profileUsername = username
		}

		// Fetch the profile data
		profileData, err := database.FetchProfileData(profileUsername)
		if err != nil {
			http.Error(w, "Error fetching profile", http.StatusInternalServerError)
			return
		}

		// Get user ID of the profile being viewed
		profileUserID, err := database.GetUserID(profileUsername)
		if err != nil {
			http.Error(w, "Error fetching user ID", http.StatusInternalServerError)
			return
		}

		// Fetch user posts
		userPosts, err := database.FetchUserPosts(userID)
		if err != nil {
			http.Error(w, "Error fetching user posts", http.StatusInternalServerError)
			return
		}
		profileData.Posts = userPosts

		// Fetch user comments
		comments, err := database.FetchUserComments(profileUserID)
		if err != nil {
			http.Error(w, "Error fetching comments", http.StatusInternalServerError)
			return
		}
		profileData.Comments = comments

		// Fetch liked posts if viewing own profile
		if profileUserID == userID {
			likedPosts, err := database.FetchLikedPosts(userID)
			if err != nil {
				http.Error(w, "Error fetching liked posts", http.StatusInternalServerError)
				return
			}

			// Convert []map[string]interface{} to []structs.Post
			var likedPostsConverted []structs.Post
			for _, postMap := range likedPosts {
				post := structs.Post{
					ID:        postMap["ID"].(int),
					Title:     postMap["Title"].(string),
					Body:      postMap["Body"].(string),
					CreatedAt: postMap["CreatedAT"].(time.Time),
					UserName:  postMap["UserName"].(string),
				}
				likedPostsConverted = append(likedPostsConverted, post)
			}
			profileData.LikedPosts = likedPostsConverted

			// Fetch liked comments
			likedComments, err := database.FetchLikedComments(userID)
			if err != nil {
				http.Error(w, "Error fetching liked comments", http.StatusInternalServerError)
				return
			}

			// Convert []map[string]interface{} to []structs.Comment
			var likedCommentsConverted []structs.Comment
			for _, commentMap := range likedComments {
				comment := structs.Comment{
					ID:     commentMap["ID"].(int),
					Body:   commentMap["Body"].(string),
					PostID: commentMap["PostID"].(int),
				}
				likedCommentsConverted = append(likedCommentsConverted, comment)
			}
			profileData.LikedComments = likedCommentsConverted
		}

		// Render the profile template
		templates.ExecuteTemplate(w, "profile.html", map[string]interface{}{
			"ProfileData": profileData,
			"LoggedUser":  username,
		})
	}
}

func RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Retrieve and validate the session cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther) // Redirect to /login if no session
			return
		}

		SessionMutex.Lock()
		_, sessionExists := SessionStore[cookie.Value]
		SessionMutex.Unlock()

		if !sessionExists {
			http.Redirect(w, r, "/login", http.StatusSeeOther) // Redirect if session is not found
			return
		}

		// If session is valid, proceed to the next handler
		next.ServeHTTP(w, r)
	})
}

func LikePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Check if the user is logged in
		userID, err := GetSession(r)
		if err != nil {
			log.Println("LikePostHandler: User not logged in, redirecting to login.")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Retrieve the post ID from the form
		postID := r.FormValue("post_id")
		if postID == "" {
			log.Println("LikePostHandler: Invalid post ID received.")
			http.Error(w, "Invalid post ID", http.StatusBadRequest)
			return
		}

		log.Printf("LikePostHandler: Received post_id = %s for user_id = %d", postID, userID)

		// Check if the user has already liked or disliked the post
		var existingLikeType int
		err = database.DB.QueryRow("SELECT like_type FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID).Scan(&existingLikeType)
		if err == sql.ErrNoRows {
			log.Println("LikePostHandler: No previous like/dislike found, inserting a new like.")
			// No existing like/dislike, insert a new like
			_, err = database.DB.Exec("INSERT INTO likes_dislikes (post_id, user_id, like_type) VALUES (?, ?, 1)", postID, userID)
		} else if existingLikeType == -1 {
			log.Println("LikePostHandler: Previously disliked, changing to like.")
			// If disliked, change it to a like
			_, err = database.DB.Exec("UPDATE likes_dislikes SET like_type = 1 WHERE post_id = ? AND user_id = ?", postID, userID)
		} else if existingLikeType == 1 {
			log.Println("LikePostHandler: Already liked, removing like.")
			// Remove like if the same button is clicked
			_, err = database.DB.Exec("DELETE FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID)
		}

		if err != nil {
			log.Printf("LikePostHandler: Error modifying like/dislike: %v", err)
			http.Error(w, "Error processing like action", http.StatusInternalServerError)
			return
		}

		// Handle redirect back to the category or the referring page
		categoryID := r.URL.Query().Get("category")
		if categoryID != "" {
			log.Printf("Redirecting back to category page with category ID: %s", categoryID)
			http.Redirect(w, r, "/posts?category="+categoryID, http.StatusSeeOther)
		} else {
			log.Println("Redirecting back to the referring page")
			http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
		}
	}
}

func DislikePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Check if the user is logged in
		userID, err := GetSession(r)
		if err != nil {
			log.Println("LikePostHandler: User not logged in, redirecting to login.")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Retrieve the post ID from the form
		postID := r.FormValue("post_id")
		if postID == "" {
			log.Println("DislikePostHandler: Invalid post ID received.")
			http.Error(w, "Invalid post ID", http.StatusBadRequest)
			return
		}
		log.Printf("DislikePostHandler: Received post_id = %s for user_id = %d", postID, userID)

		// Check if the user has already liked or disliked the post
		var existingLikeType int
		err = database.DB.QueryRow("SELECT like_type FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID).Scan(&existingLikeType)
		if err == sql.ErrNoRows {
			log.Println("DislikePostHandler:: No previous like/dislike found, inserting a new like.")
			// No existing like/dislike, insert a new like
			_, err = database.DB.Exec("INSERT INTO likes_dislikes (post_id, user_id, like_type) VALUES (?, ?, -1)", postID, userID)
		} else if existingLikeType == 1 {
			log.Println("DislikePostHandler:: Already liked, removing like.")
			// Remove like if the same button is clicked
			_, err = database.DB.Exec("UPDATE likes_dislikes SET like_type = -1 WHERE post_id = ? AND user_id = ?", postID, userID)
		} else if existingLikeType == -1 {
			log.Println("DislikePostHandler:: Previously disliked, changing to like.")
			// If disliked, change it to a like
			_, err = database.DB.Exec("DELETE FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID)
		}

		if err != nil {
			log.Printf("DislikePostHandler:: Error modifying like/dislike: %v", err)
			http.Error(w, "Error processing dislike action", http.StatusInternalServerError)
			return
		}

		// Handle redirect back to the category or the referring page
		categoryID := r.URL.Query().Get("category")
		if categoryID != "" {
			log.Printf("Redirecting back to category page with category ID: %s", categoryID)
			http.Redirect(w, r, "/posts?category="+categoryID, http.StatusSeeOther)
		} else {
			log.Println("Redirecting back to the referring page")
			http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
		}
	}
}

func UpdateLikeDislikeHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("UpdateLikeDislikeHandler: Received a request")

		// Ensure the request method is POST (or PUT for updating)
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		// Retrieve session information to identify the user
		userID, err := GetSession(r)
		if err != nil {
			http.Error(w, "Unauthorized. Please log in.", http.StatusUnauthorized)
			log.Println("Unauthorized request - session not found")
			return
		}

		// Retrieve form values for post_id, like_type, and category_id
		postIDStr := r.FormValue("post_id")
		likeTypeStr := r.FormValue("like_type")
		//categoryIDStr := r.FormValue("category_id") remove category checking

		log.Printf("Incoming form values: post_id=%s, like_type=%s", postIDStr, likeTypeStr) //, categoryIDStr, category_id=%s

		// Validate post ID and like type
		postID, err := strconv.Atoi(postIDStr)
		if err != nil {
			http.Error(w, "Invalid post ID", http.StatusBadRequest)
			log.Println("Invalid post ID:", postIDStr, "Error:", err)
			return
		}

		likeType, err := strconv.Atoi(likeTypeStr)
		if err != nil || (likeType != 1 && likeType != -1) {
			http.Error(w, "Invalid like type", http.StatusBadRequest)
			log.Println("Invalid like type:", likeTypeStr, "Error:", err)
			return
		}

		/* categoryID, err := strconv.Atoi(categoryIDStr)
		if err != nil || categoryID <= 0 {
			http.Error(w, "Category ID is required", http.StatusBadRequest)
			log.Println("Invalid category ID:", categoryIDStr, "Error:", err)
			return
		} */

		// Check if the user has already liked or disliked the post
		var existingLikeType int
		err = db.QueryRow("SELECT like_type FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID).Scan(&existingLikeType)

		if err == sql.ErrNoRows {
			// No existing like/dislike, insert a new record
			_, err = db.Exec("INSERT INTO likes_dislikes (post_id, user_id, like_type) VALUES (?, ?, ?)", postID, userID, likeType)
			if err != nil {
				http.Error(w, "Error inserting new like/dislike", http.StatusInternalServerError)
				log.Println("Error inserting new like/dislike:", err)
				return
			}
		} else if existingLikeType != likeType {
			// Update existing like/dislike
			_, err = db.Exec("UPDATE likes_dislikes SET like_type = ? WHERE post_id = ? AND user_id = ?", likeType, postID, userID)
			if err != nil {
				http.Error(w, "Error updating like/dislike", http.StatusInternalServerError)
				log.Println("Error updating like/dislike:", err)
				return
			}
		} else {
			// Remove like/dislike if user clicks the same button again
			_, err = db.Exec("DELETE FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID)
			if err != nil {
				http.Error(w, "Error removing like/dislike", http.StatusInternalServerError)
				log.Println("Error removing like/dislike:", err)
				return
			}
		}

		// Retrieve the updated like and dislike counts for the post
		var likeCount, dislikeCount int
		err = db.QueryRow(`
			SELECT IFNULL(SUM(CASE WHEN like_type = 1 THEN 1 ELSE 0 END), 0) AS likes,
			       IFNULL(SUM(CASE WHEN like_type = -1 THEN 1 ELSE 0 END), 0) AS dislikes
			FROM likes_dislikes
			WHERE post_id = ?`, postID).Scan(&likeCount, &dislikeCount)
		if err != nil {
			http.Error(w, "Error fetching like/dislike counts", http.StatusInternalServerError)
			log.Println("Error fetching like/dislike counts:", err)
			return
		}

		categoryID := r.URL.Query().Get("category")
		// Pass the updated counts back to the ShowPosts handler for the correct category
		log.Printf("Updated counts for post %d: Likes = %d, Dislikes = %d\n", postID, likeCount, dislikeCount)

		// Logic for redirection depending on the presence of the category
		if categoryID != "" {
			log.Printf("Redirecting back to category page with category ID: %s", categoryID)
			http.Redirect(w, r, fmt.Sprintf("/posts?category=%s", categoryID), http.StatusSeeOther)
		} else {
			log.Println("Redirecting back to the referring page")
			http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
			//http.Redirect(w, r, "/posts?category=%d", http.StatusSeeOther)
		}
	}
}

func SearchPosts(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query") // Retrieve the search query from the URL

	// Ensure query isn't empty
	if query == "" {
		utils.RenderErrorPage(w, http.StatusBadRequest, "Search query cannot be empty.")
		return
	}

	log.Printf("Executing search with query: %s", query)

	// Search posts based on the query (e.g., title or body match)
	rows, err := database.DB.Query(`
        SELECT title, body, author, created_at FROM posts
        WHERE title LIKE ? OR body LIKE ?`, "%"+query+"%", "%"+query+"%")
	if err != nil {
		utils.RenderErrorPage(w, http.StatusInternalServerError, "Error fetching search results.")
		return
	}
	defer rows.Close()

	// Collect results
	var results []map[string]interface{}
	for rows.Next() {
		var title, body, author string
		var createdAt string
		if err := rows.Scan(&title, &body, &author, &createdAt); err != nil {
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error scanning search results.")
			return
		}
		result := map[string]interface{}{
			"Title":     title,
			"Body":      body,
			"Author":    author,
			"CreatedAt": createdAt,
		}
		results = append(results, result)
	}

	// Create the data map to pass to the template
	data := map[string]interface{}{
		"Query":   query,
		"Results": results,
	}

	// Render the search results template
	tmpl := template.Must(template.ParseFiles("views/search_results.html"))
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err) // Log the exact template error
		utils.RenderErrorPage(w, http.StatusInternalServerError, fmt.Sprintf("Error rendering template: %v", err))
	}
}

func CreatePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse JSON body
	var postData struct {
		Title      string `json:"title"`
		Body       string `json:"body"`
		CategoryID int    `json:"category_id"`
		UserID     int    `json:"user_id"`
	}

	err := json.NewDecoder(r.Body).Decode(&postData)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate fields
	if postData.Title == "" || postData.Body == "" || postData.CategoryID == 0 {
		http.Error(w, "Title, body, and category are required.", http.StatusBadRequest)
		return
	}

	// Insert post into database
	_, err = database.DB.Exec("INSERT INTO posts (title, body, user_id, category_id) VALUES (?, ?, ?, ?)", postData.Title, postData.Body, postData.UserID, postData.CategoryID)
	if err != nil {
		http.Error(w, "Unable to create post.", http.StatusInternalServerError)
		return
	}

	// Redirect to the category page
	http.Redirect(w, r, fmt.Sprintf("/posts?category=%d", postData.CategoryID), http.StatusSeeOther)
}

func CreateComment(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		userID, err := GetUserIDFromSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Parse form values
		postID := r.FormValue("post_id")
		commentBody := r.FormValue("body")

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
		//_, err = database.DB.Exec("INSERT INTO comments (user_id, post_id, body) VALUES (?, ?, ?)", userID, postID, commentBody)
		_, err = database.WriteDB.Exec("INSERT INTO comments (user_id, post_id, body, created_at, likes, dislikes) VALUES (?, ?, ?, ?, ?)", userID, postIDInt, commentBody)
		if err != nil {
			http.Error(w, "Error posting comment.", http.StatusInternalServerError)
			log.Printf("Error posting comment: %v", err)
			return
		}

		// Redirect back to the post after adding the comment
		http.Redirect(w, r, fmt.Sprintf("/posts?post_id=%s", postID), http.StatusSeeOther)
		//http.Redirect(w, r, fmt.Sprintf("/posts/?post_id=%d", postIDInt), http.StatusSeeOther)
		//http.Redirect(w, r, "/posts/"+postID, http.StatusSeeOther)
		return

	}
}
func LikeComment(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Получаем ID комментария
		commentID := r.FormValue("comment_id")
		if commentID == "" {
			http.Error(w, "Invalid comment ID", http.StatusBadRequest)
			return
		}

		// Преобразуем ID комментария в целое число
		commentIDInt, err := strconv.Atoi(commentID)
		if err != nil {
			http.Error(w, "Invalid comment ID", http.StatusBadRequest)
			return
		}

		// Обновляем количество лайков в базе данных
		_, err = database.WriteDB.Exec("UPDATE comments SET likes = likes + 1 WHERE id = ?", commentIDInt)
		if err != nil {
			http.Error(w, "Unable to like comment", http.StatusInternalServerError)
			log.Printf("Error liking comment: %v", err)
			return
		}

		// Опционально: перенаправляем обратно на пост или возвращаем JSON для динамического обновления на странице
		http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
	}
}

// fetching comments by Post ID
func FetchCommentsForPost(db *sql.DB, postID int) ([]structs.Comment, error) {
	var comments []structs.Comment
	rows, err := db.Query("SELECT id, user_id, post_id, body, created_at, likes, dislikes FROM comments WHERE post_id = ?", postID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var comment structs.Comment
		if err := rows.Scan(&comment.ID, &comment.UserID, &comment.PostID, &comment.Body, &comment.CreatedAt, &comment.LikeCount, &comment.DislikeCount); err != nil {
			return nil, err
		}
		// Fetch the poster name using userID
		err = database.DB.QueryRow("SELECT username FROM users WHERE id = ?", comment.UserID).Scan(&comment.Poster)
		if err != nil {
			return nil, err
		}

		comments = append(comments, comment)
	}
	return comments, nil //rows.Err()
}

/*func MyPostsHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session cookie
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Get the user ID from the session store
	sessionID := sessionCookie.Value
	database.SessionMutex.Lock()
	userID, exists := database.SessionStore[sessionID]
	database.SessionMutex.Unlock()

	if !exists {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Correct query with LEFT JOIN to get categories and posts
	query := `
		SELECT posts.id, posts.title, posts.body,
		       COALESCE(categories.name, 'Uncategorized') AS category_name
		FROM posts
		LEFT JOIN categories ON posts.category_id = categories.id
		WHERE posts.user_id = ?
	`

	// Execute the query to fetch posts
	rows, err := database.DB.Query(query, userID)
	if err != nil {
		log.Printf("Error fetching posts: %v", err)
		http.Error(w, "Unable to fetch posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Process the results
	var posts []map[string]interface{}
	for rows.Next() {
		var id int
		var title, body, categoryName string
		err := rows.Scan(&id, &title, &body, &categoryName)
		if err != nil {
			http.Error(w, "Error scanning posts", http.StatusInternalServerError)
			return
		}
		post := map[string]interface{}{
			"ID":           id,
			"Title":        title,
			"Body":         body,
			"CategoryName": categoryName,
		}
		posts = append(posts, post)
	}

	// Render the template
	tmpl := template.Must(template.ParseFiles("views/myposts.html"))
	err = tmpl.Execute(w, map[string]interface{}{
		"Posts": posts,
	})
	if err != nil {
		log.Printf("Error rendering template: %v", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}
*/

func GetCategoryName(categoryID int) string {
	var categoryName string
	query := `SELECT name FROM categories WHERE id = ?`

	err := database.DB.QueryRow(query, categoryID).Scan(&categoryName)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Category with ID %d not found.", categoryID)
			return ""
		}
		log.Printf("Error retrieving category name for ID %d: %v", categoryID, err)
		return ""
	}

	log.Printf("Retrieved category name for ID %d: %s", categoryID, categoryName)
	return categoryName
}

// FilterPostsByCategory handles requests to view posts in a specific category.
func FilterPostsByCategory(w http.ResponseWriter, r *http.Request) {
	// Retrieve and validate the category ID from the URL query parameter
	categoryID := r.URL.Query().Get("category")
	log.Printf("Category ID Received from URL: %s", categoryID)

	categoryIDInt, err := strconv.Atoi(categoryID)
	if err != nil {
		log.Printf("Invalid category ID: %s", categoryID)
		utils.RenderErrorPage(w, http.StatusBadRequest, "Invalid Category ID.")
		return
	}

	// Debugging: Log the incoming category ID
	log.Printf("Received request to filter posts for category ID: %d", categoryIDInt)

	query := `
    SELECT posts.id, posts.title, posts.body, users.username, posts.created_at, categories.name 
    FROM posts
    JOIN users ON posts.user_id = users.id
    JOIN categories ON posts.category_id = categories.id
`
	log.Printf("Executing SQL query: %s with category ID: %d", query, categoryIDInt)

	// Execute the query and fetch results
	rows, err := database.DB.Query(query, categoryIDInt)
	if err != nil {
		log.Printf("Database query error for category '%d': %v", categoryIDInt, err)
		utils.RenderErrorPage(w, http.StatusInternalServerError, "Error retrieving posts.")
		return
	}
	defer rows.Close()

	// Prepare a slice to store the retrieved posts
	var posts []structs.Post

	for rows.Next() {
		var post structs.Post
		var username, categoryName string

		log.Printf("Attempting to scan row for category ID: %d", categoryIDInt)

		err := rows.Scan(&post.ID, &post.Title, &post.Body, &username, &post.CreatedAt, &categoryName)
		if err != nil {
			log.Printf("Error scanning post data for category '%d': %v", categoryIDInt, err)
			continue
		}

		log.Printf("Successfully scanned Post: ID=%d, Title=%s, Body=%s, Username=%s, CategoryName=%s",
			post.ID, post.Title, post.Body, username, categoryName)

		post.UserName = username
		post.CategoryName = categoryName
		posts = append(posts, post)
	}

	log.Printf("Total Posts for category ID %d: %d", categoryIDInt, len(posts))

	// Check for errors after iteration
	if err = rows.Err(); err != nil {
		log.Printf("Error encountered during rows iteration: %v", err)
	}

	// Debug: Print the retrieved posts and their count
	log.Printf("Number of Posts Retrieved for Category '%d': %d", categoryIDInt, len(posts))
	for _, post := range posts {
		log.Printf("Post: ID=%d, Title=%s, Body=%s, Username=%s, CategoryName=%s",
			post.ID, post.Title, post.Body, post.UserName, post.CategoryName)
	}
	log.Printf("Filtered Posts for category '%d': %+v", categoryIDInt, posts)

	categoryName := GetCategoryName(categoryIDInt)
	log.Printf("CategoryName fetched: %s", categoryName)
	if categoryName == "" {
		categoryName = "Unknown Category"
	}

	// Debug the category name
	log.Printf("Category Name Retrieved: %s", categoryName)

	// Create the template data
	tmplData := structs.TemplateData{
		Posts:        posts,
		CategoryName: categoryName,
	}

	// Debug: Log the complete template data
	log.Printf("Template Data Prepared: %+v", tmplData)

	// Render the template with the filtered posts
	tmpl := template.Must(template.ParseFiles("views/posts.html"))
	err = tmpl.Execute(w, tmplData)
	if err != nil {
		log.Printf("Template execution error for category '%d': %v", categoryIDInt, err)
		utils.RenderErrorPage(w, http.StatusInternalServerError, "Error rendering posts template.")
	}
}

func DeletePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Extract post ID from the URL
	postIDStr := strings.TrimPrefix(r.URL.Path, "/posts/delete/")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil || postID <= 0 {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	// Get the user ID from session to ensure the user can only delete their posts
	userID, err := GetUserIDFromSession(r)
	if err != nil {
		http.Error(w, "Unauthorized. Please log in.", http.StatusUnauthorized)
		return
	}

	// Verify that the post exists and belongs to the user
	var ownerID int
	err = database.DB.QueryRow("SELECT user_id FROM posts WHERE id = ?", postID).Scan(&ownerID)
	if err != nil {
		http.Error(w, "Post not found or you don't have permission to delete", http.StatusForbidden)
		return
	}

	// Only allow the owner to delete the post
	if ownerID != userID {
		http.Error(w, "You don't have permission to delete this post", http.StatusForbidden)
		return
	}

	// Delete the post from the database
	_, err = database.DB.Exec("DELETE FROM posts WHERE id = ?", postID)
	if err != nil {
		http.Error(w, "Unable to delete post", http.StatusInternalServerError)
		return
	}

	// Redirect to the posts list after deletion
	http.Redirect(w, r, "/posts", http.StatusSeeOther)
}

/* func PostHandler(w http.ResponseWriter, r *http.Request) {
	// Получите ID поста из URL
	postID := r.URL.Path[len("/posts/"):] // Отделите ID от URL
	var post structs.Post
	// Получите данные поста из базы данных
	err := database.DB.QueryRow("SELECT id, title, body FROM posts WHERE id = ?", postID).Scan(&post.ID, &post.Title, &post.Body)
	if err != nil {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	// Получите комментарии для этого поста
	comments, err := FetchCommentsForPost(db, post.ID)
	if err != nil {
		http.Error(w, "Unable to fetch comments", http.StatusInternalServerError)
		return
	}

	// Передайте данные в шаблон
	data := map[string]interface{}{
		"Post":       post,
		"Comments":   comments,
		"IsLoggedIn": true, // или ваша логика проверки авторизации
	}

	// Отрисуйте шаблон с данными
	tmpl := template.Must(template.ParseFiles("views/post.html"))
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Unable to render template", http.StatusInternalServerError)
	}
}
*/
