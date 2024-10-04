package controllers

import (
	"database/sql"
	"fmt"
	"html/template"
	"literary-lions/database"
	"literary-lions/structs"
	"literary-lions/utils"
	"log"
	"net/http"
	"strconv"
)

func PostsHandler(templates *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Use a simpler approach for debugging first
		tmpl := template.Must(template.ParseFiles("views/posts.html", "views/create_post.html"))

		// Hardcoded sample data
		samplePosts := []map[string]interface{}{
			{"ID": 1, "Title": "Test Post 1", "Body": "Sample body for Post 1", "CategoryName": "Literature", "LikeCount": 10, "DislikeCount": 1},
			{"ID": 2, "Title": "Test Post 2", "Body": "Sample body for Post 2", "CategoryName": "Non-fiction", "LikeCount": 5, "DislikeCount": 0},
		}

		sampleCategories := []map[string]interface{}{
			{"ID": 1, "Name": "Literature"},
			{"ID": 2, "Name": "Non-fiction"},
		}

		// Pass the hardcoded values to the template to test rendering
		err := tmpl.Execute(w, map[string]interface{}{
			"Posts":      samplePosts,
			"Categories": sampleCategories,
		})
		if err != nil {
			log.Printf("Error rendering template: %v", err)
			http.Error(w, "Error rendering template", http.StatusInternalServerError)
		}
	}
}

func ShowPosts(w http.ResponseWriter, r *http.Request) {
	rows, err := database.DB.Query(`
        SELECT posts.id, posts.title, posts.body, posts.created_at, users.id, 
               categories.name, COALESCE(like_count, 0) AS like_count, COALESCE(dislike_count, 0) AS dislike_count
        FROM posts
        JOIN users ON posts.user_id = users.id
        JOIN categories ON posts.category_id = categories.id
        LEFT JOIN (
            SELECT post_id, 
                   SUM(CASE WHEN like_type = 1 THEN 1 ELSE 0 END) AS like_count,
                   SUM(CASE WHEN like_type = -1 THEN 1 ELSE 0 END) AS dislike_count
            FROM likes_dislikes
            GROUP BY post_id
        ) ld ON ld.post_id = posts.id
        ORDER BY posts.created_at DESC
    `)
	if err != nil {
		log.Printf("Error retrieving posts: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Retrieve the posts and populate into the structs.Post slice
	var posts []structs.Post
	for rows.Next() {
		var post structs.Post
		err := rows.Scan(&post.ID, &post.Title, &post.Body, &post.CreatedAt, &post.UserID, &post.CategoryName, &post.LikeCount, &post.DislikeCount)
		if err != nil {
			log.Printf("Error scanning post: %v", err)
			continue
		}
		posts = append(posts, post)
	}

	// Debug: Check the contents of the posts slice
	log.Printf("Fetched Posts: %+v", posts)

	// Render posts.html with posts slice
	tmpl := template.Must(template.ParseFiles("views/posts.html"))
	if err := tmpl.Execute(w, map[string]interface{}{
		"Posts": posts,
	}); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func GetUserIDFromSession(r *http.Request) (int, error) {
	sessionID, err := r.Cookie("session_id")
	if err != nil {
		log.Printf("GetUserIDFromSession: No session ID found in cookies: %v", err)
		return 0, fmt.Errorf("no session ID")
	}

	userID, err := GetUserIDFromSessionID(sessionID.Value)
	if err != nil {
		log.Printf("GetUserIDFromSession: Invalid session ID %s: %v", sessionID.Value, err)
		return 0, fmt.Errorf("invalid session")
	}

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
	username, err := database.GetUsernameByID(userID)
	if err != nil {
		return "", fmt.Errorf("error while getting username by ID: %v", err)
	}

	return username, nil
}

func ProfileHandler(templates *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the session user ID instead of username
		userID, err := GetSession(r)
		if err != nil {
			fmt.Println("Get session error:", err)
			http.Redirect(w, r, "/loginplease", http.StatusSeeOther)
			return
		}
		fmt.Printf("Session retrieved successfully. UserID: %d\n", userID)

		// Fetch the username using the user ID
		username, err := database.GetUsernameByID(userID)
		if err != nil {
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
					ID:    postMap["ID"].(int),
					Title: postMap["Title"].(string),
					Body:  postMap["Body"].(string),
				}
				likedPostsConverted = append(likedPostsConverted, post)
			}
			profileData.LikedPosts = likedPostsConverted

			// Fetch liked comments
			fmt.Println("Fetching liked posts and comments for user ID:", userID)
			likedComments, err := database.FetchLikedComments(userID)
			if err != nil {
				fmt.Println("Error fetching liked comments:", err) // Add this line for debugging
				http.Error(w, "Error fetching liked comments", http.StatusInternalServerError)
				return
			}

			fmt.Println("Fetched liked comments:", likedComments) // Add this to see if comments are fetched

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
	// Get the session user ID instead of username
	userID, err := GetSession(r) // Get the `userID` directly
	if err != nil {
		http.Error(w, "Unauthorized. Please log in.", http.StatusUnauthorized)
		return
	}

	postID := r.FormValue("post_id")

	// Check if the user has already liked or disliked the post
	var likeType int
	err = database.DB.QueryRow("SELECT like_type FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID).Scan(&likeType)

	if err == sql.ErrNoRows {
		// No existing like/dislike, insert a new like
		_, err = database.DB.Exec("INSERT INTO likes_dislikes (post_id, user_id, like_type) VALUES (?, ?, 1)", postID, userID)
		if err != nil {
			http.Error(w, "Error liking post", http.StatusInternalServerError)
			return
		}
	} else if likeType == -1 {
		// If disliked, change it to a like
		_, err = database.DB.Exec("UPDATE likes_dislikes SET like_type = 1 WHERE post_id = ? AND user_id = ?", postID, userID)
		if err != nil {
			http.Error(w, "Error updating like", http.StatusInternalServerError)
			return
		}
	}

	// Redirect back to the posts page
	http.Redirect(w, r, "/posts", http.StatusSeeOther)
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
	if r.Method == http.MethodPost {
		userID := 13 // Hardcoded user ID for testing (should be dynamic in production)

		// Retrieve form values
		title := r.FormValue("title")
		body := r.FormValue("body")
		categoryID := r.FormValue("category_id")

		if title == "" || body == "" || categoryID == "" {
			http.Error(w, "Title, body, and category cannot be empty", http.StatusBadRequest)
			return
		}

		// Insert post into the database
		_, err := database.DB.Exec("INSERT INTO posts (title, body, user_id, category_id) VALUES (?, ?, ?, ?)", title, body, userID, categoryID)
		if err != nil {
			log.Printf("Error inserting new post: %v", err)
			http.Error(w, "Unable to create post", http.StatusInternalServerError)
			return
		}

		log.Printf("Post created successfully: Title: %s | Body: %s | CategoryID: %s", title, body, categoryID)

		// Redirect to /posts after successful creation
		http.Redirect(w, r, "/posts", http.StatusSeeOther)
	} else {
		// Render the create post page if method is GET
		categories := []struct {
			ID   int
			Name string
		}{
			{1, "Literature"},
			{2, "Poetry"},
			{3, "Non-fiction"},
			{4, "Short Stories"},
		}

		data := map[string]interface{}{
			"Categories": categories,
		}

		tmpl := template.Must(template.ParseFiles("views/create_post.html"))
		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Template execution error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}
}

func CreateComment(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Retrieve the user ID from the session
		userID, err := GetUserIDFromSession(r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Parse form values
		r.ParseForm()
		postID := r.FormValue("post_id")   // Retrieve the post ID from the form
		commentBody := r.FormValue("body") // Retrieve the comment body from the form

		// Validate form inputs
		if postID == "" || commentBody == "" {
			http.Error(w, "Post ID and comment body cannot be empty", http.StatusBadRequest)
			return
		}

		// Convert post ID to an integer for database use
		postIDInt, err := strconv.Atoi(postID)
		if err != nil {
			http.Error(w, "Invalid Post ID", http.StatusBadRequest)
			return
		}

		// Insert the comment into the database
		_, err = database.WriteDB.Exec("INSERT INTO comments (user_id, post_id, body) VALUES (?, ?, ?)", userID, postIDInt, commentBody)
		if err != nil {
			http.Error(w, "Error posting comment", http.StatusInternalServerError)
			log.Printf("Error posting comment: %v", err)
			return
		}

		// Redirect back to the post after adding the comment
		http.Redirect(w, r, fmt.Sprintf("/posts?post_id=%d", postIDInt), http.StatusSeeOther)
	}
}

func MyPostsHandler(w http.ResponseWriter, r *http.Request) {
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

func FilterPostsByCategory(w http.ResponseWriter, r *http.Request) {
	// Get category ID from the URL query parameters
	categoryID := r.URL.Query().Get("category_id")

	// Define the query to get posts for a specific category ID
	query := `
        SELECT posts.id, posts.title, posts.body, categories.name
        FROM posts
        JOIN categories ON posts.category_id = categories.id
        WHERE categories.id = ?
    `

	// Execute the query to retrieve posts based on the specified category
	rows, err := database.DB.Query(query, categoryID)
	if err != nil {
		http.Error(w, "Error fetching posts by category", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Prepare a slice to store posts
	var posts []map[string]interface{}
	var categoryName string

	// Iterate over the results and add them to the posts slice
	for rows.Next() {
		var id int
		var title, body string

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

	// Render the category-specific posts using a dedicated template (ensure the file exists)
	tmpl := template.Must(template.ParseFiles("views/category_posts.html"))
	err = tmpl.Execute(w, map[string]interface{}{
		"CategoryName": categoryName,
		"Posts":        posts,
	})
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}
