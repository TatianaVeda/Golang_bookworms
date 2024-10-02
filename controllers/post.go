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

type Post struct {
	ID        int
	Title     string
	Body      string // Change Content to Body
	UserID    int
	CreatedAt string
}

func PostsHandler(templates *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the session username (only pass the request, not the db)
		username, err := GetSession(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodPost {
			// Get the user ID using the username (only pass the username, not the db)
			userID, err := database.GetUserID(username)
			if err != nil {
				log.Println("Error fetching user ID")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			title := r.FormValue("title")
			content := r.FormValue("content")
			categoryIDs := r.Form["categories"]
			if title == "" || content == "" {
				log.Println("Bad Request: Title and content are required")
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Begin transaction to insert post and categories
			tx, err := database.DB.Begin()
			if err != nil {
				log.Printf("Error starting transaction: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			// Insert post into DB
			res, err := tx.Exec("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)", userID, title, content)
			if err != nil {
				log.Printf("Error inserting post: %v", err)
				tx.Rollback()
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			postID, _ := res.LastInsertId()

			// Link post with categories
			stmt, err := tx.Prepare("INSERT INTO post_categories (post_id, category_id) VALUES (?, ?)")
			if err != nil {
				log.Printf("Error preparing category insert: %v", err)
				tx.Rollback()
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			for _, categoryID := range categoryIDs {
				_, err = stmt.Exec(postID, categoryID)
				if err != nil {
					log.Printf("Error linking post with category: %v", err)
					tx.Rollback()
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}

			err = tx.Commit()
			if err != nil {
				log.Printf("Error committing transaction: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/posts", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	}
}

func ShowPosts(w http.ResponseWriter, r *http.Request) {
	page := 1 // Assuming the user is on the first page by default
	limit := 10
	offset := (page - 1) * limit // Calculate offset based on the page number

	// SQL query to fetch posts with like and dislike counts
	query := `
		SELECT 
			posts.id, posts.title, posts.body, 
			COALESCE(SUM(CASE WHEN like_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
			COALESCE(SUM(CASE WHEN like_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count
		FROM posts
		LEFT JOIN likes_dislikes ON posts.id = likes_dislikes.post_id
		GROUP BY posts.id
		ORDER BY posts.created_at DESC
		LIMIT ? OFFSET ?;
	`
	rows, err := database.DB.Query(query, limit, offset)
	if err != nil {
		log.Printf("Error executing SQL query: %s, %v", query, err)
		http.Error(w, "Error fetching posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Store the fetched posts in a slice of maps
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

	// Render the posts.html template with fetched posts
	tmpl := template.Must(template.ParseFiles("views/posts.html"))
	err = tmpl.Execute(w, map[string]interface{}{
		"Posts": posts,
	})
	if err != nil {
		log.Printf("Error rendering template: %v", err)
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
	}
}

func GetUserIDFromSession(r *http.Request) (int, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		log.Println("No session cookie found")
		return 0, err
	}

	sessionID := cookie.Value
	log.Printf("Session ID from cookie: %s", sessionID)

	database.SessionMutex.Lock() // Lock the mutex before accessing the session store
	userID, ok := database.SessionStore[sessionID]
	database.SessionMutex.Unlock() // Unlock the mutex after access

	if !ok {
		log.Println("Invalid session ID")
		return 0, fmt.Errorf("invalid session ID")
	}

	log.Printf("User ID from session: %d", userID)
	return userID, nil
}

func ProfileHandler(templates *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the session username (no need to pass db)
		username, err := GetSession(r)
		if err != nil {
			fmt.Println("Get session error:", err)
			http.Redirect(w, r, "/loginplease", http.StatusSeeOther)
			return
		}
		fmt.Println("Session retrieved successfully. Username:", username)

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

		// Get user ID (no need to pass db)
		userID, err := database.GetUserID(profileUsername)
		if err != nil {
			http.Error(w, "Error fetching user ID", http.StatusInternalServerError)
			return
		}

		// Fetch user comments
		comments, err := database.FetchUserComments(userID)
		if err != nil {
			http.Error(w, "Error fetching comments", http.StatusInternalServerError)
			return
		}
		profileData.Comments = comments

		// Fetch liked posts if viewing own profile
		if profileUsername == username {
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
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			utils.HandleError(w, http.StatusBadRequest, "Unable to parse form data")
			return
		}
		title := r.FormValue("title")
		body := r.FormValue("body")
		//categoryID := r.FormValue("category_id")

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

func LikePostHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session username
	username, err := GetSession(r) // Only pass the request
	if err != nil {
		http.Error(w, "Unauthorized. Please log in.", http.StatusUnauthorized)
		return
	}

	// Get the user ID from the username
	userID, err := database.GetUserID(username) // Only pass the username
	if err != nil {
		http.Error(w, "Error fetching user ID", http.StatusInternalServerError)
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

	// Render the search results template
	tmpl := template.Must(template.ParseFiles("views/search_results.html"))
	if err := tmpl.Execute(w, map[string]interface{}{
		"Query":   query,
		"Results": results,
	}); err != nil {
		utils.RenderErrorPage(w, http.StatusInternalServerError, "Error rendering search results.")
	}
}

func CreatePostHandler(templates *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Log request
		log.Println("CreatePostHandler: Incoming request for /posts/create")

		// Validate the session
		username, err := GetSession(r)
		if err != nil {
			log.Printf("CreatePostHandler: Error retrieving session: %v", err)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		log.Printf("CreatePostHandler: Session found for user: %s", username)

		// Get the user ID based on the session username
		userID, err := database.GetUserID(username)
		if err != nil {
			log.Printf("CreatePostHandler: Error retrieving user ID: %v", err)
			http.Error(w, "Error retrieving user information", http.StatusInternalServerError)
			return
		}
		log.Printf("CreatePostHandler: User ID retrieved: %d", userID)

		// If the method is POST, process the form submission
		if r.Method == http.MethodPost {
			r.ParseForm()

			title := r.FormValue("title")
			body := r.FormValue("body")
			categoryID := r.FormValue("category_id")

			// Validate form input
			if title == "" || body == "" {
				log.Println("CreatePostHandler: Bad request, title or body missing")
				http.Error(w, "Title and body cannot be empty", http.StatusBadRequest)
				return
			}

			// Insert the new post into the database
			_, err = database.DB.Exec("INSERT INTO posts (title, body, user_id, category_id) VALUES (?, ?, ?, ?)",
				title, body, userID, categoryID)
			if err != nil {
				log.Printf("CreatePostHandler: Error creating post: %v", err)
				http.Error(w, "Error creating post", http.StatusInternalServerError)
				return
			}

			// Redirect to the posts page after successful creation
			log.Println("CreatePostHandler: Post created successfully")
			http.Redirect(w, r, "/posts", http.StatusSeeOther)
			return
		}
		query := `
			SELECT 
				posts.id, posts.title, posts.body, 
				COALESCE(SUM(CASE WHEN like_type = 1 THEN 1 ELSE 0 END), 0) AS like_count,
				COALESCE(SUM(CASE WHEN like_type = -1 THEN 1 ELSE 0 END), 0) AS dislike_count
			FROM posts
			LEFT JOIN likes_dislikes ON posts.id = likes_dislikes.post_id
			WHERE posts.user_id = ?
			GROUP BY posts.id
			`
		rows, err := database.DB.Query(query, userID)
		// If the method is GET, display the post creation form
		if r.Method == http.MethodGet {
			// Fetch categories to display in the form
			// rows, err := database.DB.Query("SELECT id, name FROM categories")
			if err != nil {
				log.Printf("CreatePostHandler: Error fetching categories: %v", err)
				http.Error(w, "Error fetching categories", http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			var posts = []map[string]interface{}{}
			var categories []map[string]interface{}
			for rows.Next() {
				var name string
				var id, likeCount, dislikeCount int
				var title, body string

				err := rows.Scan(&id, &name)
				if err != nil {
					log.Printf("CreatePostHandler: Error scanning category: %v", err)
					http.Error(w, "Error reading categories", http.StatusInternalServerError)
					return
				}
				categories = append(categories, map[string]interface{}{
					"ID":   id,
					"Name": name,
				})

				err = rows.Scan(&id, &title, &body, &likeCount, &dislikeCount)
				if err != nil {
					log.Printf("Error scanning post: %v", err)
					continue
				}
				post := map[string]interface{}{
					"id":           id,
					"title":        title,
					"body":         body,
					"likeCount":    likeCount,
					"dislikeCount": dislikeCount,
				}
				posts = append(posts, post)
			}

			// Render the create post form
			err = templates.ExecuteTemplate(w, "create_post.html", map[string]interface{}{
				"Categories": categories,
			})
			if err != nil {
				log.Printf("CreatePostHandler: Error rendering template: %v", err)
				http.Error(w, "Error rendering form", http.StatusInternalServerError)
			}

			tmpl := template.Must(template.ParseFiles("views/myposts.html"))
			tmpl.Execute(w, posts)
		}
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
		postID := r.FormValue("post_id") // Ensure this is properly coming from the form
		commentBody := r.FormValue("body")

		if postID == "" || commentBody == "" {
			http.Error(w, "Post ID and comment body cannot be empty", http.StatusBadRequest)
			return
		}

		// Ensure that postID is converted to an integer, like this:
		postIDInt, err := strconv.Atoi(postID)
		if err != nil {
			http.Error(w, "Invalid Post ID", http.StatusBadRequest)
			return
		}

		_, err = database.DB.Exec("INSERT INTO comments (body, post_id, user_id) VALUES (?, ?, ?)", commentBody, postIDInt, userID)
		if err != nil {
			http.Error(w, "Error posting comment", http.StatusInternalServerError)
			log.Printf("Error posting comment: %v", err)
			return
		}

		http.Redirect(w, r, "/posts", http.StatusSeeOther)
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
