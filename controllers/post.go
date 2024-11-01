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
	"strings"
	"time"
)

var DB *sql.DB

func PostsHandler(db *sql.DB, templates *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set headers to prevent caching
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		isLoggedIn := false
		if _, err := r.Cookie("session_id"); err == nil {
			isLoggedIn = true
		}

		// Retrieve the category ID from the URL query
		categoryID := r.URL.Query().Get("category")
		if categoryID == "" {
			log.Println("Category ID is missing in the request")
			utils.RenderErrorPage(w, http.StatusBadRequest, "Category ID is required for filtering.")
			return
		}

		// Convert category ID to integer
		// Convert category ID to integer
		categoryIDInt, err := strconv.Atoi(categoryID)
		if err != nil {
			log.Printf("Invalid category ID: %s", categoryID)
			utils.RenderErrorPage(w, http.StatusBadRequest, "Invalid Category ID.")
			return
		}

		// Get category name from database
		var categoryName string
		err = db.QueryRow("SELECT name FROM categories WHERE id = ?", categoryIDInt).Scan(&categoryName)
		if err != nil {
			log.Printf("Error fetching category name for ID %d: %v", categoryIDInt, err)
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error fetching category name.")
			return
		}

		log.Printf("CategoryName: %s", categoryName)

		// Fetch posts from the database
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

		userID, err := GetUserIDFromSession(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		var posts []structs.Post
		for rows.Next() {
			var post structs.Post
			err := rows.Scan(&post.ID, &post.Title, &post.Body, &post.UserName, &post.CreatedAt)
			if err != nil {
				log.Printf("Error scanning post for category '%s': %v", categoryID, err)
				continue
			}
			// getting comments for posts
			post.Comments, err = database.FetchUserComments(post.ID, userID)
			if err != nil {
				log.Printf("Error fetching comments for post ID %d: %v", post.ID, err)
			}

			posts = append(posts, post)
		}

		log.Printf("Posts: %+v", posts)

		if err = rows.Err(); err != nil {
			log.Printf("Error iterating through posts for category '%s': %v", categoryID, err)
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error processing posts.")
			return
		}

		// Render the template with posts and login status
		err = templates.ExecuteTemplate(w, "posts.html", map[string]interface{}{
			"Posts":        posts, // Use the 'posts' variable here
			"CategoryName": categoryName,
			"IsLoggedIn":   isLoggedIn,
		})
		if err != nil {
			log.Printf("Template execution error for category '%s': %v", categoryID, err)
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error rendering posts template.")
		}
	}
}

func ShowPosts(w http.ResponseWriter, r *http.Request) {
	categoryID := r.URL.Query().Get("category") // Get the category ID from the query string
	var rows *sql.Rows
	var err error
	var categoryName string
	isLoggedIn := false

	cookie, sessErr := r.Cookie("session_id")
	if sessErr == nil {
		sessionID := cookie.Value
		sessionUserID, sessionErr := VerifySession(sessionID) // Verify the session
		if sessionErr == nil && sessionUserID > 0 {
			isLoggedIn = true
		}
	}

	categoryIDInt := 0
	if categoryID != "" {
		categoryIDInt, err = strconv.Atoi(categoryID) // 	Convert the category ID to an integer
		if err != nil {
			http.Error(w, "Invalid Category ID", http.StatusBadRequest)
			return
		}
	}

	// Prepare SQL query for posts
	query := `
    SELECT posts.id, posts.title, posts.body, users.username, categories.name, 
           IFNULL(likes_table.likes, 0) AS LikeCount, 
           IFNULL(likes_table.dislikes, 0) AS DislikeCount,
		   posts.created_at
		    
	FROM posts
    JOIN users ON posts.user_id = users.id
    JOIN categories ON posts.category_id = categories.id
    LEFT JOIN (
        SELECT post_id,
            SUM(CASE WHEN like_type = 1 THEN 1 ELSE 0 END) AS likes,
            SUM(CASE WHEN like_type = -1 THEN 1 ELSE 0 END) AS dislikes
        FROM likes_dislikes
        GROUP BY post_id
    ) AS likes_table ON posts.id = likes_table.post_id
	`

	// Add condition for category filtering if a category is selected
	if categoryIDInt > 0 {
		//log.Printf("Executing query: %s with categoryID: %d", query, categoryIDInt)
		query += " WHERE posts.category_id = ? ORDER BY posts.created_at DESC"
		rows, err = database.DB.Query(query, categoryIDInt)
	} else {
		query += " ORDER BY posts.created_at DESC"
		rows, err = database.DB.Query(query)
	}

	if err != nil {
		http.Error(w, "Error fetching posts", http.StatusInternalServerError)
		log.Printf("Database query error: %v", err)
		return
	}

	defer rows.Close()

	if categoryIDInt > 0 {
		err = database.DB.QueryRow("SELECT name FROM categories WHERE id = ?", categoryIDInt).Scan(&categoryName)
		if err != nil {
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	} else {
		categoryName = "All Categories"
	}

	defer rows.Close() // 	Close the rows

	var posts []structs.Post
	for rows.Next() {
		var post structs.Post
		err := rows.Scan(&post.ID, &post.Title, &post.Body, &post.UserName, &post.CategoryName, &post.LikeCount, &post.DislikeCount, &post.CreatedAt) //Scan the rows into the post struct
		if err != nil {
			log.Printf("Error scanning posts: %v", err)
			continue
		}

		// Fetch comments for the post
		post.Comments, err = database.FetchUserComments(post.ID, 0)
		if err != nil {
			log.Printf("Error fetching comments for post ID %d: %v", post.ID, err)
			continue
		}
		for i := range post.Comments {
			post.Comments[i].CreatedAtFormatted = post.Comments[i].CreatedAt.Format("2006-01-02 15:04:05 +0200 UTC")
		}

		posts = append(posts, post)
	}

	if err = rows.Err(); err != nil {
		http.Error(w, "Error processing posts", http.StatusInternalServerError)
		return
	}

	tmpl := template.Must(template.ParseFiles("views/posts.html")) // 	Parse the template
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

func ProfileHandler(templates *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := GetSession(r) // 	Get the user ID from the session
		if err != nil {
			fmt.Println("Get session error:", err)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		fmt.Printf("Session retrieved successfully. UserID: %d\n", userID)

		username := database.GetUserNameByID(userID)
		if username == "Unknown" {
			http.Error(w, "Error fetching username", http.StatusInternalServerError)
			return
		}

		profileUsername := r.URL.Query().Get("username") // Get the username from the query string
		if profileUsername == "" {
			profileUsername = username
		}

		profileData, err := database.FetchProfileData(profileUsername) // 	Fetch the profile data
		if err != nil {
			http.Error(w, "Error fetching profile", http.StatusInternalServerError)
			return
		}

		profileUserID, err := database.GetUserID(profileUsername) // 	Get the user ID from the database
		if err != nil {
			http.Error(w, "Error fetching user ID", http.StatusInternalServerError)
			return
		}

		userPosts, err := database.FetchUserPosts(userID) // 	Fetch the user's posts
		if err != nil {
			http.Error(w, "Error fetching user posts", http.StatusInternalServerError)
			return
		}
		profileData.Posts = userPosts

		// Fetch user comments
		comments, err := database.FetchUserComments(0, profileUserID)
		if err != nil {
			http.Error(w, "Error fetching comments", http.StatusInternalServerError)
			return
		}

		profileData.Comments = comments

		//If the user is viewing their own profile
		if profileUserID == userID {
			likedPosts, err := database.FetchLikedPosts(userID)
			if err != nil {
				http.Error(w, "Error fetching liked posts", http.StatusInternalServerError)
				return
			}

			var likedPostsConverted []structs.Post
			for _, postMap := range likedPosts {
				post := structs.Post{
					ID:        postMap["ID"].(int),
					Title:     postMap["Title"].(string),
					Body:      postMap["Body"].(string),
					CreatedAt: postMap["CreatedAt"].(time.Time),
					UserName:  postMap["UserName"].(string),
				}
				likedPostsConverted = append(likedPostsConverted, post)
			}
			profileData.LikedPosts = likedPostsConverted

			//Add the liked posts to the profile data
			likedComments, err := database.FetchLikedComments(userID)
			if err != nil {
				http.Error(w, "Error fetching liked comments", http.StatusInternalServerError)
				return
			}
			profileData.LikedComments = likedComments //Converted
		}

		// Render the profile template
		err = templates.ExecuteTemplate(w, "profile.html", map[string]interface{}{
			"ProfileData": profileData,
			"LoggedUser":  username,
		})
		if err != nil {
			http.Error(w, "Error rendering profile template", http.StatusInternalServerError)
			log.Printf("Error rendering profile template: %v", err)
		}
	}
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

func LikePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		userID, err := GetSession(r)
		if err != nil {
			log.Println("LikePostHandler: User not logged in, redirecting to login.")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		postID := r.FormValue("post_id") // 	Get the post ID from the form
		if postID == "" {
			log.Println("LikePostHandler: Invalid post ID received.")
			http.Error(w, "Invalid post ID", http.StatusBadRequest)
			return
		}

		log.Printf("LikePostHandler: Received post_id = %s for user_id = %d", postID, userID)

		var existingLikeType int // 	Check if the user has already liked or disliked the post
		err = database.DB.QueryRow("SELECT like_type FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID).Scan(&existingLikeType)
		if err == sql.ErrNoRows {
			log.Println("LikePostHandler: No previous like/dislike found, inserting a new like.")
			_, err = database.DB.Exec("INSERT INTO likes_dislikes (post_id, user_id, like_type) VALUES (?, ?, 1)", postID, userID)
		} else if existingLikeType == -1 {
			log.Println("LikePostHandler: Previously disliked, changing to like.")
			_, err = database.DB.Exec("UPDATE likes_dislikes SET like_type = 1 WHERE post_id = ? AND user_id = ?", postID, userID)
		} else if existingLikeType == 1 {
			log.Println("LikePostHandler: Already liked, removing like.")
			_, err = database.DB.Exec("DELETE FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID)
		}

		if err != nil {
			log.Printf("LikePostHandler: Error modifying like/dislike: %v", err)
			http.Error(w, "Error processing like action", http.StatusInternalServerError)
			return
		}

		categoryID := r.URL.Query().Get("category") // 	Get the category ID from the query string
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
		userID, err := GetSession(r)
		if err != nil {
			log.Println("LikePostHandler: User not logged in, redirecting to login.")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		postID := r.FormValue("post_id") // 	Get the post ID from the form
		if postID == "" {                // 	Validate the post ID
			log.Println("DislikePostHandler: Invalid post ID received.")
			http.Error(w, "Invalid post ID", http.StatusBadRequest)
			return
		}
		log.Printf("DislikePostHandler: Received post_id = %s for user_id = %d", postID, userID)

		var existingLikeType int                                                                                                                     // 	Check if the user has already liked or disliked the post
		err = database.DB.QueryRow("SELECT like_type FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID).Scan(&existingLikeType) // 	Get the like type from the database
		if err == sql.ErrNoRows {
			log.Println("DislikePostHandler:: No previous like/dislike found, inserting a new like.")
			_, err = database.DB.Exec("INSERT INTO likes_dislikes (post_id, user_id, like_type) VALUES (?, ?, -1)", postID, userID)
		} else if existingLikeType == 1 {
			log.Println("DislikePostHandler:: Already liked, removing like.")
			// Remove like if the same button is clicked
			_, err = database.DB.Exec("DELETE FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID)
			//_, err = database.DB.Exec("UPDATE likes_dislikes SET like_type = -1 WHERE post_id = ? AND user_id = ?", postID, userID)
		} else if existingLikeType == -1 {
			log.Println("DislikePostHandler:: Previously disliked, changing to like.")
			_, err = database.DB.Exec("DELETE FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID)
		}

		if err != nil {
			log.Printf("DislikePostHandler:: Error modifying like/dislike: %v", err)
			http.Error(w, "Error processing dislike action", http.StatusInternalServerError)
			return
		}

		categoryID := r.URL.Query().Get("category") // 	Get the category ID from the query string
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

		if r.Method != http.MethodPost {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		userID, err := GetSession(r)
		if err != nil {
			http.Error(w, "Unauthorized. Please log in.", http.StatusUnauthorized)
			log.Println("Unauthorized request - session not found")
			return
		}

		// Retrieve form values for post_id and like_type
		postIDStr := r.FormValue("post_id")
		likeTypeStr := r.FormValue("like_type")
		categoryIDStr := r.FormValue("category_id")

		// Log incoming form values for debugging
		log.Printf("Incoming form values: post_id=%s, like_type=%s", postIDStr, likeTypeStr) //, categoryIDStr, category_id=%s

		// Convert form values to integers
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

		// Check if the user has already liked or disliked the post
		var existingLikeType int
		err = db.QueryRow("SELECT like_type FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID).Scan(&existingLikeType)

		if err == sql.ErrNoRows { // No existing like/dislike, insert a new record
			_, err = db.Exec("INSERT INTO likes_dislikes (post_id, user_id, like_type) VALUES (?, ?, ?)", postID, userID, likeType)
			if err != nil {
				http.Error(w, "Error inserting new like/dislike", http.StatusInternalServerError)
				log.Println("Error inserting new like/dislike:", err)
				return
			}
		} else if existingLikeType == likeType { // If the user clicks the same button again, remove the like/dislike
			_, err = db.Exec("DELETE FROM likes_dislikes WHERE post_id = ? AND user_id = ?", postID, userID)
			if err != nil {
				http.Error(w, "Error removing like/dislike", http.StatusInternalServerError)
				log.Println("Error removing like/dislike:", err)
				return
			}
		} else { // Update the like/dislike to switch from like to dislike or vice versa
			_, err = db.Exec("UPDATE likes_dislikes SET like_type = ? WHERE post_id = ? AND user_id = ?", likeType, postID, userID)
			if err != nil {
				http.Error(w, "Error updating like/dislike", http.StatusInternalServerError)
				log.Println("Error updating like/dislike:", err)
				return
			}
		}

		var likeCount, dislikeCount int // Retrieve updated like and dislike counts
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
		//categoryID := r.URL.Query().Get("category")
		// Pass the updated counts back to the ShowPosts handler for the correct category
		log.Printf("Updated counts for post %d: Likes = %d, Dislikes = %d", postID, likeCount, dislikeCount) // Redirect back to the specific post or category page with the updated counts

		categoryID := categoryIDStr // Redirect back to the referring page or posts list
		if categoryID != "" {
			http.Redirect(w, r, fmt.Sprintf("/posts?category=%s#post-%d", categoryID, postID), http.StatusSeeOther)
		} else {
			http.Redirect(w, r, fmt.Sprintf("/posts#post-%d", postID), http.StatusSeeOther)
		}
	}
}

func SearchPosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		log.Println("Invalid request method; redirecting to homepage.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet && r.URL.Query().Get("keywords") == "" {
		log.Println("Direct access to /search without query; redirecting to homepage.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing form: %v", err)
		utils.RenderErrorPage(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	query := r.FormValue("keywords") // Retrieve search parameters from the form (POST) or query string (GET)
	category := r.FormValue("category")
	author := r.FormValue("author")
	startDate := r.FormValue("start_date")
	endDate := r.FormValue("end_date")

	log.Printf("Received search query: keywords=%s, category=%s, author=%s, startDate=%s, endDate=%s", query, category, author, startDate, endDate)

	if query == "" { // Redirect to homepage if the search query is empty
		log.Println("Empty search query; redirecting to homepage.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	queryStr := `
        SELECT posts.id, posts.title, posts.body, users.username, posts.created_at
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE (posts.title LIKE ? OR posts.body LIKE ?)
    `
	params := []interface{}{"%" + query + "%", "%" + query + "%"}

	if category != "" { // Apply filters if they exist
		queryStr += " AND posts.category = ?"
		params = append(params, category)
	}
	if author != "" {
		queryStr += " AND users.username LIKE ?"
		params = append(params, "%"+author+"%")
	}
	if startDate != "" {
		queryStr += " AND posts.created_at >= ?"
		startDateParsed, _ := time.Parse("2006-01-02", startDate)
		params = append(params, startDateParsed)
	}
	if endDate != "" {
		queryStr += " AND posts.created_at <= ?"
		endDateParsed, _ := time.Parse("2006-01-02", endDate)
		params = append(params, endDateParsed)
	}

	log.Printf("Executing SQL query: %s with params: %v", queryStr, params)
	rows, err := database.DB.Query(queryStr, params...)
	if err != nil {
		log.Printf("Error executing query: %v", err)
		utils.RenderErrorPage(w, http.StatusInternalServerError, "Error fetching search results.")
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int
		var title, body, username string
		var createdAt string
		if err := rows.Scan(&id, &title, &body, &username, &createdAt); err != nil {
			log.Printf("Error scanning search results: %v", err)
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error scanning search results.")
			return
		}
		results = append(results, map[string]interface{}{
			"ID":        id,
			"Title":     title,
			"Body":      body,
			"Author":    username,
			"CreatedAt": createdAt,
		})
	}

	data := map[string]interface{}{
		"Query":   query,
		"Results": results,
	}

	tmpl := template.Must(template.ParseFiles("views/search_results.html"))
	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Error rendering template: %v", err)
		utils.RenderErrorPage(w, http.StatusInternalServerError, "Error displaying results.")
	}
}

func CreatePostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	userID, err := GetUserIDFromSession(r)
	if err != nil {
		http.Error(w, "Unauthorized. Please log in.", http.StatusUnauthorized)
		return
	}
	// Retrieve form values
	title := r.FormValue("title")
	body := r.FormValue("body")
	categoryID := r.FormValue("category_id")

	if title == "" || body == "" || categoryID == "" { //If any of the form values are empty, return an error
		http.Error(w, "Title, body, and category cannot be empty", http.StatusBadRequest)
		return
	}
	// Insert post into the database
	result, err := database.DB.Exec("INSERT INTO posts (title, body, user_id, category_id) VALUES (?, ?, ?, ?)", title, body, userID, categoryID)
	if err != nil {
		log.Printf("Error inserting new post: %v", err)
		http.Error(w, "Unable to create post", http.StatusInternalServerError)
		return
	}
	log.Printf("Post created successfully: Title: %s | Body: %s | CategoryID: %s", title, body, categoryID)
	// Get the last inserted post ID (for potential debugging purposes)
	postID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Error retrieving last insert ID: %v", err)
	} else {
		log.Printf("Successfully inserted post with ID: %d", postID)
	}
	// Redirect to the category page
	http.Redirect(w, r, fmt.Sprintf("/posts?category=%s", categoryID), http.StatusSeeOther)

}

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

/* func MyPostsHandler(w http.ResponseWriter, r *http.Request) {
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

	query := `
		SELECT posts.id, posts.title, posts.body,
		       COALESCE(categories.name, 'Uncategorized') AS category_name
		FROM posts
		LEFT JOIN categories ON posts.category_id = categories.id
		WHERE posts.user_id = ?
	`
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

func FilterPostsByCategory(w http.ResponseWriter, r *http.Request) {
	categoryID := r.URL.Query().Get("category")
	log.Printf("Category ID Received from URL: %s", categoryID)

	categoryIDInt, err := strconv.Atoi(categoryID)
	if err != nil {
		log.Printf("Invalid category ID: %s", categoryID)
		utils.RenderErrorPage(w, http.StatusBadRequest, "Invalid Category ID.")
		return
	}

	log.Printf("Received request to filter posts for category ID: %d", categoryIDInt)

	query := `
    SELECT posts.id, posts.title, posts.body, users.username, posts.created_at, categories.name 
    FROM posts
    JOIN users ON posts.user_id = users.id
    JOIN categories ON posts.category_id = categories.id
`
	log.Printf("Executing SQL query: %s with category ID: %d", query, categoryIDInt)

	rows, err := database.DB.Query(query, categoryIDInt)
	if err != nil {
		log.Printf("Database query error for category '%d': %v", categoryIDInt, err)
		utils.RenderErrorPage(w, http.StatusInternalServerError, "Error retrieving posts.")
		return
	}
	defer rows.Close()

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

	if err = rows.Err(); err != nil {
		log.Printf("Error encountered during rows iteration: %v", err)
	}

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

	log.Printf("Category Name Retrieved: %s", categoryName)

	tmplData := structs.TemplateData{
		Posts:        posts,
		CategoryName: categoryName,
	}

	log.Printf("Template Data Prepared: %+v", tmplData)

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

	postIDStr := strings.TrimPrefix(r.URL.Path, "/posts/delete/")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil || postID <= 0 {
		http.Error(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	userID, err := GetUserIDFromSession(r)
	if err != nil {
		http.Error(w, "Unauthorized. Please log in.", http.StatusUnauthorized)
		return
	}

	var ownerID int
	err = database.DB.QueryRow("SELECT user_id FROM posts WHERE id = ?", postID).Scan(&ownerID)
	if err != nil {
		http.Error(w, "Post not found or you don't have permission to delete", http.StatusForbidden)
		return
	}

	if ownerID != userID {
		http.Error(w, "You don't have permission to delete this post", http.StatusForbidden)
		return
	}

	_, err = database.DB.Exec("DELETE FROM posts WHERE id = ?", postID)
	if err != nil {
		http.Error(w, "Unable to delete post", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/posts", http.StatusSeeOther)
}
