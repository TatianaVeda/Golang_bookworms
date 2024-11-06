package database

import (
	"database/sql"
	"fmt"
	"literary-lions/structs"
	"log"
)

//var db *sql.DB

// FetchProfile retrieves a user's profile from the database.
func FetchProfile(userID int) (map[string]interface{}, error) {
	var email, username string
	err := DB.QueryRow("SELECT email, username FROM users WHERE id = ?", userID).Scan(&email, &username)
	if err != nil {
		return nil, err
	}

	profile := map[string]interface{}{
		"Email":    email,
		"Username": username,
	}

	return profile, nil
}

func FetchUserPosts(userID int) ([]structs.Post, error) { // FetchUserPosts retrieves posts created by a specific user.
	query := `
    SELECT posts.id, posts.title, posts.body, posts.created_at, users.username
		FROM posts
		JOIN users ON posts.user_id = users.id
		WHERE posts.user_id = ?
		ORDER BY posts.created_at DESC
    `

	rows, err := DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []structs.Post
	for rows.Next() {
		var post structs.Post
		err := rows.Scan(&post.ID, &post.Title, &post.Body, &post.CreatedAt, &post.UserName)
		if err != nil {
			return nil, err
		}

		post.CreatedAtFormatted = post.CreatedAt.Format("Jan 2, 2006 at 03:04pm")

		posts = append(posts, post)
	}
	return posts, nil
}

func FetchLikedPosts(userID int) ([]structs.Post, error) {
	query := `
		SELECT p.id, p.title, p.body, p.created_at, u.username
		FROM posts p
		JOIN likes_dislikes ld ON p.id = ld.post_id
		JOIN users u ON p.user_id = u.id
		WHERE ld.user_id = ? AND ld.like_type = 1
		ORDER BY p.created_at DESC
	`
	rows, err := DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var likedPosts []structs.Post
	for rows.Next() {
		var post structs.Post
		err := rows.Scan(&post.ID, &post.Title, &post.Body, &post.CreatedAt, &post.UserName)
		if err != nil {
			return nil, err
		}
		post.CreatedAtFormatted = post.CreatedAt.Format("Jan 2, 2006 at 03:04pm")

		likedPosts = append(likedPosts, post)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return likedPosts, nil
}

func FetchUserComments(postID int, userID int) ([]structs.Comment, error) {
	var rows *sql.Rows
	var err error

	// query based on postID or userID
	if postID > 0 {
		query := `SELECT id, body, user_id, post_id, created_at FROM comments WHERE post_id = ? ORDER BY created_at DESC`
		rows, err = DB.Query(query, postID)
	} else if userID > 0 {
		query := `SELECT id, body, user_id, post_id, created_at FROM comments WHERE user_id = ? ORDER BY created_at DESC`
		rows, err = DB.Query(query, userID)
	} else {
		return nil, fmt.Errorf("either postID or userID must be provided")
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []structs.Comment
	for rows.Next() {
		var comment structs.Comment
		// Data scanning
		if err := rows.Scan(&comment.ID, &comment.Body, &comment.UserID, &comment.PostID, &comment.CreatedAt); err != nil {
			return nil, err
		}

		// Fetching username by userID
		err = DB.QueryRow("SELECT username FROM users WHERE id = ?", comment.UserID).Scan(&comment.UserName)
		if err != nil {
			log.Printf("Error fetching poster for comment ID %d: %v", comment.ID, err)
			return nil, err
		}

		// Likes/dislikes counting for comments
		comment.LikeCount, comment.DislikeCount, err = FetchCommentLikesDislikes(comment.ID)
		if err != nil {
			log.Printf("Error fetching likes/dislikes for comment ID %d: %v", comment.ID, err)
		}
		comment.CreatedAtFormatted = comment.CreatedAt.Format("Jan 2, 2006 at 03:04pm")

		comments = append(comments, comment)
	}

	return comments, rows.Err()
}

func FetchLikedComments(userID int) ([]structs.Comment, error) {
	// Query to retrieve liked comments with creation time
	query := `
		SELECT c.id, c.body, c.post_id, c.user_id, c.created_at
		FROM comments c
		JOIN comment_likes cl ON c.id = cl.comment_id
		WHERE cl.user_id = ? AND cl.like_type = 1
		ORDER BY c.created_at DESC
	`
	rows, err := DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []structs.Comment
	for rows.Next() {
		var comment structs.Comment
		// Scan data directly into the Comment struct fields
		if err := rows.Scan(&comment.ID, &comment.Body, &comment.PostID, &comment.UserID, &comment.CreatedAt); err != nil {
			return nil, err
		}

		// Fetch username for each liked comment
		err = DB.QueryRow("SELECT username FROM users WHERE id = ?", comment.UserID).Scan(&comment.UserName)
		if err != nil {
			log.Printf("Error fetching username for comment ID %d: %v", comment.ID, err)
			return nil, err
		}

		// Fetch like counts for each comment,  no comment.DislikeCount
		comment.LikeCount, _, err = FetchCommentLikesDislikes(comment.ID)
		if err != nil {
			log.Printf("Error fetching likes for comment ID %d: %v", comment.ID, err)
		}
		comment.CreatedAtFormatted = comment.CreatedAt.Format("Jan 2, 2006 at 03:04pm")

		comments = append(comments, comment)
	}

	if err = rows.Err(); err != nil { // Check for any errors that occurred during the iteration
		return nil, err
	}

	return comments, nil
}

/* func FetchLikedComments(userID int) ([]map[string]interface{}, error) { // FetchLikedComments retrieves comments liked by a user.
	query := `
		SELECT c.id, c.body, c.post_id
		FROM comments c
		JOIN comment_likes cl ON c.id = cl.comment_id
		WHERE cl.user_id = ? AND cl.like = 1
	`
	rows, err := DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []map[string]interface{}
	for rows.Next() {
		var id, postID int
		var body string
		err := rows.Scan(&id, &body, &postID)
		if err != nil {
			return nil, err
		}
		comment := map[string]interface{}{
			"ID":     id,
			"Body":   body,
			"PostID": postID,
		}
		comments = append(comments, comment)
	}

	if err = rows.Err(); err != nil { // Check for any errors that occurred during the iteration
		return nil, err
	}

	return comments, nil
} */

func FetchCommentLikesDislikes(commentID int) (int, int, error) {
	var likes, dislikes int

	query := `
		SELECT 
			COALESCE(SUM(CASE WHEN like_type = 1 THEN 1 ELSE 0 END), 0), 
			COALESCE(SUM(CASE WHEN like_type = -1 THEN 1 ELSE 0 END), 0)
		FROM comment_likes 
		WHERE comment_id = ?`

	err := DB.QueryRow(query, commentID).Scan(&likes, &dislikes)
	if err != nil {
		return 0, 0, err
	}

	return likes, dislikes, nil
}

func FetchPostsByCategory(categoryID string) ([]map[string]interface{}, error) {
	query := `SELECT id, title, body, COALESCE(user_id, 0) AS user_id, created_at 
	          FROM posts 
	          WHERE category_id = ? 
	          ORDER BY created_at DESC`
	rows, err := DB.Query(query, categoryID)
	if err != nil {
		log.Printf("Error executing SQL query: %v", err)
		return nil, err
	}
	defer rows.Close()

	var posts []map[string]interface{} // Prepare a slice to store posts

	for rows.Next() {
		var id, userID int
		var title, body, createdAt string

		if err := rows.Scan(&id, &title, &body, &userID, &createdAt); err != nil {
			log.Printf("Error scanning post row: %v", err)
			return nil, err
		}

		post := map[string]interface{}{
			"ID":        id,
			"Title":     title,
			"Body":      body,
			"UserID":    userID,
			"CreatedAt": createdAt,
		}

		posts = append(posts, post)
	}

	return posts, nil // Return the posts for the given category
}

func FetchProfileData(username string) (structs.ProfileData, error) { // FetchProfileData retrieves the profile data for a given username
	var profileData structs.ProfileData
	err := DB.QueryRow("SELECT username, email FROM users WHERE username = ?", username).Scan(&profileData.Username, &profileData.Email)
	if err != nil {
		return profileData, err
	}

	return profileData, nil // Fetch other profile-related data if needed, like user posts, etc.
}

func FetchCategories() ([]structs.Category, error) { // FetchCategories retrieves all categories from the database.
	rows, err := DB.Query("SELECT id, name FROM categories")
	if err != nil {
		log.Printf("FetchCategories: Error executing query: %v", err)
		return nil, err
	}
	defer rows.Close()

	var categories []structs.Category // Create a slice to store categories

	for rows.Next() { // Iterate over rows and populate categories slice
		var category structs.Category
		if err := rows.Scan(&category.ID, &category.Name); err != nil {
			log.Printf("FetchCategories: Error scanning row: %v", err)
			return nil, err
		}
		categories = append(categories, category)
	}
	log.Printf("FetchCategories: Retrieved categories: %+v", categories)
	return categories, nil
}
func FetchAllPosts() ([]structs.Post, error) {
	// Use your specific columns here
	query := `SELECT id, title, body, COALESCE(user_id, 0) AS user_id, created_at FROM posts ORDER BY created_at DESC`
	rows, err := DB.Query(query)
	if err != nil {
		log.Printf("Error executing SQL query: %v", err)
		return nil, err
	}
	defer rows.Close()

	// Prepare a slice to store posts
	var posts []structs.Post

	// Scan each row and add it to the slice
	for rows.Next() {
		var post structs.Post

		// Scan the row into variables
		if err := rows.Scan(&post.ID, &post.Title, &post.Body, &post.UserID, &post.CreatedAt); err != nil {
			log.Printf("Error scanning post row: %v", err)
			return nil, err
		}
		post.CreatedAtFormatted = post.CreatedAt.Format("Jan 2, 2006 at 03:04pm")

		posts = append(posts, post)
	}

	// Return all posts
	return posts, nil
}

/*
func FetchAllPosts() ([]map[string]interface{}, error) {
	// Use your specific columns here
	query := `SELECT id, title, body, COALESCE(user_id, 0) AS user_id, created_at FROM posts ORDER BY created_at DESC`
	rows, err := DB.Query(query)
	if err != nil {
		log.Printf("Error executing SQL query: %v", err)
		return nil, err
	}
	defer rows.Close()

	// Prepare a slice to store posts
	var posts []map[string]interface{}
	for rows.Next() { // Scan each row and add it to the slice
		var id, userID int
		var title, body, createdAt string

		if err := rows.Scan(&id, &title, &body, &userID, &createdAt); err != nil { // Scan the row into variables
			log.Printf("Error scanning post row: %v", err)
			return nil, err
		}

		post := map[string]interface{}{ // Prepare a map to hold post data
			"ID":        id,
			"Title":     title,
			"Body":      body,
			"UserID":    userID,
			"CreatedAt": createdAt,
		}
		posts = append(posts, post)
	}

	return posts, nil // Return all posts
} */
