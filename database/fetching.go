package database

import (
	"fmt"
	"literary-lions/structs"
	"log"
)

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

// FetchUserPosts retrieves posts created by a specific user.
func FetchUserPosts(userID int) ([]structs.Post, error) {
	query := `
    SELECT id, title, body, created_at 
    FROM posts 
    WHERE user_id = ?
    ORDER BY created_at DESC
    `

	rows, err := DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []structs.Post
	for rows.Next() {
		var post structs.Post
		if err := rows.Scan(&post.ID, &post.Title, &post.Body, &post.CreatedAt); err != nil {
			return nil, err
		}
		posts = append(posts, post)
	}

	return posts, nil
}

// FetchLikedPosts retrieves posts liked by a user.
func FetchLikedPosts(userID int) ([]map[string]interface{}, error) {
	query := `
		SELECT p.id, p.title, p.body
		FROM posts p
		JOIN likes_dislikes ld ON p.id = ld.post_id
		WHERE ld.user_id = ? AND ld.like_type = 1
	`
	rows, err := DB.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []map[string]interface{}
	for rows.Next() {
		var id int
		var title, body string
		err := rows.Scan(&id, &title, &body)
		if err != nil {
			return nil, err
		}
		post := map[string]interface{}{
			"ID":    id,
			"Title": title,
			"Body":  body,
		}
		posts = append(posts, post)
	}
	return posts, nil
}

func FetchUserComments(userID int) ([]structs.Comment, error) {
	rows, err := DB.Query("SELECT id, body FROM comments WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []structs.Comment
	for rows.Next() {
		var comment structs.Comment
		if err := rows.Scan(&comment.ID, &comment.Body); err != nil {
			return nil, err
		}
		comments = append(comments, comment)
	}
	return comments, nil
}

// FetchLikedComments retrieves comments liked by a user.
func FetchLikedComments(userID int) ([]map[string]interface{}, error) {
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

	// Check for any errors that occurred during the iteration
	if err = rows.Err(); err != nil {
		return nil, err
	}

	fmt.Printf("Fetched liked comments: %+v\n", comments)
	return comments, nil
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

	// Prepare a slice to store posts
	var posts []map[string]interface{}

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

	// Return the posts for the given category
	return posts, nil
}

// FetchProfileData retrieves the profile data for a given username
func FetchProfileData(username string) (structs.ProfileData, error) {
	var profileData structs.ProfileData

	// Example query to get the username and email
	err := DB.QueryRow("SELECT username, email FROM users WHERE username = ?", username).Scan(&profileData.Username, &profileData.Email)
	if err != nil {
		return profileData, err
	}

	// Fetch other profile-related data if needed, like user posts, etc.
	return profileData, nil
}

// FetchCategories retrieves all categories from the database.
func FetchCategories() ([]structs.Category, error) {
	rows, err := DB.Query("SELECT id, name FROM categories")
	if err != nil {
		log.Printf("FetchCategories: Error executing query: %v", err)
		return nil, err
	}
	defer rows.Close()

	// Create a slice to store categories
	var categories []structs.Category

	// Iterate over rows and populate categories slice
	for rows.Next() {
		var category structs.Category
		if err := rows.Scan(&category.ID, &category.Name); err != nil {
			log.Printf("FetchCategories: Error scanning row: %v", err)
			return nil, err
		}
		categories = append(categories, category)
	}

	// Log the fetched categories for debugging
	log.Printf("FetchCategories: Retrieved categories: %+v", categories)

	// Return the categories
	return categories, nil
}

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

	// Scan each row and add it to the slice
	for rows.Next() {
		var id, userID int
		var title, body, createdAt string

		// Scan the row into variables
		if err := rows.Scan(&id, &title, &body, &userID, &createdAt); err != nil {
			log.Printf("Error scanning post row: %v", err)
			return nil, err
		}

		// Prepare a map to hold post data
		post := map[string]interface{}{
			"ID":        id,
			"Title":     title,
			"Body":      body,
			"UserID":    userID,
			"CreatedAt": createdAt,
		}
		posts = append(posts, post)
	}

	// Return all posts
	return posts, nil
}
