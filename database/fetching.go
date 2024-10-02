package database

import (
	"fmt"
	"literary-lions/structs"
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
func FetchUserPosts(userID int) ([]map[string]interface{}, error) {
	rows, err := DB.Query("SELECT id, title, body FROM posts WHERE user_id = ?", userID)
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
		var id, postID int64
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

func FetchPostCategories(postID int) ([]structs.Category, error) {
	query := `
		SELECT c.id, c.name
		FROM categories c
		JOIN post_categories pc ON c.id = pc.category_id
		WHERE pc.post_id = ?`
	rows, err := DB.Query(query, postID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var categories []structs.Category
	for rows.Next() {
		var category structs.Category
		if err := rows.Scan(&category.ID, &category.Name); err != nil {
			return nil, err
		}
		categories = append(categories, category)
	}
	return categories, nil
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
