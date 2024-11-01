package controllers

import (
	"fmt"
	"html/template"
	"literary-lions/database"
	"literary-lions/structs"
	"log"
	"net/http"
	"time"
)

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
