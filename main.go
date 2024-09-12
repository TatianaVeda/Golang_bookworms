package main

import (
	"fmt"
	"html/template"
	"literary-lions/controllers"
	"literary-lions/database"
	"log"
	"net/http"
)

func main() {
	log.Println("Starting database initialization...")
	err := database.InitDB() // Declare 'err' using ':='
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}
	log.Println("Database initialized successfully!")

	// Set up routes
	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/register", controllers.RegisterUser)
	http.HandleFunc("/login", controllers.LoginUser)
	http.HandleFunc("/home", HomeHandler)
	http.HandleFunc("/posts", controllers.ShowPosts)             // Show all posts
	http.HandleFunc("/posts/create", controllers.CreatePost)     // Create post form
	http.HandleFunc("/posts/comment", controllers.CreateComment) // Comment on a post
	http.HandleFunc("/myposts", controllers.MyPostsHandler)      // Add new route for viewing user's posts

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/posts/like", controllers.LikePostHandler)
	http.HandleFunc("/posts/dislike", controllers.DislikePostHandler)

	// Start the server
	log.Println("Starting server on http://localhost:8080/")
	err = http.ListenAndServe(":8080", nil) // Use '=' here instead of ':='
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	cookie, err := r.Cookie("session_id")
	isLoggedIn := false
	if err == nil {
		controllers.SessionMutex.Lock()
		_, sessionExists := controllers.SessionStore[cookie.Value]
		controllers.SessionMutex.Unlock()

		if sessionExists {
			isLoggedIn = true
		}
	}

	// Render the homepage template
	tmpl := template.Must(template.ParseFiles("views/home.html"))

	// Pass the login status to the template
	data := map[string]interface{}{
		"IsLoggedIn": isLoggedIn,
	}

	if err := tmpl.Execute(w, data); err != nil {
		fmt.Fprintf(w, "Error rendering template: %v", err)
	}
}
