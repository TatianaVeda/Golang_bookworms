package main

import (
	"fmt"
	"html/template"
	"literary-lions/controllers"
	"literary-lions/database"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func main() {
	log.Println("Starting database initialization...")
	dsn := "./forum.db" // defining the path to the database

	err := database.InitDB(dsn)
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}
	log.Println("Database initialized successfully!")

	// Load templates (adjust path if needed)
	templates := template.Must(template.ParseGlob("views/*.html"))

	// Set up routes
	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/logout", controllers.LogoutHandler)
	http.HandleFunc("/posts", controllers.ShowPosts)             // Show all posts
	http.HandleFunc("/posts/create", controllers.CreatePost)     // Create post form
	http.HandleFunc("/posts/comment", controllers.CreateComment) // Comment on a post
	http.HandleFunc("/myposts", controllers.MyPostsHandler)      // Add new route for viewing user's posts
	http.HandleFunc("/posts/like", controllers.LikePostHandler)
	http.HandleFunc("/posts/dislike", controllers.DislikePostHandler)
	http.HandleFunc("/categories", CategoriesHandler)
	http.HandleFunc("/profile", controllers.ProfileHandler(templates))

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	// Start the server
	log.Println("Starting server on http://localhost:8080/")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	// Prevent page from being cached
	w.Header().Set("Cache-Control", "no-store")

	// Check if this is a form submission
	if r.Method == http.MethodPost {
		r.ParseForm()
		action := r.FormValue("action")

		if action == "login" {
			// Handle login
			controllers.LoginUser(w, r)

		} else if action == "register" {
			// Handle registration
			controllers.RegisterUser(w, r)

		}
	} else if r.Method == http.MethodGet {

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

		// Use the function to generate and set a CSRF token if necessary
		csrfToken, err := controllers.GenerateAndSetCSRFToken(w, r)
		if err != nil {
			fmt.Fprintf(w, "Error generating CSRF token: %v", err)
			return
		}

		// Render the homepage with modal
		tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html", "views/create_post.html", "views/categories.html"))
		//tmpl := template.Must(template.ParseGlob("views/*.html"))

		data := map[string]interface{}{
			"IsLoggedIn": isLoggedIn,
			"CsrfToken":  csrfToken,
		}

		if err := tmpl.Execute(w, data); err != nil {
			fmt.Fprintf(w, "Error rendering template: %v", err)
		}
	}
}

// Helper function to create a new HTTP request for form data
func newHTTPRequest(method, path string, form url.Values) *http.Request {
	body := strings.NewReader(form.Encode())
	req, err := http.NewRequest(method, path, body)
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func CategoriesHandler(w http.ResponseWriter, r *http.Request) {
	// Serve the categories.html view
	tmpl := template.Must(template.ParseFiles("views/categories.html"))
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "Error rendering categories section", http.StatusInternalServerError)
	}
}
