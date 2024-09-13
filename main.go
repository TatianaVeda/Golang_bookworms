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
	err := database.InitDB()
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}
	log.Println("Database initialized successfully!")

	// Set up routes
	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/logout", controllers.LogoutHandler)
	http.HandleFunc("/posts", controllers.ShowPosts)             // Show all posts
	http.HandleFunc("/posts/create", controllers.CreatePost)     // Create post form
	http.HandleFunc("/posts/comment", controllers.CreateComment) // Comment on a post
	http.HandleFunc("/myposts", controllers.MyPostsHandler)      // Add new route for viewing user's posts
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/posts/like", controllers.LikePostHandler)
	http.HandleFunc("/posts/dislike", controllers.DislikePostHandler)

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

	if r.Method == http.MethodPost {
		r.ParseForm()
		csrfToken := r.FormValue("csrf_token")
		action := r.FormValue("action")

		cookieToken, _ := controllers.GetCSRFCookie(r)
		if csrfToken != cookieToken {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		if action == "login" {
			// Create a simulated request for the login handler
			loginRequest := newHTTPRequest("POST", "/login", r.Form)
			controllers.LoginUser(w, loginRequest)
			isLoggedIn = true // Update login status if successful
		} else if action == "register" {
			// Create a simulated request for the registration handler
			registerRequest := newHTTPRequest("POST", "/register", r.Form)
			controllers.RegisterUser(w, registerRequest)
			isLoggedIn = true // Update login status if successful
		}

		// Redirect to home to avoid resubmission of form
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Generate a CSRF token
	csrfToken, err := controllers.GenerateCSRFToken()
	if err != nil {
		fmt.Fprintf(w, "Error generating CSRF token: %v", err)
		return
	}
	controllers.SetCSRFCookie(w, csrfToken)

	// Render the homepage template
	tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))

	data := map[string]interface{}{
		"IsLoggedIn": isLoggedIn,
		"CsrfToken":  csrfToken,
	}

	if err := tmpl.ExecuteTemplate(w, "home.html", data); err != nil {
		fmt.Fprintf(w, "Error rendering template: %v", err)
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
