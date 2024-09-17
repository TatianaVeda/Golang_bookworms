package main

import (
	"fmt"
	"html/template"
	"literary-lions/controllers"
	"literary-lions/database"
	"literary-lions/utils"
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
	http.HandleFunc("/404", NotFoundHandler)
	http.HandleFunc("/500", InternalServerErrorHandler)
	http.HandleFunc("/test-error", CauseInternalServerError)

	// Start the server
	log.Println("Starting server on http://localhost:8080/")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// rootHandler handles requests to the root path '/'
func rootHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		if r.Method == http.MethodGet {
			HomeHandler(w, r) // Handle homepage requests
		} else {
			http.NotFoundHandler().ServeHTTP(w, r) // Handle non-GET methods
		}
	default:
		http.NotFoundHandler().ServeHTTP(w, r) // Handle unmatched paths
	}
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		// Prevent page from being cached
		w.Header().Set("Cache-Control", "no-store")

		// Handle form submission
		if r.Method == http.MethodPost {
			r.ParseForm()
			action := r.FormValue("action")

			if action == "login" {
				controllers.LoginUser(w, r)
			} else if action == "register" {
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

			// Generate CSRF token
			csrfToken, err := controllers.GenerateAndSetCSRFToken(w, r)
			if err != nil {
				utils.RenderErrorPage(w, http.StatusInternalServerError, "Error generating CSRF token.")
				return
			}

			// Render the homepage
			tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
			data := map[string]interface{}{
				"IsLoggedIn": isLoggedIn,
				"CsrfToken":  csrfToken,
			}
			if err := tmpl.Execute(w, data); err != nil {
				utils.RenderErrorPage(w, http.StatusInternalServerError, "Error rendering homepage.")
			}
		}
	} else {
		http.NotFoundHandler().ServeHTTP(w, r) // Handle non-matching paths
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

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	utils.RenderErrorPage(w, http.StatusNotFound, "Page Not Found")
}

func InternalServerErrorHandler(w http.ResponseWriter, r *http.Request) {
	utils.RenderErrorPage(w, http.StatusInternalServerError, "Internal Server Error")
}

func CauseInternalServerError(w http.ResponseWriter, r *http.Request) {
	// Force an error
	err := fmt.Errorf("deliberate error for testing")
	log.Printf("Forced error: %v", err)
	http.Error(w, "Something went wrong. Please try again later.", http.StatusInternalServerError)
}
