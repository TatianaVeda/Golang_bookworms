package main

import (
	"database/sql"
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

func StripTrailingSlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only modify if it's not the root path
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, strings.TrimSuffix(r.URL.Path, "/"), http.StatusMovedPermanently)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	log.Println("Starting database initialization...")
	err := database.InitDB()
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}
	log.Println("Database initialized successfully!")

	cfg, err := utils.NewConfig()
	if err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	http.Handle("/", StripTrailingSlash(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rootHandler(w, r, cfg.DB, cfg.Templates)
	})))

	http.Handle("/posts", StripTrailingSlash(http.HandlerFunc(controllers.ShowPosts)))
	http.Handle("/posts/create", StripTrailingSlash(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controllers.CreatePost(w, r, cfg.DB, cfg.Templates)
	})))

	http.HandleFunc("/logout", controllers.LogoutHandler)
	http.HandleFunc("/posts/comment", controllers.CreateComment)
	http.HandleFunc("/myposts", controllers.MyPostsHandler)
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

// rootHandler processes the root path '/'
func rootHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, templates *template.Template) {
	switch r.URL.Path {
	case "/":
		if r.Method == http.MethodGet || r.Method == http.MethodPost {
			HomeHandler(w, r, db, templates) // Pass db and templates to HomeHandler
		} else {
			http.NotFoundHandler().ServeHTTP(w, r) // Handle non-GET methods
		}
	default:
		http.NotFoundHandler().ServeHTTP(w, r) // Handle unmatched paths
	}
}

// HomeHandler handles the homepage logic
func HomeHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, templates *template.Template) {
	log.Printf("Received request with method: %s", r.Method)
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost {
		r.ParseForm()
		action := r.FormValue("action")

		if action == "login" {
			controllers.LoginUser(w, r) // Process login
			return
		} else if action == "register" {
			controllers.RegisterUser(w, r) // Process registration
			return
		}
	} else if r.Method == http.MethodGet {
		// Render home page for GET requests
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

		csrfToken, err := controllers.GenerateAndSetCSRFToken(w, r)
		if err != nil {
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error generating CSRF token.")
			return
		}

		tmpl := template.Must(template.ParseFiles("views/home.html", "views/auth.html"))
		data := map[string]interface{}{
			"IsLoggedIn": isLoggedIn,
			"CsrfToken":  csrfToken,
		}
		if err := tmpl.Execute(w, data); err != nil {
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error rendering homepage.")
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

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	utils.HandleError(w, http.StatusNotFound, "Page Not Found")
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
