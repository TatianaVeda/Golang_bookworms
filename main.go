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
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
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
func GenerateHash(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash)
}

var templates *template.Template

func init() {
	// Ensure all templates are parsed together
	templates = template.Must(template.ParseFiles("views/home.html", "views/posts.html", "views/create_post.html", "views/error.html", "views/myposts.html"))
}

func main() {
	log.Println("Starting database initialization...")

	// Initialize the database
	database.DB = database.ConnectDB()
	defer database.DB.Close()

	err := database.InitDB("./forum.db")
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}
	log.Println("Database initialized successfully!")

	cfg, err := utils.NewConfig()
	if err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	// Handle routes
	http.Handle("/", StripTrailingSlash(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rootHandler(w, r, cfg.DB, cfg.Templates)
	})))

	http.HandleFunc("/login", controllers.LoginUser)
	http.HandleFunc("/register", controllers.RegisterUser)
	http.Handle("/posts", StripTrailingSlash(http.HandlerFunc(controllers.ShowPosts)))
	http.Handle("/posts/create", controllers.RequireSession(http.HandlerFunc(controllers.CreatePostHandler)))
	http.HandleFunc("/logout", controllers.LogoutHandler)
	http.HandleFunc("/posts/comment", controllers.CreateComment)
	http.HandleFunc("/myposts", controllers.MyPostsHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/posts/like", controllers.LikePostHandler)
	http.HandleFunc("/posts/dislike", controllers.DislikePostHandler)
	http.HandleFunc("/posts/update_like_dislike", controllers.UpdateLikeDislikeHandler(database.DB))
	http.HandleFunc("/404", NotFoundHandler)
	http.HandleFunc("/500", InternalServerErrorHandler)
	http.HandleFunc("/test-error", CauseInternalServerError)
	http.HandleFunc("/search", controllers.SearchPosts)

	// Logging setup
	file, err := os.OpenFile("server.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	// log.SetOutput(file) // Enable if you want to log to a file

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
		//Render home page for GET requests
		cookie, err := r.Cookie("session_id")
		isLoggedIn := false
		if err == nil {
			controllers.SessionMutex.Lock()
			_, sessionExists := controllers.SessionStore[cookie.Value]
			controllers.SessionMutex.Unlock()
			if sessionExists {
				isLoggedIn = true
			} else {
				// Ensure that invalid sessions are treated correctly
				isLoggedIn = false
			}
		} else {
			// No session found, treat as not logged in
			isLoggedIn = false
		}

		csrfToken, err := controllers.GenerateAndSetCSRFToken(w, r)
		if err != nil {
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error generating CSRF token.")
			return
		}

		rows, err := db.Query("SELECT id, name FROM categories")
		if err != nil {
			log.Printf("Error fetching categories: %v", err) // Log the exact database error
			utils.RenderErrorPage(w, http.StatusInternalServerError, fmt.Sprintf("Error fetching categories: %v", err))
			return
		}

		defer rows.Close()

		var categories []map[string]interface{}
		for rows.Next() {
			var id int
			var name string
			if err := rows.Scan(&id, &name); err != nil {
				utils.RenderErrorPage(w, http.StatusInternalServerError, "Error scanning categories.")
				return
			}
			categories = append(categories, map[string]interface{}{
				"ID":   id,
				"Name": name,
			})
		}

		// Pass the categories and other data to the template
		data := map[string]interface{}{
			"IsLoggedIn": isLoggedIn,
			"CsrfToken":  csrfToken,
			"Categories": categories, // Include categories in the template data
		}

		tmpl := template.Must(template.ParseFiles(
			"views/home.html",
			"views/auth.html",
			"views/create_post.html",
			"views/categories.html",
		))

		if err := tmpl.Execute(w, data); err != nil {
			log.Printf("Template execution error: %v", err) // Log the exact template error
			utils.RenderErrorPage(w, http.StatusInternalServerError, fmt.Sprintf("Error rendering template: %v", err))
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

func CategoriesHandler(w http.ResponseWriter, r *http.Request) {
	// Fetch categories from the database
	rows, err := database.DB.Query("SELECT id, name FROM categories")
	if err != nil {
		utils.RenderErrorPage(w, http.StatusInternalServerError, "Error fetching categories.")
		return
	}
	defer rows.Close()

	var categories []map[string]interface{}
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error scanning categories.")
			return
		}
		categories = append(categories, map[string]interface{}{
			"ID":   id,
			"Name": name,
		})
	}

	// Pass the categories data to the template
	data := map[string]interface{}{
		"Categories": categories,
	}

	// Serve the categories.html view with data
	tmpl := template.Must(template.ParseFiles("views/categories.html"))
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err) // Log the exact template error
		utils.RenderErrorPage(w, http.StatusInternalServerError, fmt.Sprintf("Error rendering template: %v", err))
	}
}
