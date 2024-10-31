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
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func StripTrailingSlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

var tmpl *template.Template
var tmpl404 *template.Template
var DB *sql.DB

func init() {
	tmpl = template.Must(template.ParseGlob("views/*.html"))
	tmpl404 = template.Must(template.ParseFiles("views/404.html"))
}

func RequireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("Checking for session cookie...")
		cookie, err := r.Cookie("session_id")
		if err != nil {
			log.Printf("No session cookie found: %v", err)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Lock to prevent race conditions
		controllers.SessionMutex.Lock()
		userID, sessionExists := controllers.SessionStore[cookie.Value]
		controllers.SessionMutex.Unlock()

		if !sessionExists {
			log.Println("Invalid session, redirecting to login.")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		log.Printf("Valid session for user ID: %d", userID)
		next.ServeHTTP(w, r)
	}
}

func main() {
	log.Println("Starting database initialization...")
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

	http.Handle("/", StripTrailingSlash(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rootHandler(w, r, cfg.DB, tmpl) // Use tmpl here
	})))
	http.Handle("/posts/create", controllers.RequireSession(EnforceMethod(controllers.CreatePostHandler, http.MethodPost)))
	http.Handle("/posts/comment", controllers.RequireSession(EnforceMethod(controllers.CreateComment, http.MethodPost)))
	http.Handle("/posts/like", EnforceMethod(controllers.LikePostHandler, http.MethodPost))
	http.Handle("/posts/dislike", EnforceMethod(controllers.DislikePostHandler, http.MethodPost))
	http.Handle("/posts/update_like_dislike", EnforceMethod(controllers.UpdateLikeDislikeHandler(database.DB), http.MethodPost))
	http.Handle("/posts", StripTrailingSlash(http.HandlerFunc(controllers.ShowPosts)))
	http.HandleFunc("/login", RedirectToHomeIfDirectAccess(controllers.LoginUser))
	http.HandleFunc("/register", RedirectToHomeIfDirectAccess(controllers.RegisterUser))
	http.HandleFunc("/logout", controllers.LogoutHandler)
	http.Handle("/like_comment", controllers.RequireSession(EnforceMethod(controllers.LikeComment, http.MethodPost)))
	http.HandleFunc("/search", controllers.SearchPosts)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/404", NotFoundHandler)
	http.HandleFunc("/500", InternalServerErrorHandler)
	http.HandleFunc("/test-error", CauseInternalServerError)

	file, err := os.OpenFile("server.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	log.Println("Starting server on http://localhost:8080/")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func EnforceMethod(handlerFunc http.HandlerFunc, method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			NotFoundHandler(w, r)
			return
		}
		handlerFunc(w, r)
	}
}

func RedirectToHomeIfDirectAccess(handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		handlerFunc(w, r) // Proceed with handler function for POST requests
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request, db *sql.DB, templates *template.Template) {
	switch r.URL.Path {
	case "/":
		if r.Method == http.MethodGet || r.Method == http.MethodPost {
			HomeHandler(w, r, db, templates)
		} else {
			NotFoundHandler(w, r) // Handle other methods on root
		}
	case "/posts":
		controllers.ShowPosts(w, r)
	case "/profile":
		controllers.ProfileHandler(templates)(w, r)
	case "/	search":
		controllers.SearchPosts(w, r)
	default:
		NotFoundHandler(w, r) // Call the custom 404 handler for undefined paths
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

		cookie, err := r.Cookie("session_id") //Render home page for GET requests
		isLoggedIn := false
		if err == nil {
			controllers.SessionMutex.Lock()
			_, sessionExists := controllers.SessionStore[cookie.Value]
			controllers.SessionMutex.Unlock()
			if sessionExists {
				isLoggedIn = true
			} else {

				isLoggedIn = false // Ensure that invalid sessions are treated correctly
			}
		} else {

			isLoggedIn = false // No session found, treat as not logged in
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

		data := map[string]interface{}{ // Pass the categories and other data to the template
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

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	if err := tmpl404.Execute(w, nil); err != nil {
		log.Printf("Error rendering 404 template: %v", err)
		http.Error(w, "404 - Page Not Found", http.StatusNotFound)
	}
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
	rows, err := database.DB.Query("SELECT id, name FROM categories") // Fetch categories from the database
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

	data := map[string]interface{}{ // Pass the categories data to the template
		"Categories": categories,
	}

	tmpl := template.Must(template.ParseFiles("views/categories.html")) // Serve the categories.html view with data
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execution error: %v", err) // Log the exact template error
		utils.RenderErrorPage(w, http.StatusInternalServerError, fmt.Sprintf("Error rendering template: %v", err))
	}
}
