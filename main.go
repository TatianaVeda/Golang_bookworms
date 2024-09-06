package main

import (
	"fmt"
	"literary-lions/controllers"
	"literary-lions/database"
	"log"
	"net/http"
)

func main() {
	// Log statement before initializing the database
	log.Println("Starting database initialization...")

	// Initialize the database (this will create tables if they don't exist)
	if err := database.InitDB(); err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}

	// Log after DB initialization
	log.Println("Database initialized successfully!")

	// Set up the routes for the server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Literary Lions!")
	})
	http.HandleFunc("/register", controllers.RegisterUser)
	http.HandleFunc("/login", controllers.LoginUser)
	http.HandleFunc("/home", HomeHandler) // Example of a protected route

	// Serve static files (like CSS or images)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Start the HTTP server
	log.Println("Starting server on http://localhost:8080/")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// HomeHandler is an example of a protected route
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	// Logic for checking if the user is logged in can go here
	w.Write([]byte("Welcome to the home page!"))
}
