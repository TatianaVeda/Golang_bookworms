package main

import (
	"fmt"
	"literary-lions/database"
	"log"
	"net/http"
)

func main() {
	// Log statement before initializing the database
	log.Println("Starting database initialization...")

	// Initialize the database (this will create tables if they don't exist)
	database.InitDB()

	// Log after DB initialization
	log.Println("Database initialized successfully!")

	// Start your web server or application logic
	log.Println("Starting server on http://localhost:8080/")
	//fmt.Println("Server starting on port 8080...")

	// Add some dummy HTTP handler for testing
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, Literary Lions!")
	})

	// Run the HTTP server (if your project has any)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
