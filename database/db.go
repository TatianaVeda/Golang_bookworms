package database

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3" // SQLite driver for Go
)

var DB *sql.DB

// InitDB initializes the SQLite database connection and runs schema creation queries.
func InitDB() error { // Changed the return type to error
	var err error

	log.Println("Connecting to the SQLite database...")

	// Assign to the global DB variable, not a local one
	DB, err = sql.Open("sqlite3", "./forum.db")
	if err != nil {
		return err // Return error instead of using log.Fatalf to let caller handle it
	}

	// Check if the connection is valid
	log.Println("Pinging the database...")
	err = DB.Ping()
	if err != nil {
		return err
	}

	// Call schema creation function to create all necessary tables
	log.Println("Creating database schema...")
	createSchema()
	log.Println("Database schema created successfully!")

	return nil // Return nil to indicate success
}

// createSchema defines and executes the SQL schema to create the necessary tables
func createSchema() {
	// Users table already exists

	// Schema for creating Posts table
	postsTable := `
	CREATE TABLE IF NOT EXISTS posts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		body TEXT NOT NULL,
		user_id INTEGER,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`
	execSchemaQuery(postsTable)

	// Schema for creating Comments table
	commentsTable := `
	CREATE TABLE IF NOT EXISTS comments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		body TEXT NOT NULL,
		post_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(post_id) REFERENCES posts(id),
		FOREIGN KEY(user_id) REFERENCES users(id)
	);`
	execSchemaQuery(commentsTable)

	likesDislikesTable := `
	CREATE TABLE IF NOT EXISTS likes_dislikes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		post_id INTEGER,
		like_type INTEGER CHECK(like_type IN (1, -1)),
		FOREIGN KEY(user_id) REFERENCES users(id),
		FOREIGN KEY(post_id) REFERENCES posts(id)
	);`
	execSchemaQuery(likesDislikesTable)
}

// execSchemaQuery executes a single schema creation query
func execSchemaQuery(query string) {
	_, err := DB.Exec(query)
	if err != nil {
		log.Fatalf("Error executing schema query: %v", err)
	}
}
