package database

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3" // SQLite driver for Go
)

var DB *sql.DB

// InitDB initializes the SQLite database connection and runs schema creation queries.
func InitDB() {
	var err error

	log.Println("Connecting to the SQLite database...")

	// Connect to the SQLite database (creates the file if it doesn't exist)
	DB, err = sql.Open("sqlite3", "./forum.db")
	if err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}

	// Check if the connection is valid
	log.Println("Pinging the database...")
	err = DB.Ping()
	if err != nil {
		log.Fatalf("Cannot connect to the database: %v", err)
	}

	// Call schema creation function to create all necessary tables
	log.Println("Creating database schema...")
	createSchema()
	log.Println("Database schema created successfully!")
}

// createSchema defines and executes the SQL schema to create the necessary tables
func createSchema() {
	// Schema for creating Users table
	usersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);`
	log.Println("Creating Users table...")
	execSchemaQuery(usersTable)
	log.Println("Users table created successfully!")

	// Schema for creating Posts table
	postsTable := `
	CREATE TABLE IF NOT EXISTS posts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		body TEXT NOT NULL,
		category_id INTEGER,
		user_id INTEGER,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id),
		FOREIGN KEY(category_id) REFERENCES categories(id)
	);`
	log.Println("Creating Posts table...")
	execSchemaQuery(postsTable)
	log.Println("Posts table created successfully!")

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
	log.Println("Creating Comments table...")
	execSchemaQuery(commentsTable)
	log.Println("Comments table created successfully!")

	// Schema for creating Categories table
	categoriesTable := `
	CREATE TABLE IF NOT EXISTS categories (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL
	);`
	log.Println("Creating Categories table...")
	execSchemaQuery(categoriesTable)
	log.Println("Categories table created successfully!")

	// Schema for creating Likes/Dislikes table
	likesDislikesTable := `
	CREATE TABLE IF NOT EXISTS likes_dislikes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		post_id INTEGER,
		comment_id INTEGER,
		like_type INTEGER CHECK(like_type IN (1, -1)),
		FOREIGN KEY(user_id) REFERENCES users(id),
		FOREIGN KEY(post_id) REFERENCES posts(id),
		FOREIGN KEY(comment_id) REFERENCES comments(id)
	);`
	log.Println("Creating Likes/Dislikes table...")
	execSchemaQuery(likesDislikesTable)
	log.Println("Likes/Dislikes table created successfully!")
}

// execSchemaQuery executes a single schema creation query
func execSchemaQuery(query string) {
	_, err := DB.Exec(query)
	if err != nil {
		log.Fatalf("Error executing schema query: %v", err)
	}
}
