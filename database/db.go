package database

import (
	"database/sql"
	"fmt"
	"log"
	"sync"

	_ "github.com/mattn/go-sqlite3" // SQLite driver for Go
)

var (
	DB           *sql.DB                // Global DB instance
	SessionMutex sync.Mutex             // Mutex to protect session store
	SessionStore = make(map[string]int) // Session store to map session IDs to user IDs
)

// InitDB initializes the SQLite database connection
func InitDB(dataSourceName string) error {
	var err error

	DB, err = sql.Open("sqlite3", dataSourceName)
	if err != nil {
		return err
	}

	if err = DB.Ping(); err != nil {
		return err
	}

	log.Println("Database connection established.")
	return nil
}

// createSchema defines and executes the SQL schema to create the necessary tables
func createSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			username TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL,
			is_admin BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS posts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			body TEXT NOT NULL,
			user_id INTEGER,
			category_id INTEGER,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id),
			FOREIGN KEY(category_id) REFERENCES categories(id)
		);`,

		`CREATE TABLE IF NOT EXISTS categories (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE
		);`,

		`CREATE TABLE IF NOT EXISTS post_categories (
			post_id INTEGER,
			category_id INTEGER,
			FOREIGN KEY(post_id) REFERENCES posts(id),
			FOREIGN KEY(category_id) REFERENCES categories(id),
			PRIMARY KEY(post_id, category_id)
		);`,

		`CREATE TABLE IF NOT EXISTS comments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			body TEXT NOT NULL,
			post_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(post_id) REFERENCES posts(id),
			FOREIGN KEY(user_id) REFERENCES users(id)
		);`,

		`CREATE TABLE IF NOT EXISTS likes_dislikes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			post_id INTEGER NOT NULL,
			like_type INTEGER NOT NULL CHECK (like_type IN (1, -1)),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id),
			FOREIGN KEY(post_id) REFERENCES posts(id)
		);`,

		`PRAGMA foreign_keys = ON;`, // Ensure foreign keys are enforced.
	}

	for _, query := range queries {
		err := execSchemaQuery(query) // Use the helper function here
		if err != nil {
			return fmt.Errorf("error creating table: %w", err)
		}
	}
	return nil
}

func execSchemaQuery(query string) error {
	_, err := DB.Exec(query)
	if err != nil {
		log.Fatalf("Error executing schema query: %v", err)
		return err // Return the error instead of just logging it.
	}
	return nil
}

// Functions for interacting with the database, e.g., adding categories, posts, etc.
func AddCategory(name string) error {
	query := `INSERT INTO categories (name) VALUES (?)`
	_, err := DB.Exec(query, name)
	if err != nil {
		return fmt.Errorf("error adding category: %w", err)
	}
	return nil
}

func AddPostCategory(postID, categoryID int) error {
	query := `INSERT INTO post_categories (post_id, category_id) VALUES (?, ?)`
	_, err := DB.Exec(query, postID, categoryID)
	if err != nil {
		return fmt.Errorf("error linking post with category: %w", err)
	}
	return nil
}
