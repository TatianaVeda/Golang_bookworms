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

func checkIfTablesExist() (bool, error) {
	var tableCount int
	query := "SELECT COUNT(name) FROM sqlite_master WHERE type='table' AND name IN ('users', 'posts', 'categories', 'post_categories', 'comments', 'likes_dislikes', 'comment_likes');"
	err := DB.QueryRow(query).Scan(&tableCount)
	if err != nil {
		return false, err
	}
	return tableCount > 0, nil
}

func InitDB(dsn string) error {
	var err error

	DB, err = sql.Open("sqlite3", dsn) // Open the SQLite database with the provided DSN (data source name)
	if err != nil {
		log.Fatalf("Failed to open the database: %v", err)
		return err
	}

	_, err = DB.Exec("PRAGMA journal_mode = WAL;") // Set journal mode to WAL (write-ahead logging) to support concurrent reads and writes.
	if err != nil {
		log.Fatalf("Failed to set journal mode to WAL: %v", err)
		return err
	}

	_, err = DB.Exec("PRAGMA busy_timeout = 5000;") // Set a 5-second timeout
	if err != nil {
		log.Fatalf("Failed to set busy timeout: %v", err)
		return err
	}

	tablesExist, err := checkIfTablesExist()
	if err != nil {
		return fmt.Errorf("failed to check for existing tables: %w", err)
	}

	if !tablesExist {
		// if table doesn't exist - create schema
		if err := createSchema(); err != nil {
			log.Fatalf("Failed to create schema: %v", err)
			return err
		}
	}

	log.Println("Database connection initialized successfully with WAL journal mode and busy timeout.")
	return nil
}

var WriteDB *sql.DB

func InitWriteDB(dsn string) error {
	var err error
	WriteDB, err = sql.Open("sqlite3", dsn)
	if err != nil {
		log.Fatalf("Failed to open the write database: %v", err)
		return err
	}

	WriteDB.SetMaxOpenConns(1) // Single write connection
	WriteDB.SetMaxIdleConns(1) // Keep only 1 idle write connection
	_, err = WriteDB.Exec("PRAGMA journal_mode = WAL;")
	if err != nil {
		log.Fatalf("Failed to set WAL mode on write DB: %v", err)
		return err
	}
	_, err = WriteDB.Exec("PRAGMA busy_timeout = 10000;")
	if err != nil {
		log.Fatalf("Failed to set busy timeout on write DB: %v", err)
		return err
	}
	return nil
}

func ConnectDB() *sql.DB {

	db, err := sql.Open("sqlite3", "./forum.db") // Connect to the SQLite database
	if err != nil {
		log.Fatal("Error connecting to the database:", err)
	}
	return db
}

// createSchema defines and executes the SQL schema to create the necessary tables
func createSchema() error {

	err := execSchemaQuery(`PRAGMA foreign_keys = ON;`) // Ensure foreign keys are enforced.
	if err != nil {
		return fmt.Errorf("error enabling foreign key support: %w", err)
	}
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

		`CREATE TABLE IF NOT EXISTS comment_likes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			comment_id INTEGER NOT NULL,
			like BOOLEAN NOT NULL DEFAULT 1,
			like_type INTEGER NOT NULL CHECK (like_type IN (1, -1)),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(user_id) REFERENCES users(id),
			FOREIGN KEY(comment_id) REFERENCES comments(id)
		);`,

		`CREATE UNIQUE INDEX IF NOT EXISTS idx_user_comment_like ON comment_likes (user_id, comment_id);`, // inique index to prevent "likes" duplicate

		`CREATE TABLE sessions (
			session_id TEXT PRIMARY KEY,      -- Stores the unique session identifier
			user_id INTEGER NOT NULL,         -- Links to the user associated with the session
			expires_at DATETIME NOT NULL,     -- Defines the expiration time of the session
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		);`,
	}

	for _, query := range queries {
		err := execSchemaQuery(query)
		if err != nil {
			return fmt.Errorf("error creating table: %w", err)
		}
	}

	// Populate categories table after all tables have been created
	log.Println("Populating categories table with default values...")
	if err := populateCategories(); err != nil {
		return fmt.Errorf("failed to populate categories: %w", err)
	}

	return nil
}

// Populate categories with default values
func populateCategories() error {
	// Check if 'categories' table exists before populating
	var tableExists bool
	err := DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='categories';").Scan(&tableExists)
	if err != nil || !tableExists {
		return fmt.Errorf("categories table does not exist or could not be verified: %w", err)
	}

	var count int
	err = DB.QueryRow("SELECT COUNT(*) FROM categories").Scan(&count)
	if err != nil {
		return fmt.Errorf("error checking categories count: %w", err)
	}

	if count == 0 {
		categories := []string{"Literature", "Poetry", "Non-fiction", "Short Stories"}
		for _, name := range categories {
			if err := AddCategory(name); err != nil {
				return fmt.Errorf("error populating categories: %w", err)
			}
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

func AddCategory(name string) error { // Functions for interacting with the database, e.g., adding categories, posts, etc.
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

func GetUserNameByID(userID int) string {
	var username string
	err := DB.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("No user found with ID %d", userID)
			return "Unknown"
		}
		log.Printf("Error fetching username for user ID %d: %v", userID, err)
		return "Unknown" // Return default "Unknown" if error occurs
	}
	return username
}

func GetUserID(username string) (int, error) {
	var userID int
	err := DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	return userID, err
}
