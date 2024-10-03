package structs

import (
	"database/sql"
	"time"
)

// Post represents a post in the system
type Post struct {
	ID         int
	Title      string
	Body       string
	CreatedAt  string
	Categories []Category
	UserID     sql.NullInt64
}

// Comment represents a comment in the system
type Comment struct {
	ID        int
	Body      string
	PostID    int
	CreatedAt string
	Poster    string
	Title     string
}

// Category represents a category for a post
type Category struct {
	ID   int
	Name string
}

// ProfileData represents the profile information for a user
type ProfileData struct {
	Username          string
	Email             string
	IsAdmin           bool
	Posts             []Post
	LikedPosts        []Post
	Comments          []Comment
	LikedComments     []Comment
	PostCount         int
	CanChangePassword bool
	Error             string
	Success           string
}

type SessionData struct {
	UserID    int
	ExpiresAt time.Time
}
