package structs

import (
	"time"
)

type Post struct {
	ID           int
	Title        string
	Body         string
	CreatedAt    time.Time
	Categories   []Category
	UserID       int
	UserName     string
	LikeCount    int
	DislikeCount int
	CategoryName string
	CategoryID   int
	Comments     []Comment
	postID       int
}

// Comment represents a comment in the system
type Comment struct {
	ID        int
	Body      string
	PostID    int
	CreatedAt time.Time
	Poster    string
	Title     string
	UserName  string
	UserID    int
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

type TemplateData struct {
	Categories   []Category
	Title        string
	Posts        []Post // Slice to store the list of posts
	CategoryName string // Store the name of the category being viewed
	LoggedUser   string
	IsLoggedIn   bool
}

type SearchResult struct {
	ID        int
	Title     string
	Author    string
	CreatedAt time.Time
	Body      string
}

type SearchPageData struct {
	Query   string
	Results []SearchResult
}
