package controllers

import (
	"fmt"
	"literary-lions/database"
	"net/http"
	"text/template"
)

func CreatePost(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		title := r.FormValue("title")
		body := r.FormValue("body")
		categoryID := r.FormValue("category_id")
		userID := 1 // Assume the user is logged in and this is the logged-in user's ID.

		// Insert post into the database
		_, err := database.DB.Exec(`INSERT INTO posts (title, body, category_id, user_id) VALUES (?, ?, ?, ?)`, title, body, categoryID, userID)
		if err != nil {
			fmt.Fprintf(w, "Error creating post: %v", err)
			return
		}
		http.Redirect(w, r, "/posts", http.StatusSeeOther)
	} else {
		tmpl := template.Must(template.ParseFiles("views/create_post.html"))
		tmpl.Execute(w, nil)
	}
}
