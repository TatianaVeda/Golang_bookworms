package controllers

import (
	"database/sql"
	"fmt"
	"literary-lions/database"
	"net/http"
	"text/template"

	"golang.org/x/crypto/bcrypt"
)

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Hash the password using bcrypt
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		// Insert user into the database
		_, err := database.DB.Exec(`INSERT INTO users (email, username, password) VALUES (?, ?, ?)`, email, username, hashedPassword)
		if err != nil {
			fmt.Fprintf(w, "Error registering user: %v", err)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	} else {
		tmpl := template.Must(template.ParseFiles("views/register.html"))
		tmpl.Execute(w, nil)
	}
}

func LoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Query for user
		row := database.DB.QueryRow(`SELECT id, password FROM users WHERE email = ?`, email)

		var id int
		var hashedPassword string
		err := row.Scan(&id, &hashedPassword)
		if err == sql.ErrNoRows {
			fmt.Fprintf(w, "Invalid email or password")
			return
		}

		// Compare hashed password
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			fmt.Fprintf(w, "Invalid email or password")
			return
		}

		// Set session cookie (simplified)
		// ...

		http.Redirect(w, r, "/home", http.StatusSeeOther)
	} else {
		tmpl := template.Must(template.ParseFiles("views/login.html"))
		tmpl.Execute(w, nil)
	}
}
