package controllers

import (
	"html/template"
	"literary-lions/database"
	"literary-lions/utils"
	"log"
	"net/http"
	"time"
)

func SearchPosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		log.Println("Invalid request method; redirecting to homepage.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet && r.URL.Query().Get("keywords") == "" {
		log.Println("Direct access to /search without query; redirecting to homepage.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing form: %v", err)
		utils.RenderErrorPage(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	query := r.FormValue("keywords") // Retrieve search parameters from the form (POST) or query string (GET)
	category := r.FormValue("category")
	author := r.FormValue("author")
	startDate := r.FormValue("start_date")
	endDate := r.FormValue("end_date")

	log.Printf("Received search query: keywords=%s, category=%s, author=%s, startDate=%s, endDate=%s", query, category, author, startDate, endDate)

	if query == "" { // Redirect to homepage if the search query is empty
		log.Println("Empty search query; redirecting to homepage.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	queryStr := `
        SELECT posts.id, posts.title, posts.body, users.username, posts.created_at
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE (posts.title LIKE ? OR posts.body LIKE ?)
    `
	params := []interface{}{"%" + query + "%", "%" + query + "%"}

	if category != "" { // Apply filters if they exist
		queryStr += " AND posts.category = ?"
		params = append(params, category)
	}
	if author != "" {
		queryStr += " AND users.username LIKE ?"
		params = append(params, "%"+author+"%")
	}
	if startDate != "" {
		queryStr += " AND posts.created_at >= ?"
		startDateParsed, _ := time.Parse("2006-01-02", startDate)
		params = append(params, startDateParsed)
	}
	if endDate != "" {
		queryStr += " AND posts.created_at <= ?"
		endDateParsed, _ := time.Parse("2006-01-02", endDate)
		params = append(params, endDateParsed)
	}

	log.Printf("Executing SQL query: %s with params: %v", queryStr, params)
	rows, err := database.DB.Query(queryStr, params...)
	if err != nil {
		log.Printf("Error executing query: %v", err)
		utils.RenderErrorPage(w, http.StatusInternalServerError, "Error fetching search results.")
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int
		var title, body, username string
		var createdAt string
		if err := rows.Scan(&id, &title, &body, &username, &createdAt); err != nil {
			log.Printf("Error scanning search results: %v", err)
			utils.RenderErrorPage(w, http.StatusInternalServerError, "Error scanning search results.")
			return
		}
		results = append(results, map[string]interface{}{
			"ID":        id,
			"Title":     title,
			"Body":      body,
			"Author":    username,
			"CreatedAt": createdAt,
		})
	}

	data := map[string]interface{}{
		"Query":   query,
		"Results": results,
	}

	tmpl := template.Must(template.ParseFiles("views/search_results.html"))
	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Error rendering template: %v", err)
		utils.RenderErrorPage(w, http.StatusInternalServerError, "Error displaying results.")
	}
}
