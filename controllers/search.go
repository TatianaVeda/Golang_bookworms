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

	keywords := r.FormValue("keywords")
	category := r.FormValue("category")
	author := r.FormValue("author")
	startDate := r.FormValue("start_date")
	endDate := r.FormValue("end_date")

	if keywords == "" && category == "" {
		log.Println("Empty search query and category; redirecting to homepage.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	queryStr := `
        SELECT posts.id, posts.title, posts.body, users.username, posts.created_at
        FROM posts
        JOIN users ON posts.user_id = users.id
        LEFT JOIN categories ON posts.category_id = categories.id
        WHERE (posts.title LIKE ? OR posts.body LIKE ? OR categories.name LIKE ?)
    `
	params := []interface{}{"%" + keywords + "%", "%" + keywords + "%", "%" + keywords + "%"}

	if category != "" {
		queryStr += " AND categories.name LIKE ?"
		params = append(params, "%"+category+"%")
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

	if len(results) == 0 {
		log.Println("No results found for the specified query and filters.")
	}

	data := map[string]interface{}{
		"Query":    keywords,
		"Category": category,
		"Results":  results,
	}

	tmpl := template.Must(template.ParseFiles("views/search_results.html"))
	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Error rendering template: %v", err)
		utils.RenderErrorPage(w, http.StatusInternalServerError, "Error displaying results.")
	}
}
