// utils/errors.go
package utils

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
)

type Config struct {
	DB        *sql.DB
	Templates *template.Template
}

func NewConfig() (*Config, error) {
	db, err := sql.Open("sqlite3", "./forum.db")
	if err != nil {
		return nil, err
	}

	templates := template.Must(template.ParseGlob("views/*.html"))

	return &Config{DB: db, Templates: templates}, nil
}

func RenderErrorPage(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode) // Set the status code

	tmpl := template.Must(template.ParseFiles("views/error.html"))
	data := map[string]interface{}{ // 	Create a map of data to pass to the template
		"StatusCode": statusCode,
		"Message":    message,
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "An error occurred", http.StatusInternalServerError)
	}
}

func HandleError(w http.ResponseWriter, statusCode int, userMessage string, err ...error) {

	if len(err) > 0 && err[0] != nil { // Check if there is an error
		log.Printf("Internal error: %v", err[0])
	}
	http.Error(w, userMessage, statusCode)
}

func middleware(next http.Handler, templates *template.Template) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // 	Handle 404 and 500 errors
		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK} // 	Create a response recorder
		next.ServeHTTP(rec, r)                                                 // 	Serve the request

		if rec.statusCode == http.StatusNotFound {
			templates.ExecuteTemplate(w, "404.html", nil)
		} else if rec.statusCode == http.StatusInternalServerError {
			templates.ExecuteTemplate(w, "error.html", nil)
		}
	})
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rec *responseRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}
