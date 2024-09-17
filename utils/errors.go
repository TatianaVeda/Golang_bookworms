// utils/errors.go
package utils

import (
	"html/template"
	"net/http"
)

// RenderErrorPage renders a custom error page with a status code and message
func RenderErrorPage(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)

	tmpl := template.Must(template.ParseFiles("views/error.html"))
	data := map[string]interface{}{
		"StatusCode": statusCode,
		"Message":    message,
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "An error occurred", http.StatusInternalServerError)
	}
}
