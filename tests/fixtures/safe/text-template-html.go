// SAFE: html/template auto-escapes all HTML contexts
package main

import (
	"html/template"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.New("page").Parse("<h1>{{.Title}}</h1>")
	tmpl.Execute(w, data)
}
