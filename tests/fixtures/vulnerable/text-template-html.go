// VULNERABLE: text/template does not escape HTML — XSS risk
package main

import (
	"text/template"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.New("page").Parse("<h1>{{.Title}}</h1>")
	tmpl.Execute(w, data)
}
