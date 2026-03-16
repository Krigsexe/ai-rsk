// VULNERABLE: http.ListenAndServe with zero timeouts — slowloris attack
package main

import "net/http"

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)
	http.ListenAndServe(":8080", mux)
}
