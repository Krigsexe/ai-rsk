// SAFE: http.Server with explicit timeouts
package main

import (
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	server.ListenAndServe()
}
