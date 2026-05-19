package main

import (
	"fmt"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	http.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/users", usersHandler)
	mux.HandleFunc("/users/create", createUserHandler)

	http.ListenAndServe(":8080", mux)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `{"status":"ok"}`)
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	page := r.FormValue("page")
	_ = q
	_ = page
	fmt.Fprintf(w, `{"users":[]}`)
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	name := r.PostFormValue("name")
	_ = name
	fmt.Fprintf(w, `{"created":true}`)
}
