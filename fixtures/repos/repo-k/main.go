package main

import (
	"net/http"
	"os"
	"path/filepath"
)

// Path traversal: the request path is joined without being contained.
func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	data, err := os.ReadFile(filepath.Join("/var/data", name))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Write(data)
}
