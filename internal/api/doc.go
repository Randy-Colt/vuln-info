package api

import (
    "encoding/json"
    "net/http"
)

func ServeOpenAPI(w http.ResponseWriter, r *http.Request) {
    swagger, err := GetSpec()
    if err != nil {
        http.Error(w, "failed to get spec", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    if err := json.NewEncoder(w).Encode(swagger); err != nil {
        http.Error(w, "failed to encode spec", http.StatusInternalServerError)
    }
}