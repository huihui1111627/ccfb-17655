// Package web serves the simulation control API and the embedded dashboard.
package web

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"

	"certrot/sim"
)

//go:embed static/*
var staticFS embed.FS

// Server wraps the simulation with an HTTP API.
type Server struct {
	Sim *sim.Sim
}

// New builds the server.
func New(s *sim.Sim) *Server { return &Server{Sim: s} }

// Mux registers all routes.
func (s *Server) Mux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.Sim.Snapshot())
	})
	mux.HandleFunc("/api/rotate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if err := s.Sim.Rotate(); err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]string{"status": "rotated"})
	})
	mux.HandleFunc("/api/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := s.Sim.Restart(req.ID); err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]string{"status": "restarted", "id": req.ID})
	})
	mux.HandleFunc("/api/restart-batch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Index int `json:"index"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		ids, err := s.Sim.RestartBatch(req.Index)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error(), "restarted": ids})
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "restarted": ids})
	})
	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.Sim.BuildReport())
	})

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
