package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/hy2-gateway/internal/traffic"
	"go.uber.org/zap"
)

// Server provides an HTTP API for managing the gateway.
type Server struct {
	trafficLogger *traffic.TrafficLogger
	secret        string
	logger        *zap.Logger
}

// NewServer creates a new API server.
func NewServer(trafficLogger *traffic.TrafficLogger, secret string, logger *zap.Logger) *Server {
	return &Server{
		trafficLogger: trafficLogger,
		secret:        secret,
		logger:        logger,
	}
}

// Handler returns the HTTP handler for the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/traffic", s.authMiddleware(s.handleTraffic))
	mux.HandleFunc("/traffic/", s.authMiddleware(s.handleTrafficUser))
	mux.HandleFunc("/traffic/reset", s.authMiddleware(s.handleTrafficReset))
	mux.HandleFunc("/health", s.handleHealth)
	return mux
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.secret != "" {
			auth := r.Header.Get("Authorization")
			if auth != s.secret {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// GET /traffic - returns all user traffic stats
// GET /traffic?clear=1 - returns and resets all stats
func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	snapshots := s.trafficLogger.GetAllSnapshots()

	clear := r.URL.Query().Get("clear")
	if clear == "1" || clear == "true" {
		s.trafficLogger.ResetAllStats()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshots)
}

// GET /traffic/{userId} - returns traffic stats for a specific user
func (s *Server) handleTrafficUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract userId from path: /traffic/{userId}
	path := strings.TrimPrefix(r.URL.Path, "/traffic/")
	userId := strings.TrimSuffix(path, "/")
	if userId == "" || userId == "reset" {
		// Let other handlers deal with it
		return
	}

	snapshot := s.trafficLogger.GetSnapshot(userId)
	if snapshot == nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snapshot)
}

// POST /traffic/reset - resets all traffic stats
// POST /traffic/reset?user={userId} - resets stats for a specific user
func (s *Server) handleTrafficReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userId := r.URL.Query().Get("user")
	if userId != "" {
		s.trafficLogger.ResetStats(userId)
		s.logger.Info("traffic stats reset for user", zap.String("user", userId))
	} else {
		s.trafficLogger.ResetAllStats()
		s.logger.Info("all traffic stats reset")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// GET /health - health check
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}
