package handlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Kyei-Ernest/DocOps/connectors"
)

// HealthHandler exposes liveness and readiness probes for orchestration
// (Docker HEALTHCHECK, Kubernetes probes, uptime monitors).
//
// /healthz answers "is the process up" — it never touches dependencies, so a
// 200 here means only that the HTTP server is serving.
// /readyz answers "can this instance serve traffic right now" — it pings every
// backing dependency (database, storage connector) and fails closed with 503
// if any of them is unreachable.
type HealthHandler struct {
	db        *sql.DB
	connector connectors.StorageConnector
}

// NewHealthHandler constructs a HealthHandler. Both dependencies may be nil in
// exotic embeddings; nil dependencies are reported as unavailable rather than
// panicking — a half-wired probe must degrade, not crash the server.
func NewHealthHandler(db *sql.DB, connector connectors.StorageConnector) *HealthHandler {
	return &HealthHandler{db: db, connector: connector}
}

// Live handles GET /healthz — liveness only.
func (h *HealthHandler) Live(w http.ResponseWriter, r *http.Request) {
	writeHealth(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Ready handles GET /readyz — dependency-gated readiness.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	status := http.StatusOK
	body := map[string]string{"status": "ok"}

	if h.db == nil {
		status = http.StatusServiceUnavailable
		body["status"] = "unavailable"
		body["database"] = "unavailable"
	} else if err := h.db.PingContext(r.Context()); err != nil {
		// Full error stays server-side: connection strings or file paths can
		// surface in driver errors and must not leak through the probe.
		slog.Error("readiness check failed", "component", "database", "error", err)
		status = http.StatusServiceUnavailable
		body["status"] = "unavailable"
		body["database"] = "unavailable"
	} else {
		body["database"] = "ok"
	}

	if h.connector == nil {
		status = http.StatusServiceUnavailable
		body["status"] = "unavailable"
		body["storage"] = "unavailable"
	} else if err := h.connector.Ping(r.Context()); err != nil {
		slog.Error("readiness check failed", "component", "storage", "error", err)
		status = http.StatusServiceUnavailable
		body["status"] = "unavailable"
		body["storage"] = "unavailable"
	} else {
		body["storage"] = "ok"
	}

	writeHealth(w, status, body)
}

func writeHealth(w http.ResponseWriter, code int, body map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(body)
}
