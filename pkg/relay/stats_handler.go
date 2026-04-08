package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// StatsHandler returns an http.Handler that serves relay statistics.
//
// It supports two response formats, negotiated via the Accept header or the
// ?format= query parameter:
//
//   - "application/json" (default)  → JSON object
//   - "text/plain" or "prometheus"  → Prometheus text exposition format
//
// Typical usage:
//
//	mux := http.NewServeMux()
//	mux.Handle("/metrics", relay.StatsHandler(&server.Stats))
//	go http.ListenAndServe(":9091", mux)
func StatsHandler(stats *GlobalStats) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		snap := stats.Snapshot()

		format := r.URL.Query().Get("format")
		if format == "" {
			format = negotiateFormat(r.Header.Get("Accept"))
		}

		switch format {
		case "prometheus":
			writePrometheus(w, snap)
		default:
			writeJSON(w, snap)
		}
	})
}

// negotiateFormat picks the response format from the Accept header.
// Defaults to "json" unless the client explicitly requests plain text.
func negotiateFormat(accept string) string {
	if strings.Contains(accept, "text/plain") {
		return "prometheus"
	}
	return "json"
}

// jsonStats is the wire format for the JSON endpoint.
type jsonStats struct {
	Timestamp string `json:"timestamp"`
	BytesIn   int64  `json:"bytes_in"`
	BytesOut  int64  `json:"bytes_out"`
	FramesIn  int64  `json:"frames_in"`
	FramesOut int64  `json:"frames_out"`
	DropsRL   int64  `json:"drops_rl"`
}

func writeJSON(w http.ResponseWriter, snap StatsSnapshot) {
	payload := jsonStats{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		BytesIn:   snap.BytesIn,
		BytesOut:  snap.BytesOut,
		FramesIn:  snap.FramesIn,
		FramesOut: snap.FramesOut,
		DropsRL:   snap.DropsRL,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(payload)
}

// prometheusLine writes a single Prometheus text-format metric line.
func prometheusLine(sb *strings.Builder, name, help, metricType string, value int64) {
	fmt.Fprintf(sb, "# HELP %s %s\n", name, help)
	fmt.Fprintf(sb, "# TYPE %s %s\n", name, metricType)
	fmt.Fprintf(sb, "%s %d\n", name, value)
}

func writePrometheus(w http.ResponseWriter, snap StatsSnapshot) {
	var sb strings.Builder

	prometheusLine(&sb,
		"nabu_relay_bytes_in_total",
		"Total payload bytes received from clients (post-decrypt).",
		"counter", snap.BytesIn)

	prometheusLine(&sb,
		"nabu_relay_bytes_out_total",
		"Total payload bytes sent to clients (pre-encrypt).",
		"counter", snap.BytesOut)

	prometheusLine(&sb,
		"nabu_relay_frames_in_total",
		"Total NABU frames accepted from clients.",
		"counter", snap.FramesIn)

	prometheusLine(&sb,
		"nabu_relay_frames_out_total",
		"Total NABU frames sent to clients.",
		"counter", snap.FramesOut)

	prometheusLine(&sb,
		"nabu_relay_drops_rate_limit_total",
		"Total frames dropped by the per-source rate limiter.",
		"counter", snap.DropsRL)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, sb.String())
}
