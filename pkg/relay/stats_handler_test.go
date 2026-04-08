package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStatsHandlerJSON(t *testing.T) {
	var gs GlobalStats
	gs.BytesIn.Add(1024)
	gs.BytesOut.Add(512)
	gs.FramesIn.Add(10)
	gs.FramesOut.Add(8)
	gs.DropsRL.Add(2)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	StatsHandler(&gs).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("expected json content-type, got %q", ct)
	}

	var got jsonStats
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode json: %v", err)
	}

	if got.BytesIn != 1024 {
		t.Errorf("bytes_in: want 1024, got %d", got.BytesIn)
	}
	if got.BytesOut != 512 {
		t.Errorf("bytes_out: want 512, got %d", got.BytesOut)
	}
	if got.FramesIn != 10 {
		t.Errorf("frames_in: want 10, got %d", got.FramesIn)
	}
	if got.FramesOut != 8 {
		t.Errorf("frames_out: want 8, got %d", got.FramesOut)
	}
	if got.DropsRL != 2 {
		t.Errorf("drops_rl: want 2, got %d", got.DropsRL)
	}

	// Timestamp must parse as RFC3339.
	if _, err := time.Parse(time.RFC3339, got.Timestamp); err != nil {
		t.Errorf("timestamp %q not RFC3339: %v", got.Timestamp, err)
	}
}

func TestStatsHandlerPrometheusViaAccept(t *testing.T) {
	var gs GlobalStats
	gs.BytesIn.Add(999)
	gs.DropsRL.Add(7)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Accept", "text/plain")
	rec := httptest.NewRecorder()

	StatsHandler(&gs).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rec.Code)
	}
	body := rec.Body.String()

	if !strings.Contains(body, "nabu_relay_bytes_in_total 999") {
		t.Errorf("expected bytes_in=999 in prometheus output; got:\n%s", body)
	}
	if !strings.Contains(body, "nabu_relay_drops_rate_limit_total 7") {
		t.Errorf("expected drops_rl=7 in prometheus output; got:\n%s", body)
	}
	if !strings.Contains(body, "# TYPE nabu_relay_bytes_in_total counter") {
		t.Errorf("expected TYPE line in prometheus output; got:\n%s", body)
	}
}

func TestStatsHandlerPrometheusViaQueryParam(t *testing.T) {
	var gs GlobalStats
	gs.FramesOut.Add(42)

	req := httptest.NewRequest(http.MethodGet, "/metrics?format=prometheus", nil)
	rec := httptest.NewRecorder()

	StatsHandler(&gs).ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "nabu_relay_frames_out_total 42") {
		t.Errorf("expected frames_out=42; got:\n%s", body)
	}
}

func TestStatsHandlerDefaultsToJSON(t *testing.T) {
	var gs GlobalStats

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	// No Accept header → default JSON
	rec := httptest.NewRecorder()

	StatsHandler(&gs).ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("expected json content-type by default, got %q", ct)
	}
}

func TestStatsHandlerZeroValues(t *testing.T) {
	var gs GlobalStats

	req := httptest.NewRequest(http.MethodGet, "/metrics?format=prometheus", nil)
	rec := httptest.NewRecorder()

	StatsHandler(&gs).ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "nabu_relay_bytes_in_total 0") {
		t.Errorf("expected zero bytes_in; got:\n%s", body)
	}
}
