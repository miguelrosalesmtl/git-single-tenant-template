package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/miguelrosalesmtl/go-template/internal/settings"
)

func TestRateLimitOnLogin(t *testing.T) {
	h := newHarnessWith(t, settings.RateLimit{Enabled: true, Attempts: 2, Window: time.Minute})
	h.register("limited@example.com")

	for i := range 2 {
		rec := h.req(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
			"email": "limited@example.com", "password": "wrong-password",
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i, rec.Code)
		}
	}

	rec := h.req(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email": "limited@example.com", "password": "wrong-password",
	})
	mustStatus(t, rec, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") == "" {
		t.Error("a 429 should carry Retry-After")
	}
}

func TestRateLimitAppliesPerEndpoint(t *testing.T) {
	h := newHarnessWith(t, settings.RateLimit{Enabled: true, Attempts: 1, Window: time.Minute})
	h.register("solo@example.com")

	// Exhaust the login limiter for this IP.
	h.req(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email": "solo@example.com", "password": "wrong",
	})
	limited := h.req(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email": "solo@example.com", "password": testPassword,
	})
	mustStatus(t, limited, http.StatusTooManyRequests)

	// A DIFFERENT endpoint, with its own rate-limit prefix, is unaffected by
	// login's exhausted bucket.
	stillOK := h.req(http.MethodPost, "/api/v1/auth/password/reset", "", map[string]string{
		"email": "solo@example.com",
	})
	mustStatus(t, stillOK, http.StatusNoContent)
}
