package server

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestAPIKeyLifecycleOverHTTP(t *testing.T) {
	h := newHarness(t)
	adminToken, _ := h.registerAndLogin("admin@example.com")
	h.makeAdmin("admin@example.com")

	rec := h.req(http.MethodPost, "/api/v1/api-keys", adminToken, map[string]any{
		"name": "ci key", "permissions": []string{"users.read"},
	})
	mustStatus(t, rec, http.StatusCreated)
	var created struct {
		APIKey struct {
			ID uuid.UUID `json:"id"`
		} `json:"api_key"`
		Token string `json:"token"`
	}
	decodeBody(t, rec, &created)
	if created.Token == "" {
		t.Fatal("create api key returned an empty token")
	}

	// The key authenticates like a session, using its own frozen scope.
	mustStatus(t, h.req(http.MethodGet, "/api/v1/users", created.Token, nil), http.StatusOK)

	// A personal key cannot reach account-management endpoints.
	mustStatus(t, h.req(http.MethodGet, "/api/v1/auth/me", created.Token, nil), http.StatusForbidden)

	mustStatus(t,
		h.req(http.MethodDelete, "/api/v1/api-keys/"+created.APIKey.ID.String(), adminToken, nil),
		http.StatusNoContent)

	// Revocation takes effect immediately.
	mustStatus(t, h.req(http.MethodGet, "/api/v1/users", created.Token, nil), http.StatusUnauthorized)
}

func TestAPIKeyEscalationGuardOverHTTP(t *testing.T) {
	h := newHarness(t)
	adminToken, _ := h.registerAndLogin("admin@example.com")
	h.makeAdmin("admin@example.com")

	plainToken, targetID := h.registerAndLogin("plain@example.com")
	memberRoleID := h.roleID(adminToken, "member")
	mustStatus(t,
		h.req(http.MethodPut, "/api/v1/users/"+targetID.String()+"/roles", adminToken,
			map[string]any{"role_ids": []string{memberRoleID.String()}}),
		http.StatusNoContent)

	// Access is resolved fresh on every request, so the existing session token
	// already reflects the role just assigned -- no need to log in again.
	rec := h.req(http.MethodPost, "/api/v1/api-keys", plainToken, map[string]any{
		"name": "too powerful", "permissions": []string{"users.read", "users.update"},
	})
	mustStatus(t, rec, http.StatusForbidden)
}

func TestAPIKeysRequirePermission(t *testing.T) {
	h := newHarness(t)
	token, _ := h.registerAndLogin("plain@example.com")

	mustStatus(t, h.req(http.MethodGet, "/api/v1/api-keys", token, nil), http.StatusForbidden)
}
