package server

import (
	"net/http"
	"testing"
)

func TestChangePasswordOverHTTP(t *testing.T) {
	h := newHarness(t)
	token, _ := h.registerAndLogin("alice@example.com")

	const newPassword = "a-different-strong-password"
	rec := h.req(http.MethodPost, "/api/v1/auth/password", token, map[string]string{
		"current_password": testPassword, "new_password": newPassword,
	})
	mustStatus(t, rec, http.StatusNoContent)

	// The old session is revoked by the change.
	mustStatus(t, h.req(http.MethodGet, "/api/v1/auth/me", token, nil), http.StatusUnauthorized)

	rec = h.req(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email": "alice@example.com", "password": newPassword,
	})
	mustStatus(t, rec, http.StatusOK)
}

func TestChangePasswordRejectsAnAPIKey(t *testing.T) {
	h := newHarness(t)
	adminToken, _ := h.registerAndLogin("admin@example.com")
	h.makeAdmin("admin@example.com")

	rec := h.req(http.MethodPost, "/api/v1/api-keys", adminToken, map[string]any{
		"name": "key", "permissions": []string{"users.read"},
	})
	mustStatus(t, rec, http.StatusCreated)
	var created struct {
		Token string `json:"token"`
	}
	decodeBody(t, rec, &created)

	rec = h.req(http.MethodPost, "/api/v1/auth/password", created.Token, map[string]string{
		"current_password": testPassword, "new_password": "does-not-matter-1234",
	})
	mustStatus(t, rec, http.StatusForbidden)
}

func TestPasswordResetFlowOverHTTP(t *testing.T) {
	h := newHarness(t)
	h.register("reset@example.com")

	mustStatus(t,
		h.req(http.MethodPost, "/api/v1/auth/password/reset", "", map[string]string{"email": "reset@example.com"}),
		http.StatusNoContent)

	msg := h.mailer.lastTo(t, "reset@example.com")
	token := tokenFromLink(t, msg.Body)

	const newPassword = "yet-another-strong-password"
	rec := h.req(http.MethodPost, "/api/v1/auth/password/reset/confirm", "", map[string]string{
		"token": token, "new_password": newPassword,
	})
	mustStatus(t, rec, http.StatusNoContent)

	rec = h.req(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email": "reset@example.com", "password": newPassword,
	})
	mustStatus(t, rec, http.StatusOK)
}

// handleRequestPasswordReset must answer 204 for an unknown address too --
// anything else is an account-enumeration oracle on an unauthenticated endpoint.
func TestPasswordResetDoesNotDiscloseUnknownAddresses(t *testing.T) {
	h := newHarness(t)

	rec := h.req(http.MethodPost, "/api/v1/auth/password/reset", "", map[string]string{
		"email": "nobody-at-all@example.com",
	})
	mustStatus(t, rec, http.StatusNoContent)
}

func TestEmailVerificationFlowOverHTTP(t *testing.T) {
	h := newHarness(t)
	token, _ := h.registerAndLogin("verify@example.com")

	msg := h.mailer.lastTo(t, "verify@example.com")
	verifyToken := tokenFromLink(t, msg.Body)

	rec := h.req(http.MethodPost, "/api/v1/auth/email/verify", "", map[string]string{"token": verifyToken})
	mustStatus(t, rec, http.StatusOK)

	rec = h.req(http.MethodGet, "/api/v1/auth/me", token, nil)
	mustStatus(t, rec, http.StatusOK)
	var me struct {
		EmailVerifiedAt *string `json:"email_verified_at"`
	}
	decodeBody(t, rec, &me)
	if me.EmailVerifiedAt == nil {
		t.Error("expected email_verified_at to be set after verification")
	}
}

func TestDecodeJSONRejectsMalformedBody(t *testing.T) {
	h := newHarness(t)

	rec := h.req(http.MethodPost, "/api/v1/auth/register", "", `{"email": "not json`)
	mustStatus(t, rec, http.StatusBadRequest)
}

func TestDecodeJSONRejectsUnknownFields(t *testing.T) {
	h := newHarness(t)

	rec := h.req(http.MethodPost, "/api/v1/auth/register", "", `{"email":"x@example.com","password":"correct-horse-battery-staple","nonsense":true}`)
	mustStatus(t, rec, http.StatusBadRequest)
}
