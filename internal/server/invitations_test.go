package server

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestInviteAcceptFlowOverHTTP(t *testing.T) {
	h := newHarness(t)
	adminToken, _ := h.registerAndLogin("admin@example.com")
	h.makeAdmin("admin@example.com")
	memberRoleID := h.roleID(adminToken, "member")

	rec := h.req(http.MethodPost, "/api/v1/invitations", adminToken, map[string]any{
		"email": "invitee@example.com", "role_id": memberRoleID.String(),
	})
	mustStatus(t, rec, http.StatusCreated)

	msg := h.mailer.lastTo(t, "invitee@example.com")
	token := tokenFromLink(t, msg.Body)

	rec = h.req(http.MethodPost, "/api/v1/invitations/accept", "", map[string]string{
		"token": token, "password": testPassword, "full_name": "Invitee",
	})
	mustStatus(t, rec, http.StatusCreated)

	// The invitee can now log in with the password they set.
	inviteeToken := h.login("invitee@example.com")
	mustStatus(t, h.req(http.MethodGet, "/api/v1/auth/me", inviteeToken, nil), http.StatusOK)

	// And can reach the member-gated route the invitation's role grants.
	mustStatus(t, h.req(http.MethodGet, "/api/v1/users", inviteeToken, nil), http.StatusOK)
}

func TestInvitationsRequirePermission(t *testing.T) {
	h := newHarness(t)
	token, _ := h.registerAndLogin("plain@example.com")

	rec := h.req(http.MethodPost, "/api/v1/invitations", token, map[string]any{
		"email": "someone@example.com", "role_id": uuid.New().String(),
	})
	mustStatus(t, rec, http.StatusForbidden)
}

func TestInviteRequiresARoleID(t *testing.T) {
	h := newHarness(t)
	adminToken, _ := h.registerAndLogin("admin@example.com")
	h.makeAdmin("admin@example.com")

	rec := h.req(http.MethodPost, "/api/v1/invitations", adminToken, map[string]any{
		"email": "someone@example.com",
	})
	mustStatus(t, rec, http.StatusBadRequest)
}

func TestRevokeInvitationOverHTTP(t *testing.T) {
	h := newHarness(t)
	adminToken, _ := h.registerAndLogin("admin@example.com")
	h.makeAdmin("admin@example.com")
	memberRoleID := h.roleID(adminToken, "member")

	rec := h.req(http.MethodPost, "/api/v1/invitations", adminToken, map[string]any{
		"email": "revoke@example.com", "role_id": memberRoleID.String(),
	})
	mustStatus(t, rec, http.StatusCreated)
	var inv struct {
		ID uuid.UUID `json:"id"`
	}
	decodeBody(t, rec, &inv)

	mustStatus(t, h.req(http.MethodDelete, "/api/v1/invitations/"+inv.ID.String(), adminToken, nil),
		http.StatusNoContent)

	msg := h.mailer.lastTo(t, "revoke@example.com")
	token := tokenFromLink(t, msg.Body)

	rec = h.req(http.MethodPost, "/api/v1/invitations/accept", "", map[string]string{
		"token": token, "password": testPassword,
	})
	mustStatus(t, rec, http.StatusBadRequest)
}
