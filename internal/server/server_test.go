package server

import (
	"net/http"
	"testing"
)

func TestHealthAndReady(t *testing.T) {
	h := newHarness(t)
	requireDB(t)

	mustStatus(t, h.req(http.MethodGet, "/healthz", "", nil), http.StatusOK)
	mustStatus(t, h.req(http.MethodGet, "/readyz", "", nil), http.StatusOK)
}

func TestRegisterLoginMeLogout(t *testing.T) {
	h := newHarness(t)

	token, id := h.registerAndLogin("alice@example.com")

	rec := h.req(http.MethodGet, "/api/v1/auth/me", token, nil)
	mustStatus(t, rec, http.StatusOK)
	var me struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	decodeBody(t, rec, &me)
	if me.ID != id.String() {
		t.Errorf("me.ID = %q, want %q", me.ID, id)
	}
	if me.Email != "alice@example.com" {
		t.Errorf("me.Email = %q", me.Email)
	}

	mustStatus(t, h.req(http.MethodPost, "/api/v1/auth/logout", token, nil), http.StatusNoContent)
	mustStatus(t, h.req(http.MethodGet, "/api/v1/auth/me", token, nil), http.StatusUnauthorized)
}

func TestMeRequiresAuthentication(t *testing.T) {
	h := newHarness(t)

	rec := h.req(http.MethodGet, "/api/v1/auth/me", "", nil)
	mustStatus(t, rec, http.StatusUnauthorized)
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("a 401 should carry WWW-Authenticate")
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	h := newHarness(t)
	h.register("dup@example.com")

	rec := h.req(http.MethodPost, "/api/v1/auth/register", "", map[string]string{
		"email": "dup@example.com", "password": testPassword,
	})
	mustStatus(t, rec, http.StatusConflict)
}

func TestPermissionGatedRouteWithoutTheRightRole(t *testing.T) {
	h := newHarness(t)
	token, _ := h.registerAndLogin("plain@example.com")

	// A user with no roles at all cannot list the directory.
	mustStatus(t, h.req(http.MethodGet, "/api/v1/users", token, nil), http.StatusForbidden)
}

func TestUsersEndpointRequiresUsersReadPermission(t *testing.T) {
	h := newHarness(t)
	adminToken, _ := h.registerAndLogin("admin@example.com")
	h.makeAdmin("admin@example.com")

	h.register("someone@example.com")

	rec := h.req(http.MethodGet, "/api/v1/users", adminToken, nil)
	mustStatus(t, rec, http.StatusOK)
	var resp struct {
		Users []struct {
			User struct {
				Email string `json:"email"`
			} `json:"user"`
		} `json:"users"`
	}
	decodeBody(t, rec, &resp)
	if len(resp.Users) < 2 {
		t.Fatalf("expected at least 2 users, got %d", len(resp.Users))
	}
}

func TestSetUserRolesOverHTTP(t *testing.T) {
	h := newHarness(t)
	adminToken, _ := h.registerAndLogin("admin@example.com")
	h.makeAdmin("admin@example.com")

	_, targetID := h.registerAndLogin("target@example.com")
	memberRoleID := h.roleID(adminToken, "member")

	rec := h.req(http.MethodPut, "/api/v1/users/"+targetID.String()+"/roles", adminToken,
		map[string]any{"role_ids": []string{memberRoleID.String()}})
	mustStatus(t, rec, http.StatusNoContent)

	// The target can now reach a member-gated route.
	targetToken := h.login("target@example.com")
	mustStatus(t, h.req(http.MethodGet, "/api/v1/users", targetToken, nil), http.StatusOK)
}

func TestSetUserActiveOverHTTP(t *testing.T) {
	h := newHarness(t)
	adminToken, _ := h.registerAndLogin("admin@example.com")
	h.makeAdmin("admin@example.com")

	targetToken, targetID := h.registerAndLogin("target@example.com")

	rec := h.req(http.MethodPatch, "/api/v1/users/"+targetID.String(), adminToken,
		map[string]bool{"is_active": false})
	mustStatus(t, rec, http.StatusOK)

	// Deactivation takes effect immediately, on the session already issued.
	mustStatus(t, h.req(http.MethodGet, "/api/v1/auth/me", targetToken, nil), http.StatusUnauthorized)
}

func TestSuperuserBypassesPermissionChecks(t *testing.T) {
	h := newHarness(t)
	token, _ := h.registerAndLogin("root@example.com")
	h.makeSuperuser("root@example.com")

	mustStatus(t, h.req(http.MethodGet, "/api/v1/users", token, nil), http.StatusOK)
	mustStatus(t, h.req(http.MethodGet, "/api/v1/audit", token, nil), http.StatusOK)
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t)

	rec := h.req(http.MethodGet, "/healthz", "", nil)
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
}

func TestCORSAllowlist(t *testing.T) {
	h := newHarness(t)

	allowed := h.reqOrigin(http.MethodGet, "/healthz", testOrigin)
	if got := allowed.Header().Get("Access-Control-Allow-Origin"); got != testOrigin {
		t.Errorf("allowed origin echoed = %q, want %q", got, testOrigin)
	}

	blocked := h.reqOrigin(http.MethodGet, "/healthz", "https://evil.example.com")
	if got := blocked.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("disallowed origin should not be echoed, got %q", got)
	}
}
