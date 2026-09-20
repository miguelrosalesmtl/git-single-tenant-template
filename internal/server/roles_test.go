package server

import (
	"net/http"
	"testing"
)

func TestListPermissionsIsPublic(t *testing.T) {
	h := newHarness(t)
	rec := h.req(http.MethodGet, "/api/v1/permissions", "", nil)
	mustStatus(t, rec, http.StatusOK)

	var resp struct {
		Permissions []struct {
			Key string `json:"key"`
		} `json:"permissions"`
	}
	decodeBody(t, rec, &resp)
	if len(resp.Permissions) == 0 {
		t.Fatal("expected a non-empty permission catalog")
	}
}

func TestRoleCRUDOverHTTP(t *testing.T) {
	h := newHarness(t)
	adminToken, _ := h.registerAndLogin("admin@example.com")
	h.makeAdmin("admin@example.com")

	rec := h.req(http.MethodPost, "/api/v1/roles", adminToken, map[string]any{
		"key": "billing_manager", "name": "Billing Manager", "permissions": []string{"users.read"},
	})
	mustStatus(t, rec, http.StatusCreated)
	var role struct {
		ID string `json:"id"`
	}
	decodeBody(t, rec, &role)

	rec = h.req(http.MethodPut, "/api/v1/roles/"+role.ID, adminToken, map[string]any{
		"name": "Billing Manager (renamed)", "permissions": []string{"users.read"},
	})
	mustStatus(t, rec, http.StatusOK)

	mustStatus(t, h.req(http.MethodDelete, "/api/v1/roles/"+role.ID, adminToken, nil), http.StatusNoContent)
}

func TestSystemRolesAreImmutableOverHTTP(t *testing.T) {
	h := newHarness(t)
	adminToken, _ := h.registerAndLogin("admin@example.com")
	h.makeAdmin("admin@example.com")
	adminRoleID := h.roleID(adminToken, "admin")

	rec := h.req(http.MethodPut, "/api/v1/roles/"+adminRoleID.String(), adminToken, map[string]any{
		"name": "Not Admin Anymore", "permissions": []string{"users.read"},
	})
	mustStatus(t, rec, http.StatusForbidden)

	mustStatus(t, h.req(http.MethodDelete, "/api/v1/roles/"+adminRoleID.String(), adminToken, nil),
		http.StatusForbidden)
}

func TestCreateRoleEscalationGuardOverHTTP(t *testing.T) {
	h := newHarness(t)
	token, targetID := h.registerAndLogin("plain@example.com")
	adminToken, _ := h.registerAndLogin("admin@example.com")
	h.makeAdmin("admin@example.com")

	// The actor must hold roles.create themselves, or requirePermission
	// rejects them before the service's escalation guard ever runs -- that
	// would be testing the wrong 403. A role holding roles.create but not
	// users.update isolates the guard we actually want to exercise.
	rec := h.req(http.MethodPost, "/api/v1/roles", adminToken, map[string]any{
		"key": "role_editor", "name": "Role Editor", "permissions": []string{"roles.create"},
	})
	mustStatus(t, rec, http.StatusCreated)
	var editorRole struct {
		ID string `json:"id"`
	}
	decodeBody(t, rec, &editorRole)

	mustStatus(t,
		h.req(http.MethodPut, "/api/v1/users/"+targetID.String()+"/roles", adminToken,
			map[string]any{"role_ids": []string{editorRole.ID}}),
		http.StatusNoContent)

	// The actor holds roles.create but not users.update, and cannot mint a
	// role that grants users.update.
	rec = h.req(http.MethodPost, "/api/v1/roles", token, map[string]any{
		"key": "sneaky", "name": "Sneaky", "permissions": []string{"users.read", "users.update"},
	})
	mustStatus(t, rec, http.StatusForbidden)
}

func TestLastAdminCannotBeDemotedOverHTTP(t *testing.T) {
	h := newHarness(t)
	adminToken, adminID := h.registerAndLogin("solo-admin@example.com")
	h.makeAdmin("solo-admin@example.com")

	rec := h.req(http.MethodPut, "/api/v1/users/"+adminID.String()+"/roles", adminToken,
		map[string]any{"role_ids": []string{}})
	mustStatus(t, rec, http.StatusConflict)
}
