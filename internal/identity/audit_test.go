package identity

import (
	"context"
	"testing"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
)

func TestAuditRecordsSuccessAndFailedLogins(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "alice@example.com", testPassword, "Alice")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, _, err := svc.Login(ctx, "alice@example.com", testPassword, RequestMeta{}); err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, _, err := svc.Login(ctx, "alice@example.com", "wrong", RequestMeta{}); err == nil {
		t.Fatal("expected the bad login to fail")
	}

	rec := audit.NewRecorder(testPool)
	entries, err := rec.List(ctx, audit.Filter{ActorUserID: &user.ID})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	var sawRegistered, sawLoggedIn, sawFailed bool
	for _, e := range entries {
		switch e.Action {
		case audit.ActionUserRegistered:
			sawRegistered = true
		case audit.ActionUserLoggedIn:
			sawLoggedIn = true
		case audit.ActionLoginFailed:
			sawFailed = true
		}
	}
	if !sawRegistered || !sawLoggedIn || !sawFailed {
		t.Errorf("missing expected audit entries: registered=%v loggedIn=%v failed=%v (got %d entries)",
			sawRegistered, sawLoggedIn, sawFailed, len(entries))
	}
}

func TestAuditFiltersByAction(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	admin := makeAdmin(t, svc, "admin@example.com")
	access := accessFor(t, svc, admin)

	if _, err := svc.CreateRole(ctx, admin, access, "auditor", "Auditor", []Permission{PermUsersRead}); err != nil {
		t.Fatalf("create role: %v", err)
	}

	rec := audit.NewRecorder(testPool)
	entries, err := rec.List(ctx, audit.Filter{Action: audit.ActionRoleCreated})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].TargetType != "role" {
		t.Errorf("target type = %q, want role", entries[0].TargetType)
	}
}

func TestAuditKeysetPagination(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "paginate@example.com", testPassword, "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	for i := range 3 {
		if err := svc.Logout(ctx, "", user.ID); err != nil {
			t.Fatalf("logout %d: %v", i, err)
		}
	}

	rec := audit.NewRecorder(testPool)
	page, err := rec.List(ctx, audit.Filter{ActorUserID: &user.ID, Limit: 2})
	if err != nil {
		t.Fatalf("list page 1: %v", err)
	}
	if len(page) != 2 {
		t.Fatalf("page size = %d, want 2", len(page))
	}

	rest, err := rec.List(ctx, audit.Filter{ActorUserID: &user.ID, Before: page[len(page)-1].ID})
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	for _, e := range rest {
		if e.ID == page[0].ID || e.ID == page[1].ID {
			t.Error("second page repeated an entry from the first")
		}
	}
}
