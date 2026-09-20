package identity

import (
	"context"
	"errors"
	"testing"
)

func TestAPIKeyLifecycle(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	admin := makeAdmin(t, svc, "admin@example.com")
	access := accessFor(t, svc, admin)

	key, token, err := svc.CreateAPIKey(ctx, admin, access, "ci key", []Permission{PermUsersRead}, nil)
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	if token == "" {
		t.Fatal("create api key returned an empty token")
	}
	if key.UserID != admin.ID {
		t.Errorf("key owner = %s, want %s", key.UserID, admin.ID)
	}

	authedKey, actor, err := svc.AuthenticateAPIKey(ctx, token)
	if err != nil {
		t.Fatalf("authenticate api key: %v", err)
	}
	if actor.ID != admin.ID {
		t.Error("api key should authenticate as its owning user")
	}
	if !authedKey.Permissions.Has(PermUsersRead) {
		t.Error("authenticated key lost its permission scope")
	}

	keys, err := svc.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("list api keys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(keys))
	}

	if err := svc.RevokeAPIKey(ctx, admin, key.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, err := svc.AuthenticateAPIKey(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("revoked key still authenticates: err = %v", err)
	}
}

func TestAPIKeyEscalationGuard(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	member, err := svc.Register(ctx, "member@example.com", testPassword, "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	memberRoleID := systemRoleID(t, svc, RoleKeyMember)
	if err := svc.repo.AddUserRole(ctx, member.ID, memberRoleID); err != nil {
		t.Fatalf("assign member role: %v", err)
	}
	member, err = svc.repo.GetUserByID(ctx, member.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	access := accessFor(t, svc, member)

	// A plain member holds only users.read, and cannot mint a key that can
	// also update users.
	_, _, err = svc.CreateAPIKey(ctx, member, access, "too powerful", []Permission{PermUsersRead, PermUsersUpdate}, nil)
	if !errors.Is(err, ErrEscalation) {
		t.Fatalf("mint a key beyond own permissions: err = %v, want ErrEscalation", err)
	}
}

func TestAPIKeyDisabledWhenOwnerDeactivated(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	admin := makeAdmin(t, svc, "admin@example.com")
	access := accessFor(t, svc, admin)
	second := makeAdmin(t, svc, "second-admin@example.com") // so admin isn't the last

	_, token, err := svc.CreateAPIKey(ctx, admin, access, "personal key", []Permission{PermUsersRead}, nil)
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}

	if _, err := svc.SetUserActive(ctx, second, admin.ID, false); err != nil {
		t.Fatalf("deactivate key owner: %v", err)
	}

	if _, _, err := svc.AuthenticateAPIKey(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("deactivated owner's key still authenticates: err = %v", err)
	}
}
