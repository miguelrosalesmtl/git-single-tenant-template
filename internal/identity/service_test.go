package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

const testPassword = "correct-horse-battery-staple"

func TestRegisterAndLogin(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "Alice@Example.com", testPassword, "Alice")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Errorf("email = %q, want normalised lowercase", user.Email)
	}
	if user.IsVerified() {
		t.Error("a freshly registered user should not be verified yet")
	}

	// Registering the same email again is a conflict, not a silent success.
	if _, err := svc.Register(ctx, "alice@example.com", testPassword, "Alice Two"); !errors.Is(err, ErrEmailTaken) {
		t.Errorf("duplicate register error = %v, want ErrEmailTaken", err)
	}

	token, loggedIn, err := svc.Login(ctx, "alice@example.com", testPassword, RequestMeta{})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if token == "" {
		t.Error("login returned an empty token")
	}
	if loggedIn.ID != user.ID {
		t.Errorf("login returned a different user")
	}

	if _, _, err := svc.Login(ctx, "alice@example.com", "wrong-password", RequestMeta{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password error = %v, want ErrInvalidCredentials", err)
	}
	if _, _, err := svc.Login(ctx, "nobody@example.com", testPassword, RequestMeta{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown email error = %v, want ErrInvalidCredentials (must not be distinguishable)", err)
	}

	authed, _, err := svc.Authenticate(ctx, token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if authed.ID != user.ID {
		t.Error("authenticate resolved to a different user")
	}

	if err := svc.Logout(ctx, token, user.ID); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, _, err := svc.Authenticate(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("post-logout authenticate error = %v, want ErrUnauthenticated", err)
	}
}

func TestRegisterValidation(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Register(ctx, "not-an-email", testPassword, ""); !errors.Is(err, ErrValidation) {
		t.Errorf("bad email error = %v, want ErrValidation", err)
	}
	if _, err := svc.Register(ctx, "alice@example.com", "short", ""); !errors.Is(err, ErrValidation) {
		t.Errorf("short password error = %v, want ErrValidation", err)
	}
}

func TestChangePasswordRevokesEverySession(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "bob@example.com", testPassword, "Bob")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	token, _, err := svc.Login(ctx, "bob@example.com", testPassword, RequestMeta{})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	const newPassword = "a-brand-new-password-1234"
	if err := svc.ChangePassword(ctx, user.ID, testPassword, newPassword); err != nil {
		t.Fatalf("change password: %v", err)
	}

	// The very session making the change is revoked too -- a password change that
	// leaves a stolen session alive has achieved nothing.
	if _, _, err := svc.Authenticate(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("old session survived a password change: err = %v", err)
	}

	if _, _, err := svc.Login(ctx, "bob@example.com", testPassword, RequestMeta{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("old password still works after a change")
	}
	if _, _, err := svc.Login(ctx, "bob@example.com", newPassword, RequestMeta{}); err != nil {
		t.Errorf("new password does not work: %v", err)
	}
}

func TestRevokeSessionIsScopedToOwner(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	alice, err := svc.Register(ctx, "alice2@example.com", testPassword, "Alice")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	if _, err := svc.Register(ctx, "carol@example.com", testPassword, "Carol"); err != nil {
		t.Fatalf("register carol: %v", err)
	}
	carol, err := svc.repo.GetUserByEmail(ctx, "carol@example.com")
	if err != nil {
		t.Fatalf("get carol: %v", err)
	}

	if _, _, err := svc.Login(ctx, "carol@example.com", testPassword, RequestMeta{}); err != nil {
		t.Fatalf("login carol: %v", err)
	}
	sessions, err := svc.ListSessions(ctx, carol.ID)
	if err != nil || len(sessions) == 0 {
		t.Fatalf("list carol's sessions: %v (%d)", err, len(sessions))
	}

	// Alice cannot revoke Carol's session by guessing its id.
	if err := svc.RevokeSession(ctx, alice, sessions[0].ID); !isNotFound(err) {
		t.Errorf("cross-user session revoke error = %v, want ErrNotFound", err)
	}
}

func TestSuperuserBypassesRBACEntirely(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "root@example.com", testPassword, "Root")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	access := accessFor(t, svc, user)
	if len(access.Permissions) != 0 {
		t.Error("a freshly registered, unelevated user should hold no permissions")
	}

	if _, err := svc.SetSuperuser(ctx, user.Email, true); err != nil {
		t.Fatalf("grant superuser: %v", err)
	}

	elevated, err := svc.repo.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	access = accessFor(t, svc, elevated)
	if !access.ViaSuperuser {
		t.Error("ViaSuperuser should be true once granted")
	}
	if len(access.Permissions) != len(Catalog) {
		t.Errorf("superuser holds %d permissions, want the entire catalog (%d)", len(access.Permissions), len(Catalog))
	}

	if _, err := svc.SetSuperuser(ctx, user.Email, false); err != nil {
		t.Fatalf("revoke superuser: %v", err)
	}
	reverted, err := svc.repo.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	access = accessFor(t, svc, reverted)
	if access.ViaSuperuser || len(access.Permissions) != 0 {
		t.Error("revoking superuser should remove the bypass entirely")
	}
}

func TestSetUserActive(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	admin, err := svc.Register(ctx, "admin@example.com", testPassword, "Admin")
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}
	target, err := svc.Register(ctx, "target@example.com", testPassword, "Target")
	if err != nil {
		t.Fatalf("register target: %v", err)
	}
	token, _, err := svc.Login(ctx, "target@example.com", testPassword, RequestMeta{})
	if err != nil {
		t.Fatalf("login target: %v", err)
	}

	if _, err := svc.SetUserActive(ctx, admin, target.ID, false); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	// Deactivation revokes sessions immediately -- not "eventually, on expiry".
	if _, _, err := svc.Authenticate(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("deactivated user's session still authenticates: err = %v", err)
	}
	if _, _, err := svc.Login(ctx, "target@example.com", testPassword, RequestMeta{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("deactivated user can still log in")
	}

	// You cannot deactivate yourself -- that would risk locking out the only
	// person who could undo it.
	if _, err := svc.SetUserActive(ctx, admin, admin.ID, false); !errors.Is(err, ErrValidation) {
		t.Errorf("self-deactivate error = %v, want ErrValidation", err)
	}

	if _, err := svc.SetUserActive(ctx, admin, target.ID, true); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if _, _, err := svc.Login(ctx, "target@example.com", testPassword, RequestMeta{}); err != nil {
		t.Errorf("reactivated user cannot log in: %v", err)
	}
}

func TestListUsersPagination(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	for _, email := range []string{"one@example.com", "two@example.com", "three@example.com"} {
		if _, err := svc.Register(ctx, email, testPassword, ""); err != nil {
			t.Fatalf("register %s: %v", email, err)
		}
	}

	page, err := svc.ListUsers(ctx, uuid.Nil, 2)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(page) != 2 {
		t.Fatalf("page size = %d, want 2", len(page))
	}

	rest, err := svc.ListUsers(ctx, page[len(page)-1].User.ID, 2)
	if err != nil {
		t.Fatalf("list users page 2: %v", err)
	}
	if len(rest) != 1 {
		t.Fatalf("second page size = %d, want 1", len(rest))
	}
	if rest[0].User.ID == page[0].User.ID || rest[0].User.ID == page[1].User.ID {
		t.Error("second page repeated a user from the first")
	}
}
