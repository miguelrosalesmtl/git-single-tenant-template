package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// makeAdmin registers a user and grants them the system admin role directly,
// bypassing the escalation guard the way the CLI bootstrap command does. Tests
// use it to get a first administrator into an otherwise-empty installation.
func makeAdmin(t *testing.T, svc *Service, email string) User {
	t.Helper()
	user, err := svc.Register(context.Background(), email, testPassword, "")
	if err != nil {
		t.Fatalf("register %s: %v", email, err)
	}
	if _, _, err := svc.GrantRoleByKey(context.Background(), email, RoleKeyAdmin); err != nil {
		t.Fatalf("grant admin to %s: %v", email, err)
	}
	reloaded, err := svc.repo.GetUserByID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("reload %s: %v", email, err)
	}
	return reloaded
}

func TestSystemRolesAreSeeded(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	roles, err := svc.ListRoles(ctx)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	var haveAdmin, haveMember bool
	for _, r := range roles {
		if !r.IsSystem {
			t.Errorf("role %q from a clean database should be a system role", r.Key)
		}
		switch r.Key {
		case RoleKeyAdmin:
			haveAdmin = true
			if !r.Permissions.Has(PermUsersUpdate) {
				t.Error("admin should hold users.update")
			}
		case RoleKeyMember:
			haveMember = true
			if !r.Permissions.Has(PermUsersRead) {
				t.Error("member should hold users.read")
			}
		}
	}
	if !haveAdmin || !haveMember {
		t.Fatalf("expected both system roles, got %+v", roles)
	}
}

func TestEscalationGuardOnCreateRole(t *testing.T) {
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
		t.Fatalf("reload member: %v", err)
	}
	access := accessFor(t, svc, member)

	// A plain member holds only users.read. Trying to mint a role that also
	// grants users.update must fail: you cannot hand out what you do not hold.
	_, err = svc.CreateRole(ctx, member, access, "sneaky", "Sneaky", []Permission{PermUsersRead, PermUsersUpdate})
	if !errors.Is(err, ErrEscalation) {
		t.Fatalf("create role beyond own permissions: err = %v, want ErrEscalation", err)
	}

	// A role made only of permissions the caller already holds succeeds.
	role, err := svc.CreateRole(ctx, member, access, "auditor", "Auditor", []Permission{PermUsersRead})
	if err != nil {
		t.Fatalf("create role within own permissions: %v", err)
	}
	if role.IsSystem {
		t.Error("a custom role must not be marked is_system")
	}
}

func TestCannotShadowASystemRoleKey(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	admin := makeAdmin(t, svc, "admin@example.com")
	access := accessFor(t, svc, admin)

	_, err := svc.CreateRole(ctx, admin, access, RoleKeyAdmin, "Fake Admin", []Permission{PermUsersRead})
	if !errors.Is(err, ErrRoleKeyTaken) {
		t.Errorf("shadow a system role key: err = %v, want ErrRoleKeyTaken", err)
	}
}

func TestSystemRolesAreImmutable(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	admin := makeAdmin(t, svc, "admin@example.com")
	access := accessFor(t, svc, admin)
	adminRoleID := systemRoleID(t, svc, RoleKeyAdmin)

	if _, err := svc.UpdateRole(ctx, admin, access, adminRoleID, "Renamed", []Permission{PermUsersRead}); !errors.Is(err, ErrSystemRole) {
		t.Errorf("update system role: err = %v, want ErrSystemRole", err)
	}
	if err := svc.DeleteRole(ctx, admin, access, adminRoleID); !errors.Is(err, ErrSystemRole) {
		t.Errorf("delete system role: err = %v, want ErrSystemRole", err)
	}
}

func TestDeleteRoleInUse(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	admin := makeAdmin(t, svc, "admin@example.com")
	access := accessFor(t, svc, admin)

	role, err := svc.CreateRole(ctx, admin, access, "billing", "Billing", []Permission{PermUsersRead})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	holder, err := svc.Register(ctx, "holder@example.com", testPassword, "")
	if err != nil {
		t.Fatalf("register holder: %v", err)
	}
	if err := svc.SetUserRoles(ctx, admin, access, holder.ID, []uuid.UUID{role.ID}); err != nil {
		t.Fatalf("assign role: %v", err)
	}

	if err := svc.DeleteRole(ctx, admin, access, role.ID); !errors.Is(err, ErrRoleInUse) {
		t.Errorf("delete role in use: err = %v, want ErrRoleInUse", err)
	}

	// Reassign, then deletion succeeds.
	if err := svc.SetUserRoles(ctx, admin, access, holder.ID, nil); err != nil {
		t.Fatalf("clear roles: %v", err)
	}
	if err := svc.DeleteRole(ctx, admin, access, role.ID); err != nil {
		t.Errorf("delete role after reassignment: %v", err)
	}
}

func TestSetUserRolesEscalationGuard(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	member, err := svc.Register(ctx, "member2@example.com", testPassword, "")
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

	target, err := svc.Register(ctx, "target2@example.com", testPassword, "")
	if err != nil {
		t.Fatalf("register target: %v", err)
	}
	adminRoleID := systemRoleID(t, svc, RoleKeyAdmin)

	// A member cannot promote anyone to admin -- they do not hold admin's
	// permissions themselves.
	err = svc.SetUserRoles(ctx, member, access, target.ID, []uuid.UUID{adminRoleID})
	if !errors.Is(err, ErrEscalation) {
		t.Errorf("member promoting to admin: err = %v, want ErrEscalation", err)
	}
}

func TestLastAdminCannotBeDemoted(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	admin := makeAdmin(t, svc, "solo-admin@example.com")
	access := accessFor(t, svc, admin)

	// The sole admin cannot even demote themself: doing so would leave the
	// installation unadministrable through the ordinary API.
	err := svc.SetUserRoles(ctx, admin, access, admin.ID, nil)
	if !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote the last admin: err = %v, want ErrLastAdmin", err)
	}

	// Once a second admin exists, the first can step down safely.
	second := makeAdmin(t, svc, "second-admin@example.com")
	_ = second
	if err := svc.SetUserRoles(ctx, admin, access, admin.ID, nil); err != nil {
		t.Errorf("demote non-last admin: %v", err)
	}
}

func TestOnlyAnAdminMayDemoteAnAdmin(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	adminA := makeAdmin(t, svc, "admin-a@example.com")
	adminB := makeAdmin(t, svc, "admin-b@example.com")

	member, err := svc.Register(ctx, "member3@example.com", testPassword, "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	memberRoleID := systemRoleID(t, svc, RoleKeyMember)

	// Give the member EVERY permission via a custom role, so checkEscalation
	// alone would not stop them -- only the "demoting an admin is an admin-level
	// act" rule can.
	adminAccess := accessFor(t, svc, adminA) // adminA mints the role
	all := make([]Permission, 0, len(Catalog))
	for _, e := range Catalog {
		all = append(all, e.Key)
	}
	everything, err := svc.CreateRole(ctx, adminA, adminAccess, "god_mode", "God Mode", all)
	if err != nil {
		t.Fatalf("create all-permissions role: %v", err)
	}
	if err := svc.repo.AddUserRole(ctx, member.ID, everything.ID); err != nil {
		t.Fatalf("assign god_mode: %v", err)
	}
	if err := svc.repo.AddUserRole(ctx, member.ID, memberRoleID); err != nil {
		t.Fatalf("assign member: %v", err)
	}
	member, err = svc.repo.GetUserByID(ctx, member.ID)
	if err != nil {
		t.Fatalf("reload member: %v", err)
	}
	access := accessFor(t, svc, member)

	err = svc.SetUserRoles(ctx, member, access, adminB.ID, nil)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin demoting an admin: err = %v, want ErrForbidden", err)
	}
}
