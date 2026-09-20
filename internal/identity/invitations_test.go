package identity

import (
	"context"
	"errors"
	"testing"
)

func TestInviteAndAccept(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	admin := makeAdmin(t, svc, "admin@example.com")
	access := accessFor(t, svc, admin)
	memberRoleID := systemRoleID(t, svc, RoleKeyMember)

	inv, err := svc.Invite(ctx, admin, access, "New.Invitee@Example.com", memberRoleID)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if inv.Email != "new.invitee@example.com" {
		t.Errorf("invitation email = %q, want normalised", inv.Email)
	}

	msg := testMailer.lastTo(t, "new.invitee@example.com")
	token := tokenFromLink(t, msg.Body)

	user, err := svc.AcceptInvitation(ctx, token, testPassword, "New Invitee")
	if err != nil {
		t.Fatalf("accept invitation: %v", err)
	}
	if user.Email != "new.invitee@example.com" {
		t.Errorf("created user email = %q", user.Email)
	}
	if !user.IsVerified() {
		t.Error("accepting an invitation should verify the email -- the token proved control of the mailbox")
	}

	// The invited role landed.
	roles, err := svc.repo.LoadUserRoles(ctx, user.ID)
	if err != nil {
		t.Fatalf("load roles: %v", err)
	}
	if !hasRole(roles, RoleKeyMember) {
		t.Errorf("accepted user roles = %+v, want member", roles)
	}

	// The new account can log in with the password it set.
	if _, _, err := svc.Login(ctx, "new.invitee@example.com", testPassword, RequestMeta{}); err != nil {
		t.Errorf("login with invitation password: %v", err)
	}

	// The token is single-use.
	if _, err := svc.AcceptInvitation(ctx, token, testPassword, "Again"); !errors.Is(err, ErrInvitationInvalid) {
		t.Errorf("reuse invitation token: err = %v, want ErrInvitationInvalid", err)
	}
}

func TestInviteRefusesAnAlreadyRegisteredEmail(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	admin := makeAdmin(t, svc, "admin@example.com")
	access := accessFor(t, svc, admin)
	memberRoleID := systemRoleID(t, svc, RoleKeyMember)

	if _, err := svc.Register(ctx, "existing@example.com", testPassword, ""); err != nil {
		t.Fatalf("register: %v", err)
	}

	_, err := svc.Invite(ctx, admin, access, "existing@example.com", memberRoleID)
	if !errors.Is(err, ErrEmailTaken) {
		t.Errorf("invite an existing account: err = %v, want ErrEmailTaken", err)
	}
}

func TestInviteEscalationGuard(t *testing.T) {
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
	adminRoleID := systemRoleID(t, svc, RoleKeyAdmin)

	// A plain member cannot invite somebody straight into the admin role -- they
	// do not hold admin's permissions themselves.
	_, err = svc.Invite(ctx, member, access, "wannabe@example.com", adminRoleID)
	if !errors.Is(err, ErrEscalation) {
		t.Errorf("invite into admin without holding it: err = %v, want ErrEscalation", err)
	}
}

func TestReInviteReplacesThePendingInvitation(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	admin := makeAdmin(t, svc, "admin@example.com")
	access := accessFor(t, svc, admin)
	memberRoleID := systemRoleID(t, svc, RoleKeyMember)

	first, err := svc.Invite(ctx, admin, access, "twice@example.com", memberRoleID)
	if err != nil {
		t.Fatalf("first invite: %v", err)
	}
	firstMsg := testMailer.lastTo(t, "twice@example.com")
	firstToken := tokenFromLink(t, firstMsg.Body)

	second, err := svc.Invite(ctx, admin, access, "twice@example.com", memberRoleID)
	if err != nil {
		t.Fatalf("second invite: %v", err)
	}
	if second.ID == first.ID {
		t.Error("re-inviting should mint a new invitation, not return the old one")
	}

	// The first link no longer works.
	if _, err := svc.AcceptInvitation(ctx, firstToken, testPassword, ""); !errors.Is(err, ErrInvitationInvalid) {
		t.Errorf("old invitation link still valid: err = %v", err)
	}
}

func TestRevokeInvitation(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	admin := makeAdmin(t, svc, "admin@example.com")
	access := accessFor(t, svc, admin)
	memberRoleID := systemRoleID(t, svc, RoleKeyMember)

	inv, err := svc.Invite(ctx, admin, access, "revoke-me@example.com", memberRoleID)
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	msg := testMailer.lastTo(t, "revoke-me@example.com")
	token := tokenFromLink(t, msg.Body)

	if err := svc.RevokeInvitation(ctx, admin, inv.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.AcceptInvitation(ctx, token, testPassword, ""); !errors.Is(err, ErrInvitationInvalid) {
		t.Errorf("accept a revoked invitation: err = %v, want ErrInvitationInvalid", err)
	}
}

func TestAcceptInvitationBadToken(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.AcceptInvitation(ctx, "not-a-real-token", testPassword, ""); !errors.Is(err, ErrInvitationInvalid) {
		t.Errorf("bad token error = %v, want ErrInvitationInvalid", err)
	}
}
