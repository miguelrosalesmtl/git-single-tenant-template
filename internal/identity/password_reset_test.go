package identity

import (
	"context"
	"errors"
	"testing"
)

func TestPasswordResetFlow(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "reset@example.com", testPassword, "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	oldToken, _, err := svc.Login(ctx, "reset@example.com", testPassword, RequestMeta{})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if err := svc.RequestPasswordReset(ctx, "Reset@Example.com", RequestMeta{}); err != nil {
		t.Fatalf("request reset: %v", err)
	}
	msg := testMailer.lastTo(t, "reset@example.com")
	token := tokenFromLink(t, msg.Body)

	const newPassword = "a-different-strong-password"
	if err := svc.ResetPassword(ctx, token, newPassword); err != nil {
		t.Fatalf("reset password: %v", err)
	}

	// Resetting revokes every existing session -- an attacker's stolen session
	// included.
	if _, _, err := svc.Authenticate(ctx, oldToken); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("old session survived a password reset: err = %v", err)
	}

	if _, _, err := svc.Login(ctx, "reset@example.com", testPassword, RequestMeta{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("old password still works after a reset")
	}
	if _, _, err := svc.Login(ctx, "reset@example.com", newPassword, RequestMeta{}); err != nil {
		t.Errorf("new password does not work: %v", err)
	}

	// The token is single-use.
	if err := svc.ResetPassword(ctx, token, "yet-another-password-1234"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("reuse reset token: err = %v, want ErrInvalidToken", err)
	}
	_ = user
}

func TestPasswordResetNeverDisclosesWhetherTheAccountExists(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Every one of these must return nil -- an unknown email, a real one, a
	// deactivated account. Anything else is an account-enumeration oracle on an
	// unauthenticated endpoint.
	if err := svc.RequestPasswordReset(ctx, "nobody-at-all@example.com", RequestMeta{}); err != nil {
		t.Errorf("unknown email returned an error: %v", err)
	}

	if _, err := svc.Register(ctx, "real@example.com", testPassword, ""); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := svc.RequestPasswordReset(ctx, "real@example.com", RequestMeta{}); err != nil {
		t.Errorf("known email returned an error: %v", err)
	}
}

func TestResetPasswordBadToken(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.ResetPassword(ctx, "not-a-real-token", "some-new-password-1234"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("bad token error = %v, want ErrInvalidToken", err)
	}
}
