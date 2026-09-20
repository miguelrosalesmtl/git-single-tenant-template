package identity

import (
	"context"
	"errors"
	"testing"
)

func TestEmailVerificationFlow(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "verify@example.com", testPassword, "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if user.IsVerified() {
		t.Fatal("a freshly registered user should not be verified")
	}

	msg := testMailer.lastTo(t, "verify@example.com")
	token := tokenFromLink(t, msg.Body)

	verified, err := svc.VerifyEmail(ctx, token)
	if err != nil {
		t.Fatalf("verify email: %v", err)
	}
	if !verified.IsVerified() {
		t.Error("VerifyEmail did not mark the address verified")
	}

	// The token is single-use.
	if _, err := svc.VerifyEmail(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("reuse verification token: err = %v, want ErrInvalidToken", err)
	}
}

func TestResendVerification(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	user, err := svc.Register(ctx, "resend@example.com", testPassword, "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	first := tokenFromLink(t, testMailer.lastTo(t, "resend@example.com").Body)

	if err := svc.ResendVerification(ctx, user); err != nil {
		t.Fatalf("resend: %v", err)
	}
	second := tokenFromLink(t, testMailer.lastTo(t, "resend@example.com").Body)

	if first == second {
		t.Fatal("resend should mint a fresh token")
	}

	// The old link no longer works; only the newest does.
	if _, err := svc.VerifyEmail(ctx, first); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("old verification link still valid: err = %v", err)
	}
	if _, err := svc.VerifyEmail(ctx, second); err != nil {
		t.Errorf("newest verification link failed: %v", err)
	}

	// Resending once already verified is refused -- there's nothing to confirm.
	verified, err := svc.repo.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := svc.ResendVerification(ctx, verified); !errors.Is(err, ErrValidation) {
		t.Errorf("resend for an already-verified address: err = %v, want ErrValidation", err)
	}
}

func TestVerifyEmailBadToken(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if _, err := svc.VerifyEmail(ctx, "not-a-real-token"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("bad token error = %v, want ErrInvalidToken", err)
	}
}
