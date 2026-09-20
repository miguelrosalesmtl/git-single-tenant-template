package identity

import "errors"

// The errors the service returns. The HTTP layer maps each to a status code in
// one place (see internal/server/response.go), so handlers never invent their
// own error semantics.
var (
	// ErrNotFound means the requested row does not exist.
	ErrNotFound = errors.New("identity: not found")

	// ErrInvalidCredentials is returned for a bad email, a bad password, and a
	// deactivated account alike. Never let the caller tell them apart: any
	// distinction is an oracle for enumerating registered accounts.
	ErrInvalidCredentials = errors.New("identity: invalid credentials")

	// ErrUnauthenticated means no valid session token or API key accompanied the
	// request.
	ErrUnauthenticated = errors.New("identity: unauthenticated")

	// ErrForbidden means the caller is authenticated but their role is too weak
	// for this action.
	ErrForbidden = errors.New("identity: forbidden")

	// ErrEmailTaken is returned when registering, or inviting, an email that
	// already has an account. This is an unavoidable disclosure at the
	// registration endpoint; rate-limit it (see the README) rather than
	// pretending to succeed.
	ErrEmailTaken = errors.New("identity: email already registered")

	// ErrInvitationInvalid covers an invitation token that is unknown, already
	// accepted, revoked, or expired -- collapsed, so a probe cannot learn which.
	ErrInvitationInvalid = errors.New("identity: invitation is invalid or has expired")

	// ErrLastAdmin is returned when removing the admin role from its final
	// holder, or deactivating that person, which would leave the installation
	// permanently unadministrable through the ordinary API -- nobody could grant
	// roles, invite anyone, or manage anyone else. (The superuser CLI escape
	// hatch is unaffected by this guard.)
	ErrLastAdmin = errors.New("identity: cannot remove the last admin")

	// ErrEscalation is THE RBAC guard. It is returned when a caller tries to grant
	// a permission they do not themselves hold -- by putting it in a role they are
	// creating or editing, or by assigning someone a role that carries it.
	//
	// Without this rule, RBAC defeats itself: anyone with roles.create would simply
	// mint a role holding every permission and assign it to themselves. The same
	// rule also stops a member assigning the system "admin" role, because admin
	// carries permissions a member lacks -- no special case needed.
	ErrEscalation = errors.New("identity: you cannot grant a permission you do not hold")

	// ErrSystemRole is returned when trying to edit or delete a role the
	// application ships and depends on (admin, member). They are immutable so
	// that the installation cannot lock itself out -- by, say, stripping every
	// permission from "admin".
	ErrSystemRole = errors.New("identity: system roles cannot be modified or deleted")

	// ErrRoleInUse is returned when deleting a role that users still hold. The
	// caller must reassign them first; silently stripping people's access as a
	// side effect of a delete is not something to do quietly.
	ErrRoleInUse = errors.New("identity: this role is still assigned to users")

	// ErrRoleKeyTaken is returned when creating a role whose key is already in
	// use -- including the keys of the system roles.
	ErrRoleKeyTaken = errors.New("identity: a role with that key already exists")

	// ErrInvalidToken covers a password-reset or email-verification token that is
	// unknown, already spent, or expired -- collapsed, as ever, so a probe cannot
	// learn which.
	ErrInvalidToken = errors.New("identity: this link is invalid or has expired")

	// ErrRateLimited means the caller has made too many attempts. It maps to 429.
	ErrRateLimited = errors.New("identity: too many attempts")

	// ErrMailFailed means the thing was created but the email announcing it did not
	// go out. It is NOT a failure of the operation: the invitation exists, and the
	// caller can resend it.
	//
	// It has its own error because the alternative -- failing the request -- would
	// be worse. The admin would retry, re-inviting revokes and reissues the token,
	// and they would accumulate dead invitations while still not knowing what went
	// wrong. A 502 that says "created, but the email did not send" is the honest
	// answer.
	ErrMailFailed = errors.New("identity: the email could not be sent")

	// ErrValidation is the base for input that is malformed. Wrap it with the
	// specific complaint (see validationError) so the message reaches the caller
	// while errors.Is still identifies the class.
	ErrValidation = errors.New("identity: validation failed")
)

// isNotFound is shorthand for errors.Is(err, ErrNotFound), which appears often
// enough in the service to be worth a name.
func isNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// validationError carries a human-readable message while remaining detectable
// via errors.Is(err, ErrValidation).
type validationError struct{ msg string }

func (e validationError) Error() string { return e.msg }
func (e validationError) Is(target error) bool {
	return target == ErrValidation
}

func invalid(msg string) error { return validationError{msg: msg} }
