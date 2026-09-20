// Package identity owns users, roles, permissions, sessions, API keys, and
// invitations -- everything needed to answer "who is calling, and what may they
// do?" for a single-tenant application: one installation, many users, no
// per-tenant boundary.
//
// It is the part of the template you keep. Your product's own packages sit
// beside it and depend on it for the caller's identity and permissions.
package identity

import (
	"time"

	"github.com/google/uuid"
)

// Role is a named bundle of permissions.
//
// Roles are DATA: an admin holding roles.create/update/delete creates and edits
// them at runtime. Permissions are CODE (see permissions.go). What you configure
// is which permissions a role bundles -- not which permissions exist.
//
// A role is one of two kinds:
//
//   - System (IsSystem true): admin and member. Ships with the application and is
//     immutable through the API -- so the installation cannot lock itself out by
//     stripping every permission from "admin".
//   - Custom (IsSystem false): created by an admin at runtime, and may be edited
//     or deleted. This is where "Billing Manager" lives.
type Role struct {
	ID uuid.UUID `json:"id"`
	// Key is the stable identifier, e.g. "billing_manager". Globally unique.
	Key string `json:"key"`
	// Name is the human label shown in a UI, e.g. "Billing Manager".
	Name string `json:"name"`
	// IsSystem marks a role the application depends on. Immutable through the API.
	IsSystem bool `json:"is_system"`
	// Permissions is what the role grants. The configurable part.
	Permissions PermissionSet `json:"permissions"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// The keys of the two system roles. They are strings, not a Role type: a role is
// now a row, and these merely name the ones the application ships with and
// depends on.
const (
	// RoleKeyAdmin holds every permission by default. The last user holding it
	// cannot be stripped of it, nor can that last holder be deactivated -- an
	// installation with no admin would have nobody able to grant roles or manage
	// anyone else through the ordinary API. (The superuser CLI escape hatch always
	// remains, see User.IsSuperuser.)
	RoleKeyAdmin = "admin"
	// RoleKeyMember can see the user directory. Nothing more, by default -- but it
	// is an ordinary role like any other, and its permissions can be changed.
	RoleKeyMember = "member"
)

// User is an account in this installation.
type User struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	FullName string    `json:"full_name"`

	// IsSuperuser is the only privilege that outranks RBAC entirely: it holds every
	// permission in the catalog regardless of which roles the account holds, and it
	// cannot be locked out by any role change.
	//
	// It cannot be granted over HTTP. The only way to set it is the CLI
	// (`server grant-superuser <email>`), which requires database access -- so
	// acquiring it takes more than a stolen bearer token, and a compromised
	// superuser account cannot mint more of itself.
	IsSuperuser bool `json:"is_superuser"`

	// IsActive gates login and every authenticated request: deactivating a user
	// takes effect on their very next request, because the session lookup joins
	// against it.
	IsActive bool `json:"is_active"`

	// EmailVerifiedAt is when the user proved they control the address -- by
	// clicking a link sent to it, or by redeeming an invitation that was emailed
	// there, which is the same proof by a different route.
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// PasswordHash never leaves the process: it is json:"-" so that a User can
	// be handed straight to an HTTP response encoder without leaking it.
	PasswordHash string `json:"-"`
}

// IsVerified reports whether the user has proved control of their email address.
func (u User) IsVerified() bool { return u.EmailVerifiedAt != nil }

// Access is the answer to "may this caller do X?". It is what the authorization
// middleware puts on the request context, and the only thing a handler needs to
// consult.
//
// Permissions is the union of every role the caller holds. That union is the
// whole reason a user can hold several roles: "Member" plus "Billing Manager" is
// a person who can do both, without anyone having to invent a "Member Who Also
// Does Billing" role.
type Access struct {
	// Roles are the roles the caller holds, for display. Empty for a superuser
	// (who holds no role; they simply outrank the question) and for an API key
	// (which holds a frozen scope, not roles).
	Roles []Role `json:"roles"`
	// Permissions is the union of those roles' permissions. Every authorization
	// check reads this and nothing else.
	Permissions PermissionSet `json:"permissions"`
	// ViaSuperuser reports that access came from the global superuser flag rather
	// than from assigned roles. Permissions is then the entire catalog.
	ViaSuperuser bool `json:"via_superuser,omitempty"`
	// ViaAPIKey reports that access came from an API key rather than a logged-in
	// human. Permissions is then the key's frozen scope.
	ViaAPIKey bool `json:"via_api_key,omitempty"`
}

// Can reports whether the caller may perform p. This is the single question
// every authorization check in the application asks.
func (a Access) Can(p Permission) bool {
	return a.Permissions.Has(p)
}

// UserSummary is a user plus the roles they hold and the union of those roles'
// permissions -- what the user directory (GET /users) lists.
type UserSummary struct {
	User        User          `json:"user"`
	Roles       []Role        `json:"roles"`
	Permissions PermissionSet `json:"permissions"`
}

// Session is a live login. The plaintext token exists only in the login response
// and in the client's hands; this struct holds its digest.
type Session struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	UserAgent  string     `json:"user_agent"`
	IPAddress  string     `json:"ip_address,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`

	TokenHash []byte `json:"-"`
}

// Invitation is a pending offer to create an account, addressed to an email that
// has no account yet. Accepting it is what creates the user -- see
// Service.AcceptInvitation.
//
// It points at a role row rather than carrying a role string, so an admin can
// invite somebody directly into a custom role.
type Invitation struct {
	ID         uuid.UUID  `json:"id"`
	Email      string     `json:"email"`
	Role       Role       `json:"role"`
	InvitedBy  *uuid.UUID `json:"invited_by,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`

	TokenHash []byte `json:"-"`
}

// Pending reports whether the invitation can still be accepted: not already
// accepted, not revoked, not expired.
func (i Invitation) Pending(now time.Time) bool {
	return i.AcceptedAt == nil && i.RevokedAt == nil && i.ExpiresAt.After(now)
}

// APIKey is a programmatic credential, owned by the user who created it. It
// authenticates like a session -- the plaintext token is shown once and only its
// hash is stored -- but carries its own frozen set of permissions rather than its
// owner's roles.
type APIKey struct {
	ID     uuid.UUID `json:"id"`
	UserID uuid.UUID `json:"user_id"`
	Name   string    `json:"name"`
	// TokenPrefix is a short, non-secret slice of the plaintext, so a key is
	// identifiable in a list without ever revealing the whole secret again.
	TokenPrefix string        `json:"token_prefix"`
	Permissions PermissionSet `json:"permissions"`
	ExpiresAt   *time.Time    `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time    `json:"last_used_at,omitempty"`
	RevokedAt   *time.Time    `json:"revoked_at,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
}

// unionPermissions returns the combined permissions of a set of roles. This is
// what a user "can do": hold two roles, get both their powers.
func unionPermissions(roles []Role) PermissionSet {
	out := PermissionSet{}
	for _, r := range roles {
		for p := range r.Permissions {
			out[p] = struct{}{}
		}
	}
	return out
}

// hasRole reports whether any of the roles has the given key.
func hasRole(roles []Role, key string) bool {
	for _, r := range roles {
		if r.IsSystem && r.Key == key {
			return true
		}
	}
	return false
}
