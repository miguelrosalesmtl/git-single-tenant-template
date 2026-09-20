package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/auth"
	"github.com/miguelrosalesmtl/go-template/internal/database"
)

// API keys: programmatic credentials, owned by the user who creates them.
//
// A key is the machine counterpart of a session. Where a session derives its
// power from its owner's roles, a key carries a FROZEN set of permissions chosen
// when it is minted. The two are deliberately parallel: both are opaque bearer
// tokens, shown once, stored only as a SHA-256 hash.
//
// The one rule that makes keys safe is the same one that governs roles: you cannot
// mint a key more powerful than yourself. checkEscalation enforces it, so a member
// cannot create a key that can update users when they themselves cannot.

// apiKeyDisplayPrefixLen is how much of the plaintext token is kept, in the clear,
// as an identifier. Enough to tell two keys apart in a list; far too little to
// guess the rest of a 256-bit secret.
const apiKeyDisplayPrefixLen = len(auth.APIKeyTokenPrefix) + 4

// CreateAPIKey mints a key owned by actor and returns it together with its
// plaintext token. THE PLAINTEXT IS RETURNED EXACTLY ONCE, here; it is never
// stored and cannot be shown again. The caller (the HTTP handler) passes it to the
// user, who copies it into their automation.
//
// The caller must hold every permission they are putting into the key -- the same
// escalation guard as creating a role. Without it, apikeys.create would be a
// long-winded way to spell "admin".
func (s *Service) CreateAPIKey(
	ctx context.Context,
	actor User,
	access Access,
	name string,
	perms []Permission,
	expiresAt *time.Time,
) (APIKey, string, error) {
	name, set, err := validateAPIKeyInput(name, perms, expiresAt)
	if err != nil {
		return APIKey{}, "", err
	}
	if err := checkEscalation(access, set); err != nil {
		return APIKey{}, "", err
	}

	plaintext, digest, err := auth.NewToken(auth.APIKeyTokenPrefix)
	if err != nil {
		return APIKey{}, "", err
	}
	displayPrefix := plaintext[:apiKeyDisplayPrefixLen]

	var key APIKey
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		key, err = repo.CreateAPIKey(ctx, actor.ID, name, displayPrefix, digest, set, expiresAt)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID,
			Action:      audit.ActionAPIKeyCreated,
			TargetType:  "api_key",
			TargetID:    key.ID.String(),
			Metadata: map[string]any{
				"name":        name,
				"permissions": set.Slice(),
			},
		})
	})
	if err != nil {
		return APIKey{}, "", err
	}
	return key, plaintext, nil
}

// ListAPIKeys returns every live key in the installation. It never carries a
// token: the plaintext was shown once and only its hash was ever stored.
func (s *Service) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	return s.repo.ListAPIKeys(ctx)
}

// RevokeAPIKey kills a key. It takes effect on the key's very next request, since
// authentication checks revoked_at every time -- the same immediate revocation the
// sessions model gives a human.
func (s *Service) RevokeAPIKey(ctx context.Context, actor User, keyID uuid.UUID) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		key, err := repo.RevokeAPIKey(ctx, keyID)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID,
			Action:      audit.ActionAPIKeyRevoked,
			TargetType:  "api_key",
			TargetID:    key.ID.String(),
			Metadata:    map[string]any{"name": key.Name},
		})
	})
}

// AuthenticateAPIKey resolves a plaintext key token into everything the
// middleware needs to serve the request: the key's permission scope, and the
// user it acts as (its owner). It is the key-authentication counterpart of
// Authenticate for sessions.
//
// The owning user is loaded fresh, so a key cannot outlive a deactivated
// owner -- the repository query already refuses those, and this load then
// succeeds by construction.
func (s *Service) AuthenticateAPIKey(ctx context.Context, token string) (APIKey, User, error) {
	if token == "" {
		return APIKey{}, User{}, ErrUnauthenticated
	}

	key, err := s.repo.AuthenticateAPIKey(ctx, auth.HashToken(token))
	if err != nil {
		return APIKey{}, User{}, err
	}

	actor, err := s.repo.GetUserByID(ctx, key.UserID)
	if err != nil {
		return APIKey{}, User{}, err
	}

	return key, actor, nil
}

// validateAPIKeyInput checks the fields a caller controls when minting a key.
func validateAPIKeyInput(name string, perms []Permission, expiresAt *time.Time) (string, PermissionSet, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", nil, invalid("api key name is required")
	case len(name) > 100:
		return "", nil, invalid("api key name must be at most 100 characters")
	case len(perms) == 0:
		return "", nil, invalid("an api key must grant at least one permission")
	}

	if expiresAt != nil && !expiresAt.After(time.Now()) {
		return "", nil, invalid("api key expiry must be in the future")
	}

	set := PermissionSet{}
	for _, p := range perms {
		if !p.Valid() {
			return "", nil, invalid(fmt.Sprintf("%q is not a permission this application enforces", p))
		}
		set[p] = struct{}{}
	}
	return name, set, nil
}
