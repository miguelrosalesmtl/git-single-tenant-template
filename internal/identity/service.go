package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	netmail "net/mail" // aliased: internal/mail is also imported, for sending
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/auth"
	"github.com/miguelrosalesmtl/go-template/internal/database"
	"github.com/miguelrosalesmtl/go-template/internal/mail"
	"github.com/miguelrosalesmtl/go-template/internal/settings"
)

// Service holds the identity business rules: what must be validated, what must
// happen atomically, and what must be audited. HTTP handlers call it and do
// nothing else of consequence, so the same rules would apply to a gRPC or CLI
// front end.
type Service struct {
	pool    *pgxpool.Pool
	repo    *Repository // pool-backed, for single-statement operations
	hasher  *auth.Hasher
	mailer  mail.Mailer
	cfg     settings.Auth
	mailCfg settings.Mail
	log     *slog.Logger
}

// NewService builds the identity service.
//
// The mailer is a dependency rather than something the service constructs,
// because the two flows that need it -- invitations and password resets -- are the
// two places where getting it wrong is a security bug, and a test must be able to
// see exactly what was sent.
func NewService(
	pool *pgxpool.Pool,
	cfg settings.Auth,
	mailCfg settings.Mail,
	mailer mail.Mailer,
	log *slog.Logger,
) *Service {
	return &Service{
		pool:    pool,
		repo:    NewRepository(pool),
		hasher:  auth.NewHasher(cfg.ArgonMemoryKiB, cfg.ArgonIterations, cfg.ArgonParallelism),
		mailer:  mailer,
		cfg:     cfg,
		mailCfg: mailCfg,
		log:     log,
	}
}

// RequestMeta is the ambient information about an HTTP request that the service
// records on sessions and audit entries.
type RequestMeta struct {
	UserAgent string
	IPAddress string
}

// ---------------------------------------------------------------- registration

// Register creates a user account.
func (s *Service) Register(ctx context.Context, email, password, fullName string) (User, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	if err := s.validatePassword(password); err != nil {
		return User{}, err
	}

	hash, err := s.hasher.Hash(password)
	if err != nil {
		return User{}, err
	}

	var user User
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		user, err = repo.CreateUser(ctx, email, hash, strings.TrimSpace(fullName))
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &user.ID,
			Action:      audit.ActionUserRegistered,
			TargetType:  "user",
			TargetID:    user.ID.String(),
			Metadata:    map[string]any{"email": email},
		})
	})
	if err != nil {
		return User{}, err
	}

	// After the commit, so the token cannot outlive a rolled-back user. A send
	// failure is logged, not returned: registration must not fail because the mail
	// provider hiccuped, and they can always ask for another link.
	s.SendVerificationEmail(ctx, user)

	return user, nil
}

// ---------------------------------------------------------------- sessions

// Login verifies a password and issues a session token. The returned plaintext
// token is the only copy that will ever exist outside the client: the database
// stores its digest.
func (s *Service) Login(ctx context.Context, email, password string, meta RequestMeta) (string, User, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Hash a dummy password anyway. Returning immediately here would make
			// a request for an unregistered email measurably faster than one for a
			// registered email, turning login timing into an account-enumeration
			// oracle -- which is exactly what the identical error message is meant
			// to prevent.
			_, _ = s.hasher.Hash(password)
			s.recordFailedLogin(ctx, email, nil, "unknown_email")
			return "", User{}, ErrInvalidCredentials
		}
		return "", User{}, err
	}

	// No password hash means an SSO-only account; it can never log in this way.
	if user.PasswordHash == "" || !user.IsActive {
		_, _ = s.hasher.Hash(password)

		reason := "deactivated"
		if user.PasswordHash == "" {
			reason = "no_password_set"
		}
		s.recordFailedLogin(ctx, email, &user.ID, reason)
		return "", User{}, ErrInvalidCredentials
	}

	if err := s.hasher.Verify(password, user.PasswordHash); err != nil {
		if errors.Is(err, auth.ErrMismatch) {
			s.recordFailedLogin(ctx, email, &user.ID, "wrong_password")
			return "", User{}, ErrInvalidCredentials
		}
		// A malformed stored hash is our bug, not the caller's. They still get
		// ErrInvalidCredentials, but we want to know about it.
		s.log.Error("stored password hash is unreadable",
			slog.String("user_id", user.ID.String()), slog.String("error", err.Error()))
		s.recordFailedLogin(ctx, email, &user.ID, "corrupt_hash")
		return "", User{}, ErrInvalidCredentials
	}

	// The password is correct and in hand -- the only moment we can transparently
	// upgrade a hash written under weaker parameters. Failure here is not worth
	// failing the login over.
	if s.hasher.NeedsRehash(user.PasswordHash) {
		if newHash, err := s.hasher.Hash(password); err == nil {
			if err := s.repo.UpdateUserPassword(ctx, user.ID, newHash); err != nil {
				s.log.Warn("could not upgrade password hash",
					slog.String("user_id", user.ID.String()), slog.String("error", err.Error()))
			}
		}
	}

	plaintext, digest, err := auth.NewToken(auth.SessionTokenPrefix)
	if err != nil {
		return "", User{}, err
	}

	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		if _, err := repo.CreateSession(ctx, user.ID, digest,
			time.Now().Add(s.cfg.SessionTTL), meta.UserAgent, meta.IPAddress); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &user.ID,
			Action:      audit.ActionUserLoggedIn,
			TargetType:  "user",
			TargetID:    user.ID.String(),
			Metadata:    map[string]any{"ip": meta.IPAddress, "user_agent": meta.UserAgent},
		})
	})
	if err != nil {
		return "", User{}, err
	}

	return plaintext, user, nil
}

// recordFailedLogin writes an audit entry for a rejected login.
//
// The CALLER cannot tell a wrong password from an unknown email from a
// deactivated account -- that is deliberate, and it is what stops login from
// becoming an account-enumeration oracle. But the AUDIT LOG records exactly which
// it was, because you need to tell a customer's typo apart from somebody working
// through a password list.
//
// It is written on the pool, not in a transaction: there is no transaction here to
// join, and a failure to record must not turn a clean 401 into a 500. A failed
// audit write is logged and swallowed -- losing one entry is bad, but refusing to
// answer a login attempt because the audit table hiccuped is worse.
func (s *Service) recordFailedLogin(ctx context.Context, email string, userID *uuid.UUID, reason string) {
	err := audit.NewRecorder(s.pool).Record(ctx, audit.Event{
		ActorUserID: userID, // nil when the email matched nobody
		Action:      audit.ActionLoginFailed,
		TargetType:  "user",
		Metadata:    map[string]any{"email": email, "reason": reason},
	})
	if err != nil {
		s.log.Error("could not audit a failed login", slog.String("error", err.Error()))
	}
}

// Authenticate resolves a bearer token to the user it belongs to. This runs on
// every authenticated request, which is why it is a single indexed query.
func (s *Service) Authenticate(ctx context.Context, token string) (User, Session, error) {
	if token == "" {
		return User{}, Session{}, ErrUnauthenticated
	}
	return s.repo.AuthenticateSession(ctx, auth.HashToken(token))
}

// Logout revokes the session behind the given token. It is idempotent.
func (s *Service) Logout(ctx context.Context, token string, userID uuid.UUID) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		if err := NewRepository(db).RevokeSession(ctx, auth.HashToken(token)); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &userID,
			Action:      audit.ActionUserLoggedOut,
			TargetType:  "user",
			TargetID:    userID.String(),
		})
	})
}

// ListSessions returns the caller's live sessions.
func (s *Service) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	return s.repo.ListUserSessions(ctx, userID)
}

// RevokeSession kills ONE of the caller's sessions -- "sign out that other device".
//
// The user id goes into the WHERE clause, so a caller cannot revoke somebody else's
// session by guessing its id.
func (s *Service) RevokeSession(ctx context.Context, actor User, sessionID uuid.UUID) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		if err := NewRepository(db).RevokeSessionByID(ctx, actor.ID, sessionID); err != nil {
			return err
		}
		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID,
			Action:      audit.ActionSessionRevoked,
			TargetType:  "session",
			TargetID:    sessionID.String(),
		})
	})
}

// ChangePassword rotates a user's password and, in the same transaction, revokes
// every session they have -- including, deliberately, the one making this
// request. A password change that leaves an attacker's stolen session alive has
// achieved nothing.
func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, current, next string) error {
	if err := s.validatePassword(next); err != nil {
		return err
	}

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.PasswordHash == "" {
		return ErrInvalidCredentials
	}
	if err := s.hasher.Verify(current, user.PasswordHash); err != nil {
		return ErrInvalidCredentials
	}

	hash, err := s.hasher.Hash(next)
	if err != nil {
		return err
	}

	return database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		if err := repo.UpdateUserPassword(ctx, userID, hash); err != nil {
			return err
		}
		revoked, err := repo.RevokeUserSessions(ctx, userID)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &userID,
			Action:      audit.ActionPasswordChanged,
			TargetType:  "user",
			TargetID:    userID.String(),
			Metadata:    map[string]any{"sessions_revoked": revoked},
		})
	})
}

// CleanupSessions deletes long-dead session rows. cmd/server runs it on a ticker.
func (s *Service) CleanupSessions(ctx context.Context, retain time.Duration) (int64, error) {
	return s.repo.DeleteDeadSessions(ctx, retain)
}

// ---------------------------------------------------------------- authorization

// Authorize resolves the caller's authority: their roles and the union of those
// roles' permissions. This is what the HTTP middleware puts on the request
// context for every route that needs a permission check.
//
// A superuser holds every permission in the catalog, regardless of which roles
// they are assigned -- see User.IsSuperuser.
func (s *Service) Authorize(ctx context.Context, user User) (Access, error) {
	if user.IsSuperuser {
		return Access{Permissions: AllPermissions(), ViaSuperuser: true}, nil
	}

	roles, err := s.repo.LoadUserRoles(ctx, user.ID)
	if err != nil {
		return Access{}, err
	}
	return Access{Roles: roles, Permissions: unionPermissions(roles)}, nil
}

// ---------------------------------------------------------------- users

// ListUsers returns every user in the installation, newest first, each with the
// roles they hold. Requires users.read.
func (s *Service) ListUsers(ctx context.Context, before uuid.UUID, limit int) ([]UserSummary, error) {
	return s.repo.ListUsers(ctx, before, limit)
}

// SetUserActive activates or deactivates a user, and -- when deactivating --
// revokes every session they hold, in the same transaction.
//
// The revocation is the point. Flipping is_active alone would leave the user
// working normally until their token expired, which for the default 30-day TTL
// means "deactivated" would mean nothing for a month. With it, the lockout takes
// effect on their very next request.
func (s *Service) SetUserActive(ctx context.Context, actor User, targetUserID uuid.UUID, isActive bool) (User, error) {
	// Deactivating yourself would be a way to lock yourself out with nobody else
	// able to undo it, if you were the only administrator around.
	if actor.ID == targetUserID && !isActive {
		return User{}, invalid("you cannot deactivate your own account")
	}

	var user User
	err := database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		if !isActive {
			// Deactivating the last admin would leave the installation
			// unadministrable through the ordinary API -- nobody could grant
			// roles, invite anyone, or manage anyone else. (The superuser CLI
			// escape hatch is unaffected by this guard.)
			targetRoles, err := repo.LoadUserRoles(ctx, targetUserID)
			if err != nil {
				return err
			}
			if hasRole(targetRoles, RoleKeyAdmin) {
				n, err := repo.CountActiveUsersWithRole(ctx, RoleKeyAdmin)
				if err != nil {
					return err
				}
				if n <= 1 {
					return ErrLastAdmin
				}
			}
		}

		var err error
		user, err = repo.SetUserActive(ctx, targetUserID, isActive)
		if err != nil {
			return err
		}

		action := audit.ActionUserReactivated
		metadata := map[string]any{"email": user.Email}

		if !isActive {
			revoked, err := repo.RevokeUserSessions(ctx, targetUserID)
			if err != nil {
				return err
			}
			action = audit.ActionUserDeactivated
			metadata["sessions_revoked"] = revoked
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID,
			Action:      action,
			TargetType:  "user",
			TargetID:    targetUserID.String(),
			Metadata:    metadata,
		})
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// SetSuperuser grants or revokes the global superuser flag. It is reachable only
// from the CLI (`server grant-superuser`), never over HTTP -- so acquiring the
// most powerful privilege in the system therefore takes database access, not a
// stolen token, and a compromised superuser cannot mint more of itself.
//
// The audit entry has a NULL actor: there is no logged-in user behind a shell
// command. Who ran it is a question for your shell history and your ops logs.
func (s *Service) SetSuperuser(ctx context.Context, email string, isSuperuser bool) (User, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return User{}, err
	}

	var user User
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		user, err = repo.SetSuperuser(ctx, email, isSuperuser)
		if err != nil {
			return err
		}

		action := audit.ActionSuperuserRevoked
		if isSuperuser {
			action = audit.ActionSuperuserGranted
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: nil, // the CLI has no logged-in actor
			Action:      action,
			TargetType:  "user",
			TargetID:    user.ID.String(),
			Metadata:    map[string]any{"email": user.Email, "via": "cli"},
		})
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// GrantRoleByKey assigns a role to a user by email, additively. Like
// SetSuperuser, it is reachable only from the CLI (`server grant-role`) -- this
// is the bootstrap path for standing up the first administrator, without
// needing the full superuser escape hatch.
//
// Unlike the HTTP role editor (SetUserRoles), this bypasses the escalation guard
// deliberately: the CLI already requires database access, so there is no
// "actor" whose authority it could be checked against.
func (s *Service) GrantRoleByKey(ctx context.Context, email, roleKey string) (User, Role, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return User{}, Role{}, err
	}

	var user User
	var role Role
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		user, err = repo.GetUserByEmail(ctx, email)
		if err != nil {
			return err
		}
		role, err = repo.GetRoleByKey(ctx, roleKey)
		if err != nil {
			return err
		}
		if err := repo.AddUserRole(ctx, user.ID, role.ID); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: nil, // the CLI has no logged-in actor
			Action:      audit.ActionUserRolesUpdated,
			TargetType:  "user",
			TargetID:    user.ID.String(),
			Metadata:    map[string]any{"email": user.Email, "granted": role.Key, "via": "cli"},
		})
	})
	if err != nil {
		return User{}, Role{}, err
	}
	return user, role, nil
}

// ---------------------------------------------------------------- invitations

// Invite creates an invitation to create an account and returns it along with
// the plaintext token. The token is returned exactly once, here: hand it to your
// mailer, put it in a link, and do not log it.
//
// The template does not send the email -- that is the one piece deliberately
// left to you, since every project's mailer differs. Wire it up where the
// handler returns.
//
// An invitation carries a ROLE, so issuing one is a way of handing out
// permissions -- and therefore takes the same escalation guard as creating a role
// or assigning one. Without it, an admin who cannot promote a member to admin
// could simply invite a fresh account as an admin and log in as it.
//
// THE TOKEN IS EMAILED AND NEVER RETURNED. It used to come back in the HTTP
// response, which was a hole with a plausible excuse: it made the template usable
// with no mailer -- and it meant any admin could mint a working invitation link
// for an address they did not control. carol@example.com's invitation, sitting in
// the admin's own hands, redeemable by whoever registers that address first. The
// only copy now goes to the invitee's inbox.
//
// In development the "inbox" is the application log (MAIL_BACKEND=log), which is
// exactly why startup refuses that backend in production.
func (s *Service) Invite(
	ctx context.Context, actor User, access Access, email string, roleID uuid.UUID,
) (Invitation, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return Invitation{}, err
	}

	role, err := s.repo.GetRole(ctx, roleID)
	if err != nil {
		return Invitation{}, err
	}
	if err := checkEscalation(access, role.Permissions); err != nil {
		return Invitation{}, err
	}

	// An account with this email already exists -- there is nothing to invite them
	// to. Assign the role directly instead.
	if _, err := s.repo.GetUserByEmail(ctx, email); err == nil {
		return Invitation{}, ErrEmailTaken
	} else if !isNotFound(err) {
		return Invitation{}, err
	}

	plaintext, digest, err := auth.NewToken(auth.InvitationTokenPrefix)
	if err != nil {
		return Invitation{}, err
	}

	var inv Invitation
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		// Re-inviting somebody replaces their outstanding invitation rather than
		// colliding with the partial unique index on email. This also invalidates
		// the old link, which is the behaviour you want if the first one went to
		// the wrong address.
		if err := repo.RevokePendingInvitationFor(ctx, email); err != nil {
			return err
		}

		id, err := repo.CreateInvitation(ctx, email, role.ID, actor.ID, digest,
			time.Now().Add(s.cfg.InvitationTTL))
		if err != nil {
			return err
		}

		inv, err = repo.GetInvitation(ctx, id)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID,
			Action:      audit.ActionInvitationCreated,
			TargetType:  "invitation",
			TargetID:    inv.ID.String(),
			Metadata:    map[string]any{"email": email, "role": role.Key},
		})
	})
	if err != nil {
		return Invitation{}, err
	}
	inv.TokenHash = digest

	// Send AFTER the commit. The other order would email a link to an invitation
	// that does not exist yet -- and could email one for an invitation that never
	// comes to exist, if the transaction then rolled back.
	msg := mail.Invitation(s.mailCfg.BaseURL, actor.Email, plaintext)
	msg.To = email

	if err := s.mailer.Send(ctx, msg); err != nil {
		// The invitation is committed but the email did not go. Do NOT fail the
		// request: the admin would retry, and re-inviting revokes and reissues, so
		// they would generate a second dead token. Tell them the truth instead --
		// the invitation exists, and it can be resent.
		s.log.Error("invitation created but the email could not be sent",
			slog.String("email", email), slog.String("error", err.Error()))
		return inv, ErrMailFailed
	}
	return inv, nil
}

// ListInvitations returns the installation's outstanding invitations.
func (s *Service) ListInvitations(ctx context.Context) ([]Invitation, error) {
	return s.repo.ListPendingInvitations(ctx)
}

// RevokeInvitation withdraws a pending invitation, invalidating its link.
func (s *Service) RevokeInvitation(ctx context.Context, actor User, invitationID uuid.UUID) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		if err := repo.RevokeInvitation(ctx, invitationID); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID,
			Action:      audit.ActionInvitationRevoked,
			TargetType:  "invitation",
			TargetID:    invitationID.String(),
		})
	})
}

// AcceptInvitation turns an invitation token into a new account, with the
// invited role already assigned. It is unauthenticated by necessity: the
// invitee has no account yet to log in with.
//
// Redeeming the token IS proof of control of the mailbox it was emailed to, so
// the new account is created already email-verified -- asking for a second
// confirmation would be theatre.
func (s *Service) AcceptInvitation(ctx context.Context, token, password, fullName string) (User, error) {
	if err := s.validatePassword(password); err != nil {
		return User{}, err
	}

	hash, err := s.hasher.Hash(password)
	if err != nil {
		return User{}, err
	}

	digest := auth.HashToken(token)

	var user User
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		inv, err := repo.GetInvitationByTokenHash(ctx, digest)
		if err != nil {
			return err
		}
		if !inv.Pending(time.Now()) {
			return ErrInvitationInvalid
		}

		// Marking the invitation accepted is guarded in SQL, so two concurrent
		// accepts of the same link cannot both create an account: exactly one
		// updates a row, and the loser rolls back with ErrInvitationInvalid.
		if err := repo.AcceptInvitation(ctx, inv.ID); err != nil {
			return err
		}

		user, err = repo.CreateUser(ctx, inv.Email, hash, strings.TrimSpace(fullName))
		if err != nil {
			return err
		}
		if err := repo.AddUserRole(ctx, user.ID, inv.Role.ID); err != nil {
			return err
		}

		// Holding the token IS proof of control of the mailbox -- the link went
		// there and nowhere else -- so mark the address verified in the same
		// transaction rather than asking for a second confirmation.
		user, err = repo.MarkEmailVerified(ctx, user.ID, user.Email)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &user.ID,
			Action:      audit.ActionInvitationAccepted,
			TargetType:  "invitation",
			TargetID:    inv.ID.String(),
			Metadata:    map[string]any{"email": inv.Email, "role": inv.Role.Key},
		})
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// ---------------------------------------------------------------- validation

func normalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", invalid("email is required")
	}
	// net/mail accepts "Name <addr@example.com>"; we want the bare address only.
	addr, err := netmail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return "", invalid("email is not a valid address")
	}
	if len(email) > 254 { // RFC 5321 maximum
		return "", invalid("email is too long")
	}
	return email, nil
}

func (s *Service) validatePassword(password string) error {
	if len(password) < s.cfg.MinPasswordLength {
		return invalid(fmt.Sprintf("password must be at least %d characters", s.cfg.MinPasswordLength))
	}
	// argon2 itself has no length ceiling, but hashing a megabyte of input on
	// every login attempt is a free denial-of-service, so cap it.
	if len(password) > 1024 {
		return invalid("password must be at most 1024 characters")
	}
	return nil
}
