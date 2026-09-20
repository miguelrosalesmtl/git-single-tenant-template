package identity

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/miguelrosalesmtl/go-template/internal/database"
)

// Repository is the only code in the application that writes SQL for identity
// tables.
type Repository struct {
	db database.DB
}

// NewRepository returns a Repository backed by db, which may be a *pgxpool.Pool
// or a pgx.Tx. Passing a transaction is how a caller makes several repository
// calls atomic -- see Service.AcceptInvitation.
func NewRepository(db database.DB) *Repository {
	return &Repository{db: db}
}

// sessionTouchInterval throttles writes to sessions.last_used_at. Updating it on
// literally every authenticated request would make each read of a session a row
// rewrite, and the resulting WAL traffic and index churn buys nothing: the field
// only needs to be accurate enough to show a human "last active a few minutes
// ago" in a session list.
//
// It is a SQL literal rather than a parameter because it is a compile-time
// constant, and because pgx has no default codec mapping a Go time.Duration onto
// a Postgres interval -- where a duration does have to cross that boundary, this
// file passes seconds to make_interval() instead.
const sessionTouchInterval = `interval '5 minutes'`

// ---------------------------------------------------------------- users

const userColumns = `id, email, password_hash, full_name, is_superuser, is_active, email_verified_at, created_at, updated_at`

// qualifiedUserColumns is userColumns with every name prefixed by its table. Use
// it in any query that joins users against something else that also has an "id",
// "created_at", or "updated_at" column. Without the prefix Postgres rejects the
// query as ambiguous.
const qualifiedUserColumns = `users.id, users.email, users.password_hash, users.full_name,
	users.is_superuser, users.is_active, users.email_verified_at, users.created_at, users.updated_at`

// CreateUser inserts a user. passwordHash may be empty for an SSO-only account,
// in which case the column is NULL and password login is impossible for them.
func (r *Repository) CreateUser(ctx context.Context, email, passwordHash, fullName string) (User, error) {
	var hash *string
	if passwordHash != "" {
		hash = &passwordHash
	}

	row := r.db.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, full_name)
		 VALUES ($1, $2, $3)
		 RETURNING `+userColumns,
		email, hash, fullName,
	)

	u, err := scanUser(row)
	if isUniqueViolation(err, "users_email_key") {
		return User{}, ErrEmailTaken
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: create user: %w", err)
	}
	return u, nil
}

// GetUserByEmail looks a user up by email. The column is citext, so the
// comparison is case-insensitive without lower() defeating the index.
func (r *Repository) GetUserByEmail(ctx context.Context, email string) (User, error) {
	row := r.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1`, email)
	return scanUserOrNotFound(row, "get user by email")
}

// GetUserByID looks a user up by primary key.
func (r *Repository) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	row := r.db.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id)
	return scanUserOrNotFound(row, "get user by id")
}

// SetSuperuser sets or clears the global superuser flag. There is deliberately
// no HTTP route that reaches this: it is called only from the CLI
// (`server grant-superuser`), so granting the most powerful privilege in the
// system requires database access, not merely a stolen token.
func (r *Repository) SetSuperuser(ctx context.Context, email string, isSuperuser bool) (User, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE users SET is_superuser = $2, updated_at = now()
		 WHERE email = $1
		 RETURNING `+userColumns,
		email, isSuperuser,
	)
	return scanUserOrNotFound(row, "set superuser")
}

// SetUserActive activates or deactivates a user.
//
// Deactivation alone does not end their existing sessions -- the caller must also
// revoke them, which Service.SetUserActive does in the same transaction.
// Without that, a deactivated user would keep working until their token expired.
func (r *Repository) SetUserActive(ctx context.Context, userID uuid.UUID, isActive bool) (User, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE users SET is_active = $2, updated_at = now()
		 WHERE id = $1
		 RETURNING `+userColumns,
		userID, isActive,
	)
	return scanUserOrNotFound(row, "set user active")
}

// UpdateUserPassword replaces a user's password hash. The caller is responsible
// for also revoking the user's sessions -- see Service.ChangePassword, which
// does both in one transaction.
func (r *Repository) UpdateUserPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`,
		userID, passwordHash,
	)
	if err != nil {
		return fmt.Errorf("identity: update password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListUsers returns every user in the installation, newest first, each with the
// roles they hold and the union of those roles' permissions. This is the user
// directory: GET /users.
//
// One query with a LEFT JOIN through user_roles, folded back in Go, rather than a
// roles query per user -- the classic N+1.
//
// Keyset pagination on the uuidv7 primary key, as with the audit log: no OFFSET,
// and a stable cursor.
func (r *Repository) ListUsers(ctx context.Context, before uuid.UUID, limit int) ([]UserSummary, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var beforeArg any
	if before != uuid.Nil {
		beforeArg = before
	}

	rows, err := r.db.Query(ctx,
		`SELECT `+qualifiedUserColumns+`, `+roleColumns+`, rp.permission
		 FROM users
		 LEFT JOIN user_roles ur       ON ur.user_id = users.id
		 LEFT JOIN roles r             ON r.id = ur.role_id
		 LEFT JOIN role_permissions rp ON rp.role_id = r.id
		 WHERE ($1::uuid IS NULL OR users.id < $1::uuid)
		 ORDER BY users.id DESC, r.is_system DESC, r.key`,
		beforeArg,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list users: %w", err)
	}
	defer rows.Close()

	byUser := map[uuid.UUID]*UserSummary{}
	roleByUser := map[uuid.UUID]map[uuid.UUID]*Role{}
	var order []uuid.UUID

	for rows.Next() {
		var (
			u                  User
			hash               *string
			roleID             *uuid.UUID
			roleKey, roleName  *string
			isSystem           *bool
			rCreated, rUpdated *time.Time
			perm               *Permission
		)
		if err := rows.Scan(
			&u.ID, &u.Email, &hash, &u.FullName, &u.IsSuperuser, &u.IsActive, &u.EmailVerifiedAt,
			&u.CreatedAt, &u.UpdatedAt,
			&roleID, &roleKey, &roleName, &isSystem, &rCreated, &rUpdated, &perm,
		); err != nil {
			return nil, fmt.Errorf("identity: scan user summary: %w", err)
		}
		if hash != nil {
			u.PasswordHash = *hash
		}

		summary, seen := byUser[u.ID]
		if !seen {
			// Stop paginating once we have a full page of distinct users; the
			// ORDER BY guarantees a user's rows are contiguous, so this is safe.
			if len(order) == limit {
				break
			}
			summary = &UserSummary{User: u, Permissions: PermissionSet{}}
			byUser[u.ID] = summary
			roleByUser[u.ID] = map[uuid.UUID]*Role{}
			order = append(order, u.ID)
		}
		if roleID == nil {
			continue // a user holding no roles
		}

		role, seenRole := roleByUser[u.ID][*roleID]
		if !seenRole {
			role = &Role{
				ID: *roleID, Key: *roleKey, Name: *roleName, IsSystem: *isSystem,
				Permissions: PermissionSet{}, CreatedAt: *rCreated, UpdatedAt: *rUpdated,
			}
			roleByUser[u.ID][*roleID] = role
		}
		if perm != nil {
			role.Permissions[*perm] = struct{}{}
			summary.Permissions[*perm] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: iterate users: %w", err)
	}

	out := make([]UserSummary, 0, len(order))
	for _, id := range order {
		s := byUser[id]
		for _, role := range roleByUser[id] {
			s.Roles = append(s.Roles, *role)
		}
		sortRoles(s.Roles)
		out = append(out, *s)
	}
	return out, nil
}

// ---------------------------------------------------------------- sessions

// CreateSession stores a new session. tokenHash is the SHA-256 of the plaintext
// token; the plaintext itself is never given to this layer.
func (r *Repository) CreateSession(
	ctx context.Context,
	userID uuid.UUID,
	tokenHash []byte,
	expiresAt time.Time,
	userAgent, ipAddress string,
) (Session, error) {
	row := r.db.QueryRow(ctx,
		`INSERT INTO sessions (user_id, token_hash, expires_at, user_agent, ip_address)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, user_id, expires_at, revoked_at, user_agent, ip_address, last_used_at, created_at`,
		userID, tokenHash, expiresAt, userAgent, parseIP(ipAddress),
	)

	s, err := scanSession(row)
	if err != nil {
		return Session{}, fmt.Errorf("identity: create session: %w", err)
	}
	s.TokenHash = tokenHash
	return s, nil
}

// AuthenticateSession resolves a session token hash to the user it belongs to,
// in a single round trip, and refreshes last_used_at at most once every
// sessionTouchInterval.
//
// The validity rules live in SQL rather than in Go on purpose: a session is
// usable only if it is unrevoked, unexpired, and belongs to an active user, and
// putting all three in the WHERE clause means no caller can forget one.
//
// It returns ErrUnauthenticated for every failure -- unknown token, revoked,
// expired, deactivated user -- because the caller has no legitimate use for the
// distinction and an attacker does.
func (r *Repository) AuthenticateSession(ctx context.Context, tokenHash []byte) (User, Session, error) {
	// The data-modifying CTE runs to completion whether or not the outer SELECT
	// reads it, so the touch happens even for the (common) case where the
	// throttle window means no row is updated.
	row := r.db.QueryRow(ctx,
		`WITH live AS (
		     SELECT id, user_id, expires_at, revoked_at, user_agent, ip_address, last_used_at, created_at
		     FROM sessions
		     WHERE token_hash = $1
		       AND revoked_at IS NULL
		       AND expires_at > now()
		 ), touched AS (
		     UPDATE sessions SET last_used_at = now()
		     -- Qualify both sides: an unadorned "id" here is ambiguous between
		     -- sessions.id and live.id, and Postgres rejects the statement.
		     WHERE sessions.id IN (SELECT live.id FROM live)
		       AND (sessions.last_used_at IS NULL
		            OR sessions.last_used_at < now() - `+sessionTouchInterval+`)
		 )
		 SELECT `+qualifiedUserColumns+`,
		        live.id, live.user_id, live.expires_at, live.revoked_at,
		        live.user_agent, live.ip_address, live.last_used_at, live.created_at
		 FROM live
		 JOIN users ON users.id = live.user_id
		 WHERE users.is_active`,
		tokenHash,
	)

	var u User
	var hash *string
	var s Session
	var ip *netip.Addr
	err := row.Scan(
		&u.ID, &u.Email, &hash, &u.FullName, &u.IsSuperuser, &u.IsActive, &u.EmailVerifiedAt,
		&u.CreatedAt, &u.UpdatedAt,
		&s.ID, &s.UserID, &s.ExpiresAt, &s.RevokedAt, &s.UserAgent, &ip, &s.LastUsedAt, &s.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, Session{}, ErrUnauthenticated
	}
	if err != nil {
		return User{}, Session{}, fmt.Errorf("identity: authenticate session: %w", err)
	}
	if hash != nil {
		u.PasswordHash = *hash
	}
	if ip != nil {
		s.IPAddress = ip.String()
	}
	s.TokenHash = tokenHash
	return u, s, nil
}

// RevokeSession marks one session dead. It is idempotent: revoking an already
// revoked or unknown token is not an error, because logout must always appear
// to succeed.
func (r *Repository) RevokeSession(ctx context.Context, tokenHash []byte) error {
	_, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now()
		 WHERE token_hash = $1 AND revoked_at IS NULL`,
		tokenHash,
	)
	if err != nil {
		return fmt.Errorf("identity: revoke session: %w", err)
	}
	return nil
}

// RevokeUserSessions kills every live session a user has. This is the payoff of
// database-backed sessions over JWTs: a password change or a deactivation takes
// effect on the very next request, everywhere, instead of after the token's TTL.
func (r *Repository) RevokeUserSessions(ctx context.Context, userID uuid.UUID) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now()
		 WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	)
	if err != nil {
		return 0, fmt.Errorf("identity: revoke user sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ListUserSessions returns a user's live sessions, newest first -- the "you are
// signed in on these devices" screen. id is a uuidv7, so ordering by it is
// ordering by creation time.
func (r *Repository) ListUserSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, user_id, expires_at, revoked_at, user_agent, ip_address, last_used_at, created_at
		 FROM sessions
		 WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
		 ORDER BY id DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list sessions: %w", err)
	}
	defer rows.Close()

	out := []Session{}
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("identity: scan session: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: iterate sessions: %w", err)
	}
	return out, nil
}

// DeleteDeadSessions permanently removes sessions that expired or were revoked
// more than retain ago. Sessions are the one table here that grows without
// bound, so something must prune it -- cmd/server runs this on a ticker.
func (r *Repository) DeleteDeadSessions(ctx context.Context, retain time.Duration) (int64, error) {
	// make_interval(secs => ...) is how a Go duration reaches Postgres as an
	// interval: pgx would not know what to do with a time.Duration directly.
	tag, err := r.db.Exec(ctx,
		`DELETE FROM sessions
		 WHERE expires_at < now() - make_interval(secs => $1)
		    OR (revoked_at IS NOT NULL AND revoked_at < now() - make_interval(secs => $1))`,
		retain.Seconds(),
	)
	if err != nil {
		return 0, fmt.Errorf("identity: delete dead sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RevokeSessionByID revokes ONE session belonging to a user.
//
// user_id is in the WHERE clause, so a caller cannot revoke somebody else's session
// by guessing its id.
func (r *Repository) RevokeSessionByID(ctx context.Context, userID, sessionID uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE sessions SET revoked_at = now()
		 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
		sessionID, userID,
	)
	if err != nil {
		return fmt.Errorf("identity: revoke session by id: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- password resets

// CreatePasswordReset stores a reset token. The plaintext lives in the email and
// nowhere else; this layer only ever sees the digest.
func (r *Repository) CreatePasswordReset(
	ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time, ip, userAgent string,
) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO password_resets (user_id, token_hash, expires_at, ip_address, user_agent)
		 VALUES ($1, $2, $3, $4, $5)`,
		userID, tokenHash, expiresAt, parseIP(ip), userAgent,
	)
	if err != nil {
		return fmt.Errorf("identity: create password reset: %w", err)
	}
	return nil
}

// ConsumePasswordReset spends a reset token and returns whose it was.
//
// The whole check is in the WHERE clause -- unspent, unexpired -- and the UPDATE is
// what claims it. That is not a stylistic choice: a check-then-write in Go would
// let two concurrent requests both read an unused token, both conclude it was
// valid, and both reset the password. Here exactly one UPDATE affects a row, and
// the loser gets ErrInvalidToken.
func (r *Repository) ConsumePasswordReset(ctx context.Context, tokenHash []byte) (uuid.UUID, error) {
	var userID uuid.UUID
	err := r.db.QueryRow(ctx,
		`UPDATE password_resets SET used_at = now()
		 WHERE token_hash = $1
		   AND used_at IS NULL
		   AND expires_at > now()
		 RETURNING user_id`,
		tokenHash,
	).Scan(&userID)

	if errors.Is(err, pgx.ErrNoRows) {
		// Unknown, already spent, or expired. The caller cannot tell which, and has
		// no legitimate need to.
		return uuid.Nil, ErrInvalidToken
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("identity: consume password reset: %w", err)
	}
	return userID, nil
}

// InvalidatePasswordResets spends every outstanding reset token for a user.
//
// Called when a new one is issued (so the old link stops working -- what you want
// if the first went astray), and again when a reset completes (so a second
// outstanding link cannot be used to change the password straight back).
func (r *Repository) InvalidatePasswordResets(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE password_resets SET used_at = now()
		 WHERE user_id = $1 AND used_at IS NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("identity: invalidate password resets: %w", err)
	}
	return nil
}

// DeleteDeadPasswordResets prunes spent and expired rows. Run on the same ticker
// as the session reaper.
func (r *Repository) DeleteDeadPasswordResets(ctx context.Context, retain time.Duration) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM password_resets
		 WHERE expires_at < now() - make_interval(secs => $1)
		    OR (used_at IS NOT NULL AND used_at < now() - make_interval(secs => $1))`,
		retain.Seconds(),
	)
	if err != nil {
		return 0, fmt.Errorf("identity: delete dead password resets: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ---------------------------------------------------------------- invitations

// invitationSelect joins each invitation to the role it offers. An invitation
// points at a role row rather than carrying a role string, so an admin can invite
// somebody straight into a custom role.
const invitationSelect = `
	SELECT i.id, i.email, i.invited_by, i.expires_at,
	       i.accepted_at, i.revoked_at, i.created_at,
	       r.id, r.key, r.name, r.is_system, r.created_at, r.updated_at,
	       rp.permission
	FROM invitations i
	JOIN roles r                  ON r.id = i.role_id
	LEFT JOIN role_permissions rp ON rp.role_id = r.id`

// CreateInvitation stores a pending invitation offering the given role.
func (r *Repository) CreateInvitation(
	ctx context.Context,
	email string,
	roleID uuid.UUID,
	invitedBy uuid.UUID,
	tokenHash []byte,
	expiresAt time.Time,
) (uuid.UUID, error) {
	var id uuid.UUID
	err := r.db.QueryRow(ctx,
		`INSERT INTO invitations (email, role_id, invited_by, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`,
		email, roleID, invitedBy, tokenHash, expiresAt,
	).Scan(&id)

	if isUniqueViolation(err, "invitations_pending_email_idx") {
		// A live invitation for this email already exists. The service revokes the
		// old one first, so reaching here means a genuine race.
		return uuid.Nil, ErrEmailTaken
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("identity: create invitation: %w", err)
	}
	return id, nil
}

// GetInvitation returns one invitation by id, with the role it offers.
func (r *Repository) GetInvitation(ctx context.Context, id uuid.UUID) (Invitation, error) {
	rows, err := r.db.Query(ctx, invitationSelect+` WHERE i.id = $1`, id)
	if err != nil {
		return Invitation{}, fmt.Errorf("identity: get invitation: %w", err)
	}
	defer rows.Close()

	invitations, err := collectInvitations(rows)
	if err != nil {
		return Invitation{}, err
	}
	if len(invitations) == 0 {
		return Invitation{}, ErrNotFound
	}
	return invitations[0], nil
}

// GetInvitationByTokenHash resolves an invitation link. It returns the row even
// if it is expired or spent; the service decides, via Invitation.Pending,
// whether it may still be accepted.
func (r *Repository) GetInvitationByTokenHash(ctx context.Context, tokenHash []byte) (Invitation, error) {
	rows, err := r.db.Query(ctx, invitationSelect+` WHERE i.token_hash = $1`, tokenHash)
	if err != nil {
		return Invitation{}, fmt.Errorf("identity: get invitation by token: %w", err)
	}
	defer rows.Close()

	invitations, err := collectInvitations(rows)
	if err != nil {
		return Invitation{}, err
	}
	if len(invitations) == 0 {
		return Invitation{}, ErrInvitationInvalid
	}
	inv := invitations[0]
	inv.TokenHash = tokenHash
	return inv, nil
}

// collectInvitations folds the invitation x permission fan-out produced by the
// LEFT JOIN back into one Invitation per id, each with its role fully populated.
func collectInvitations(rows pgx.Rows) ([]Invitation, error) {
	byID := map[uuid.UUID]*Invitation{}
	var order []uuid.UUID

	for rows.Next() {
		var (
			inv                Invitation
			role               Role
			rCreated, rUpdated time.Time
			perm               *Permission
		)
		if err := rows.Scan(
			&inv.ID, &inv.Email, &inv.InvitedBy, &inv.ExpiresAt,
			&inv.AcceptedAt, &inv.RevokedAt, &inv.CreatedAt,
			&role.ID, &role.Key, &role.Name, &role.IsSystem, &rCreated, &rUpdated,
			&perm,
		); err != nil {
			return nil, fmt.Errorf("identity: scan invitation: %w", err)
		}

		existing, seen := byID[inv.ID]
		if !seen {
			role.CreatedAt, role.UpdatedAt = rCreated, rUpdated
			role.Permissions = PermissionSet{}
			inv.Role = role

			byID[inv.ID] = &inv
			order = append(order, inv.ID)
			existing = &inv
		}
		if perm != nil {
			existing.Role.Permissions[*perm] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: iterate invitations: %w", err)
	}

	out := make([]Invitation, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}

// ListPendingInvitations returns the installation's outstanding invitations, each
// with the role it offers.
func (r *Repository) ListPendingInvitations(ctx context.Context) ([]Invitation, error) {
	rows, err := r.db.Query(ctx,
		invitationSelect+`
		 WHERE i.accepted_at IS NULL
		   AND i.revoked_at IS NULL
		   AND i.expires_at > now()
		 ORDER BY i.id DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list invitations: %w", err)
	}
	defer rows.Close()

	return collectInvitations(rows)
}

// AcceptInvitation marks an invitation spent, but only if it is still pending.
// The guard is in the WHERE clause, not in Go, so that two concurrent accepts of
// the same link cannot both pass a check-then-write race: exactly one will
// report a row affected.
func (r *Repository) AcceptInvitation(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE invitations SET accepted_at = now()
		 WHERE id = $1
		   AND accepted_at IS NULL
		   AND revoked_at IS NULL
		   AND expires_at > now()`,
		id,
	)
	if err != nil {
		return fmt.Errorf("identity: accept invitation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInvitationInvalid
	}
	return nil
}

// RevokeInvitation withdraws a pending invitation.
func (r *Repository) RevokeInvitation(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE invitations SET revoked_at = now()
		 WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL`,
		id,
	)
	if err != nil {
		return fmt.Errorf("identity: revoke invitation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokePendingInvitationFor withdraws any live invitation for an email. The
// service calls it before issuing a new one, so that re-inviting somebody
// replaces their old link instead of colliding with the partial unique index on
// email.
func (r *Repository) RevokePendingInvitationFor(ctx context.Context, email string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE invitations SET revoked_at = now()
		 WHERE email = $1 AND accepted_at IS NULL AND revoked_at IS NULL`,
		email,
	)
	if err != nil {
		return fmt.Errorf("identity: revoke pending invitation: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- scanning

// row is the common ground between pgx.Row (single) and pgx.Rows (iterated), so
// one scan function serves both a QueryRow and a loop over Query.
type row interface {
	Scan(dest ...any) error
}

func scanUser(r row) (User, error) {
	var u User
	var hash *string // NULL for SSO-only accounts
	err := r.Scan(&u.ID, &u.Email, &hash, &u.FullName, &u.IsSuperuser, &u.IsActive,
		&u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return User{}, err
	}
	if hash != nil {
		u.PasswordHash = *hash
	}
	return u, nil
}

func scanUserOrNotFound(r row, op string) (User, error) {
	u, err := scanUser(r)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: %s: %w", op, err)
	}
	return u, nil
}

func scanSession(r row) (Session, error) {
	var s Session
	var ip *netip.Addr // pgx maps a nullable inet onto this; NULL yields nil
	err := r.Scan(
		&s.ID, &s.UserID, &s.ExpiresAt, &s.RevokedAt,
		&s.UserAgent, &ip, &s.LastUsedAt, &s.CreatedAt,
	)
	if err != nil {
		return Session{}, err
	}
	if ip != nil {
		s.IPAddress = ip.String()
	}
	return s, nil
}

// ---------------------------------------------------------------- helpers

// parseIP converts a client IP string into the *netip.Addr that pgx encodes into
// an inet column, or nil for NULL.
//
// A malformed or absent address becomes NULL rather than an error: we are not
// going to refuse somebody's login because a proxy in front of us sent a header
// we could not parse.
func parseIP(s string) *netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return nil
	}
	return &addr
}

// isUniqueViolation reports whether err is a Postgres unique-constraint failure
// on the named constraint. Matching the constraint name -- rather than just the
// 23505 SQLSTATE -- means adding a second unique index to a table later cannot
// silently turn its violation into the wrong error for the user.
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "23505" && pgErr.ConstraintName == constraint
}

// isForeignKeyViolation reports whether err is a Postgres referential-integrity
// failure on the named constraint.
//
// BOTH SQLSTATEs are checked, and the distinction is easy to get wrong:
//
//	23503 foreign_key_violation -- inserting a row that points at nothing, e.g.
//	      granting a permission that is not in the catalog.
//	23001 restrict_violation    -- deleting a row that something still points at,
//	      when the constraint is ON DELETE RESTRICT (as opposed to NO ACTION,
//	      which reports 23503 instead).
//
// Matching only 23503 silently misses every RESTRICT failure, and the raw
// Postgres error escapes to the caller as a 500.
//
// Two of these are load-bearing rather than incidental:
//
//   - user_roles_role_id_fkey (RESTRICT) fires when deleting a role somebody
//     still holds. Better a loud refusal than silently stripping their access.
//   - role_permissions_permission_fkey fires when granting a permission that is
//     not in the catalog -- i.e. one that no code enforces. It is the database
//     itself enforcing "permissions come from code".
func isForeignKeyViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	isFKError := pgErr.Code == "23503" || pgErr.Code == "23001"
	return isFKError && pgErr.ConstraintName == constraint
}

// ---------------------------------------------------------------- email verification

// CreateEmailVerification stores a verification token.
func (r *Repository) CreateEmailVerification(
	ctx context.Context, userID uuid.UUID, email string, tokenHash []byte, expiresAt time.Time,
) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO email_verifications (user_id, email, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4)`,
		userID, email, tokenHash, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("identity: create email verification: %w", err)
	}
	return nil
}

// ConsumeEmailVerification spends a token and returns whose address it confirms.
//
// Validity is checked and claimed in the one UPDATE, so two concurrent uses of the
// same link cannot both succeed.
func (r *Repository) ConsumeEmailVerification(ctx context.Context, tokenHash []byte) (uuid.UUID, string, error) {
	var userID uuid.UUID
	var email string

	err := r.db.QueryRow(ctx,
		`UPDATE email_verifications SET used_at = now()
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
		 RETURNING user_id, email`,
		tokenHash,
	).Scan(&userID, &email)

	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", ErrInvalidToken
	}
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("identity: consume email verification: %w", err)
	}
	return userID, email, nil
}

// MarkEmailVerified stamps the user's address as confirmed.
//
// The email is in the WHERE clause: a token minted for one address must not verify
// a different one, which is what would happen if the user changed their email
// between requesting the link and clicking it.
func (r *Repository) MarkEmailVerified(ctx context.Context, userID uuid.UUID, email string) (User, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE users SET email_verified_at = now(), updated_at = now()
		 WHERE id = $1 AND email = $2
		 RETURNING `+userColumns,
		userID, email,
	)

	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// The address changed under the token. Refuse rather than verify the wrong one.
		return User{}, ErrInvalidToken
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: mark email verified: %w", err)
	}
	return u, nil
}

// InvalidateEmailVerifications spends every outstanding token for a user, so that
// only the newest link works.
func (r *Repository) InvalidateEmailVerifications(ctx context.Context, userID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`UPDATE email_verifications SET used_at = now()
		 WHERE user_id = $1 AND used_at IS NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("identity: invalidate email verifications: %w", err)
	}
	return nil
}

// DeleteDeadEmailVerifications prunes spent and expired rows.
func (r *Repository) DeleteDeadEmailVerifications(ctx context.Context, retain time.Duration) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM email_verifications
		 WHERE expires_at < now() - make_interval(secs => $1)
		    OR (used_at IS NOT NULL AND used_at < now() - make_interval(secs => $1))`,
		retain.Seconds(),
	)
	if err != nil {
		return 0, fmt.Errorf("identity: delete dead email verifications: %w", err)
	}
	return tag.RowsAffected(), nil
}
