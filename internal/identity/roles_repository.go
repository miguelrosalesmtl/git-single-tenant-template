package identity

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Everything that reads or writes roles, their permissions, and their assignment
// to users.

// roleColumns is qualified with the alias "r" because every one of these queries
// joins roles against role_permissions, and both tables have an id.
const roleColumns = `r.id, r.key, r.name, r.is_system, r.created_at, r.updated_at`

// ListRoles returns every role in the installation, each with its permissions.
func (r *Repository) ListRoles(ctx context.Context) ([]Role, error) {
	// LEFT JOIN, not JOIN: a role with no permissions yet is still a role, and an
	// inner join would make it vanish from the list.
	rows, err := r.db.Query(ctx,
		`SELECT `+roleColumns+`, rp.permission
		 FROM roles r
		 LEFT JOIN role_permissions rp ON rp.role_id = r.id
		 ORDER BY r.is_system DESC, r.key`,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: list roles: %w", err)
	}
	defer rows.Close()

	return collectRoles(rows)
}

// GetRole returns one role by id.
func (r *Repository) GetRole(ctx context.Context, roleID uuid.UUID) (Role, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+roleColumns+`, rp.permission
		 FROM roles r
		 LEFT JOIN role_permissions rp ON rp.role_id = r.id
		 WHERE r.id = $1`,
		roleID,
	)
	if err != nil {
		return Role{}, fmt.Errorf("identity: get role: %w", err)
	}
	defer rows.Close()

	roles, err := collectRoles(rows)
	if err != nil {
		return Role{}, err
	}
	if len(roles) == 0 {
		return Role{}, ErrNotFound
	}
	return roles[0], nil
}

// GetRoleByKey resolves a role by its key. Used to find "admin" and other system
// roles.
func (r *Repository) GetRoleByKey(ctx context.Context, key string) (Role, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+roleColumns+`, rp.permission
		 FROM roles r
		 LEFT JOIN role_permissions rp ON rp.role_id = r.id
		 WHERE r.key = $1`,
		key,
	)
	if err != nil {
		return Role{}, fmt.Errorf("identity: get role by key: %w", err)
	}
	defer rows.Close()

	roles, err := collectRoles(rows)
	if err != nil {
		return Role{}, err
	}
	if len(roles) == 0 {
		return Role{}, ErrNotFound
	}
	return roles[0], nil
}

// GetRolesByIDs resolves a set of role ids.
//
// If any requested id is missing, this returns ErrNotFound rather than silently
// assigning the subset it could find. That strictness is the point: a caller
// passing an id that does not exist must fail, not quietly get a shorter list.
func (r *Repository) GetRolesByIDs(ctx context.Context, ids []uuid.UUID) ([]Role, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	rows, err := r.db.Query(ctx,
		`SELECT `+roleColumns+`, rp.permission
		 FROM roles r
		 LEFT JOIN role_permissions rp ON rp.role_id = r.id
		 WHERE r.id = ANY($1)
		 ORDER BY r.is_system DESC, r.key`,
		ids,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: get roles by ids: %w", err)
	}
	defer rows.Close()

	roles, err := collectRoles(rows)
	if err != nil {
		return nil, err
	}

	// Deduplicate the request before comparing counts, so passing the same id
	// twice is not mistaken for a missing role.
	wanted := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		wanted[id] = struct{}{}
	}
	if len(roles) != len(wanted) {
		return nil, ErrNotFound
	}
	return roles, nil
}

// CreateRole inserts a custom role and its permissions. It must run inside a
// transaction: a role that committed without its permissions would be a role
// that grants nothing.
func (r *Repository) CreateRole(ctx context.Context, key, name string, perms PermissionSet) (Role, error) {
	var role Role
	err := r.db.QueryRow(ctx,
		`INSERT INTO roles (key, name, is_system)
		 VALUES ($1, $2, false)
		 RETURNING id, key, name, is_system, created_at, updated_at`,
		key, name,
	).Scan(&role.ID, &role.Key, &role.Name, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt)

	if isUniqueViolation(err, "roles_key_key") {
		return Role{}, ErrRoleKeyTaken
	}
	if err != nil {
		return Role{}, fmt.Errorf("identity: create role: %w", err)
	}

	if err := r.replaceRolePermissions(ctx, role.ID, perms); err != nil {
		return Role{}, err
	}
	role.Permissions = perms
	return role, nil
}

// UpdateRole renames a custom role and replaces its permission set wholesale.
//
// is_system is excluded from the WHERE clause, so this can never touch a system
// role.
func (r *Repository) UpdateRole(ctx context.Context, roleID uuid.UUID, name string, perms PermissionSet) (Role, error) {
	var role Role
	err := r.db.QueryRow(ctx,
		`UPDATE roles SET name = $2, updated_at = now()
		 WHERE id = $1 AND NOT is_system
		 RETURNING id, key, name, is_system, created_at, updated_at`,
		roleID, name,
	).Scan(&role.ID, &role.Key, &role.Name, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		// Either it does not exist, or it is a system role. The service
		// distinguishes the latter for a better message; from here both are
		// "you cannot update that".
		return Role{}, ErrNotFound
	}
	if err != nil {
		return Role{}, fmt.Errorf("identity: update role: %w", err)
	}

	if err := r.replaceRolePermissions(ctx, roleID, perms); err != nil {
		return Role{}, err
	}
	role.Permissions = perms
	return role, nil
}

// DeleteRole removes a custom role.
//
// user_roles.role_id is ON DELETE RESTRICT, so if anybody still holds the role,
// Postgres refuses and this returns ErrRoleInUse. Deleting a role should not
// silently strip people's access as a side effect.
func (r *Repository) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM roles WHERE id = $1 AND NOT is_system`,
		roleID,
	)
	if isForeignKeyViolation(err, "user_roles_role_id_fkey") {
		return ErrRoleInUse
	}
	if err != nil {
		return fmt.Errorf("identity: delete role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// replaceRolePermissions swaps a role's permission set for a new one. Delete then
// insert, inside the caller's transaction, so no moment exists in which the role
// holds a mixture of the old and new sets.
func (r *Repository) replaceRolePermissions(ctx context.Context, roleID uuid.UUID, perms PermissionSet) error {
	if _, err := r.db.Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, roleID); err != nil {
		return fmt.Errorf("identity: clear role permissions: %w", err)
	}

	for _, p := range perms.Slice() {
		_, err := r.db.Exec(ctx,
			`INSERT INTO role_permissions (role_id, permission) VALUES ($1, $2)`,
			roleID, p,
		)
		if isForeignKeyViolation(err, "role_permissions_permission_fkey") {
			// The permission is not in the catalog: no code enforces it. The
			// service validates against Catalog first, so reaching here means the
			// database and the binary disagree.
			return fmt.Errorf("%w: %q is not a permission this application enforces", ErrValidation, p)
		}
		if err != nil {
			return fmt.Errorf("identity: grant permission %q: %w", p, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------- assignment

// LoadUserRoles returns the roles a user holds, with their permissions. A user
// holding none returns an empty slice, never an error -- that is a valid state,
// not a missing one.
func (r *Repository) LoadUserRoles(ctx context.Context, userID uuid.UUID) ([]Role, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+roleColumns+`, rp.permission
		 FROM user_roles ur
		 JOIN roles r                  ON r.id = ur.role_id
		 LEFT JOIN role_permissions rp ON rp.role_id = r.id
		 WHERE ur.user_id = $1
		 ORDER BY r.is_system DESC, r.key`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("identity: load user roles: %w", err)
	}
	defer rows.Close()

	return collectRoles(rows)
}

// SetUserRoles replaces the complete set of roles a user holds. Must run in a
// transaction.
func (r *Repository) SetUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	if _, err := r.db.Exec(ctx,
		`DELETE FROM user_roles WHERE user_id = $1`, userID,
	); err != nil {
		return fmt.Errorf("identity: clear user roles: %w", err)
	}

	for _, id := range roleIDs {
		if _, err := r.db.Exec(ctx,
			`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`,
			userID, id,
		); err != nil {
			return fmt.Errorf("identity: assign role %s: %w", id, err)
		}
	}
	return nil
}

// AddUserRole grants a user a role in addition to whatever they already hold.
// Idempotent -- assigning a role the user already has is a no-op, not an error.
//
// Unlike SetUserRoles (a full replace, used by the HTTP role editor), this is
// additive, which is what makes it right for the CLI bootstrap command
// (`server grant-role`): it can hand out "admin" without first having to look up
// and resend every role the user already holds.
func (r *Repository) AddUserRole(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)
		 ON CONFLICT (user_id, role_id) DO NOTHING`,
		userID, roleID,
	)
	if err != nil {
		return fmt.Errorf("identity: add user role: %w", err)
	}
	return nil
}

// CountUsersWithRole returns how many users hold the given system role's key.
//
// Used to guard against removing or deactivating the last admin, which would
// leave the installation unadministrable through the ordinary API. Call it
// inside the same transaction as the write it guards, or two concurrent requests
// each removing one of the last two admins could both see a count of 2 and both
// succeed.
func (r *Repository) CountUsersWithRole(ctx context.Context, roleKey string) (int, error) {
	var n int
	err := r.db.QueryRow(ctx,
		`SELECT count(DISTINCT ur.user_id)
		 FROM user_roles ur
		 JOIN roles r ON r.id = ur.role_id
		 WHERE r.is_system AND r.key = $1`,
		roleKey,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("identity: count users with role: %w", err)
	}
	return n, nil
}

// CountActiveUsersWithRole is CountUsersWithRole restricted to accounts that are
// still active -- what guards a deactivation from taking out the last working
// admin.
func (r *Repository) CountActiveUsersWithRole(ctx context.Context, roleKey string) (int, error) {
	var n int
	err := r.db.QueryRow(ctx,
		`SELECT count(DISTINCT ur.user_id)
		 FROM user_roles ur
		 JOIN roles r ON r.id = ur.role_id
		 JOIN users u ON u.id = ur.user_id AND u.is_active
		 WHERE r.is_system AND r.key = $1`,
		roleKey,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("identity: count active users with role: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------- scanning

// collectRoles folds the role x permission rows produced by the LEFT JOIN back
// into one Role per id, with its permissions gathered into a set.
//
// The join necessarily repeats a role's columns once per permission it holds;
// this is where that fan-out is undone.
func collectRoles(rows pgx.Rows) ([]Role, error) {
	byID := map[uuid.UUID]*Role{}
	var order []uuid.UUID

	for rows.Next() {
		var (
			role Role
			perm *Permission
		)
		if err := rows.Scan(&role.ID, &role.Key, &role.Name, &role.IsSystem,
			&role.CreatedAt, &role.UpdatedAt, &perm); err != nil {
			return nil, fmt.Errorf("identity: scan role: %w", err)
		}

		existing, seen := byID[role.ID]
		if !seen {
			role.Permissions = PermissionSet{}
			byID[role.ID] = &role
			order = append(order, role.ID)
			existing = &role
		}
		if perm != nil {
			existing.Permissions[*perm] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: iterate roles: %w", err)
	}

	out := make([]Role, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}

// sortRoles orders roles for display: system roles first (admin, member as the
// reader expects), then custom ones alphabetically. Map iteration in Go is
// randomised, so without this the same user's roles would come back in a
// different order on every request.
func sortRoles(roles []Role) {
	sort.Slice(roles, func(i, j int) bool {
		if roles[i].IsSystem != roles[j].IsSystem {
			return roles[i].IsSystem // system roles first
		}
		return roles[i].Key < roles[j].Key
	})
}

// ---------------------------------------------------------------- helpers

// rolesToIDs is a small convenience used by the service when it has roles and
// needs to store the assignment.
func rolesToIDs(roles []Role) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(roles))
	for _, r := range roles {
		out = append(out, r.ID)
	}
	return out
}
