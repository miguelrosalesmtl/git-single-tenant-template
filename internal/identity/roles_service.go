package identity

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/database"
)

// The RBAC rules. Everything in this file exists to stop one thing:
//
//	SOMEONE GRANTING THEMSELVES AUTHORITY THEY DO NOT HAVE.
//
// A role editor is, by construction, a machine for handing out permissions. Give
// a member roles.create without a guard and they will simply build a role
// holding users.update, assign it to themselves, and walk out through every
// limit you placed on them. The guard is checkEscalation, and it is called on
// every path that can move a permission from one person to another.

// roleKeyPattern is what a custom role's key may look like. It ends up in APIs
// and configuration, so it is deliberately boring.
var roleKeyPattern = regexp.MustCompile(`^[a-z0-9]+(?:_[a-z0-9]+)*$`)

// ListRoles returns every role this installation uses.
func (s *Service) ListRoles(ctx context.Context) ([]Role, error) {
	return s.repo.ListRoles(ctx)
}

// GetRole returns one role.
func (s *Service) GetRole(ctx context.Context, roleID uuid.UUID) (Role, error) {
	return s.repo.GetRole(ctx, roleID)
}

// CreateRole builds a new custom role.
//
// The caller needs roles.create AND must already hold every permission they are
// putting into the new role. The second condition is the whole ballgame --
// without it, roles.create would be a synonym for "may become an admin".
func (s *Service) CreateRole(
	ctx context.Context, actor User, access Access, key, name string, perms []Permission,
) (Role, error) {
	key, name, set, err := s.validateRoleInput(key, name, perms)
	if err != nil {
		return Role{}, err
	}
	if err := checkEscalation(access, set); err != nil {
		return Role{}, err
	}

	var role Role
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		// A custom role may not shadow a system role's key: the installation
		// already has "admin" and "member", and two roles answering to the same
		// key would make "which role is this?" ambiguous.
		if _, err := repo.GetRoleByKey(ctx, key); err == nil {
			return ErrRoleKeyTaken
		} else if !isNotFound(err) {
			return err
		}

		role, err = repo.CreateRole(ctx, key, name, set)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID,
			Action:      audit.ActionRoleCreated,
			TargetType:  "role",
			TargetID:    role.ID.String(),
			Metadata: map[string]any{
				"key":         key,
				"name":        name,
				"permissions": set.Slice(),
			},
		})
	})
	if err != nil {
		return Role{}, err
	}
	return role, nil
}

// UpdateRole renames a custom role and replaces its permissions wholesale.
//
// Two refusals matter here. A system role cannot be touched at all -- otherwise
// the installation could strip every permission from "admin" and lock itself
// out forever. And the caller cannot put a permission into the role that they do
// not hold themselves, which is the same escalation guard as CreateRole: editing
// an existing role would otherwise be the trivial way around it.
func (s *Service) UpdateRole(
	ctx context.Context, actor User, access Access, roleID uuid.UUID, name string, perms []Permission,
) (Role, error) {
	_, name, set, err := s.validateRoleInput("placeholder", name, perms)
	if err != nil {
		return Role{}, err
	}
	if err := checkEscalation(access, set); err != nil {
		return Role{}, err
	}

	var role Role
	err = database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		existing, err := repo.GetRole(ctx, roleID)
		if err != nil {
			return err
		}
		if existing.IsSystem {
			return ErrSystemRole
		}

		// The caller must also hold everything the role ALREADY grants. Otherwise
		// a member could take a powerful role they cannot fully wield and quietly
		// rewrite it -- stripping permissions from whoever holds it, or keeping
		// the ones they want. Editing a role is editing everyone who holds it.
		if err := checkEscalation(access, existing.Permissions); err != nil {
			return err
		}

		role, err = repo.UpdateRole(ctx, roleID, name, set)
		if err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID,
			Action:      audit.ActionRoleUpdated,
			TargetType:  "role",
			TargetID:    role.ID.String(),
			Metadata: map[string]any{
				"key":  role.Key,
				"from": existing.Permissions.Slice(),
				"to":   set.Slice(),
			},
		})
	})
	if err != nil {
		return Role{}, err
	}
	return role, nil
}

// DeleteRole removes a custom role.
//
// It fails with ErrRoleInUse while anyone still holds the role. Reassign them
// first: deleting a role should not silently strip somebody's access as an
// invisible side effect of tidying up.
func (s *Service) DeleteRole(ctx context.Context, actor User, access Access, roleID uuid.UUID) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		existing, err := repo.GetRole(ctx, roleID)
		if err != nil {
			return err
		}
		if existing.IsSystem {
			return ErrSystemRole
		}
		// Same reasoning as UpdateRole: you may not destroy authority you do not
		// yourself hold.
		if err := checkEscalation(access, existing.Permissions); err != nil {
			return err
		}

		if err := repo.DeleteRole(ctx, roleID); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID,
			Action:      audit.ActionRoleDeleted,
			TargetType:  "role",
			TargetID:    roleID.String(),
			Metadata:    map[string]any{"key": existing.Key},
		})
	})
}

// SetUserRoles replaces the set of roles a user holds. An empty list is valid: it
// leaves them holding no roles at all, able to manage only their own account.
//
// This is the other door authority can walk through, so it takes the same guard:
// the caller must hold every permission carried by every role they are assigning.
// That one rule also makes "only an admin may create an admin" fall out for free
// -- the admin role carries permissions a member does not have, so a member
// assigning it fails without any special case for admins anywhere.
func (s *Service) SetUserRoles(
	ctx context.Context, actor User, access Access, targetUserID uuid.UUID, roleIDs []uuid.UUID,
) error {
	return database.InTx(ctx, s.pool, func(db database.DB) error {
		repo := NewRepository(db)

		// Resolving the ids strictly is what stops a caller from assigning a role
		// that does not exist and getting a silently shorter list back.
		roles, err := repo.GetRolesByIDs(ctx, roleIDs)
		if err != nil {
			return err
		}

		// THE GUARD: you cannot hand out what you do not hold.
		if err := checkEscalation(access, unionPermissions(roles)); err != nil {
			return err
		}

		before, err := repo.LoadUserRoles(ctx, targetUserID)
		if err != nil {
			return err
		}

		// Demoting an admin is itself an admin-level act. Without this, a member
		// holding users.update could strip an admin down to nothing -- they are
		// not GRANTING anything they lack, so checkEscalation would happily let it
		// pass, but they would have neutered somebody strictly more powerful than
		// themselves.
		//
		// This is checked BEFORE the last-admin invariant below, and the order is
		// deliberate: authorization first, invariants second. Otherwise a member
		// attempting the demotion would be told "that is the last admin" -- a fact
		// about the installation's composition that someone with no business
		// acting here has no business learning.
		if hasRole(before, RoleKeyAdmin) && !access.ViaSuperuser && !actorHoldsRole(access, RoleKeyAdmin) {
			return ErrForbidden
		}

		// Taking the admin role away from somebody who has it: refuse if they are
		// the last admin, or the installation becomes unadministrable by anyone
		// through the ordinary API.
		if hasRole(before, RoleKeyAdmin) && !hasRole(roles, RoleKeyAdmin) {
			admins, err := repo.CountUsersWithRole(ctx, RoleKeyAdmin)
			if err != nil {
				return err
			}
			if admins <= 1 {
				return ErrLastAdmin
			}
		}

		if err := repo.SetUserRoles(ctx, targetUserID, rolesToIDs(roles)); err != nil {
			return err
		}

		return audit.NewRecorder(db).Record(ctx, audit.Event{
			ActorUserID: &actor.ID,
			Action:      audit.ActionUserRolesUpdated,
			TargetType:  "user",
			TargetID:    targetUserID.String(),
			Metadata: map[string]any{
				"from": roleKeys(before),
				"to":   roleKeys(roles),
			},
		})
	})
}

// ---------------------------------------------------------------- the guard

// checkEscalation is the single rule that keeps RBAC from defeating itself:
//
//	YOU MAY ONLY GRANT PERMISSIONS YOU YOURSELF HOLD.
//
// It is called before creating a role, before editing one, and before assigning
// one to a user -- every path by which a permission can travel from the system
// to a person.
//
// The error names the permissions the caller was missing, because "forbidden"
// with no explanation is how an admin ends up filing a bug report about a role
// editor that mysteriously refuses to save.
func checkEscalation(actor Access, granting PermissionSet) error {
	if actor.Permissions.Superset(granting) {
		return nil
	}

	missing := actor.Permissions.Missing(granting)
	names := make([]string, 0, len(missing))
	for _, p := range missing {
		names = append(names, string(p))
	}
	return fmt.Errorf("%w: you do not hold %s", ErrEscalation, strings.Join(names, ", "))
}

// actorHoldsRole reports whether the caller genuinely holds the given system
// role (as opposed to merely holding every permission, which a custom role
// could in principle also do).
func actorHoldsRole(access Access, key string) bool {
	return hasRole(access.Roles, key)
}

// ---------------------------------------------------------------- validation

// validateRoleInput normalises and checks a role's key, name, and permissions.
//
// Every permission must be in the Catalog. The database's foreign key would catch
// an unknown one anyway, but that would be a 500; catching it here is a 400 that
// says which permission does not exist.
func (s *Service) validateRoleInput(key, name string, perms []Permission) (string, string, PermissionSet, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	name = strings.TrimSpace(name)

	switch {
	case key == "":
		return "", "", nil, invalid("role key is required")
	case len(key) > 63:
		return "", "", nil, invalid("role key must be at most 63 characters")
	case !roleKeyPattern.MatchString(key):
		return "", "", nil, invalid("role key may contain only lowercase letters, digits, and single underscores between them")
	case name == "":
		return "", "", nil, invalid("role name is required")
	case len(name) > 100:
		return "", "", nil, invalid("role name must be at most 100 characters")
	case len(perms) == 0:
		return "", "", nil, invalid("a role must grant at least one permission")
	}

	set := PermissionSet{}
	for _, p := range perms {
		if !p.Valid() {
			return "", "", nil, invalid(fmt.Sprintf("%q is not a permission this application enforces", p))
		}
		set[p] = struct{}{}
	}
	return key, name, set, nil
}

// roleKeys is a small helper for audit metadata.
func roleKeys(roles []Role) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, r.Key)
	}
	return out
}
