package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/miguelrosalesmtl/go-template/internal/audit"
	"github.com/miguelrosalesmtl/go-template/internal/identity"
)

// Handlers are deliberately thin: decode, call the service, encode. Every rule
// worth testing lives in internal/identity, so none of it has to be re-tested
// through HTTP, and a future gRPC or CLI front end gets the same behaviour free.

// ---------------------------------------------------------------- auth

type registerRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// handleRegister creates a user account. It does not log them in.
//
// This endpoint necessarily discloses whether an email is registered (it must
// 409 on a duplicate). Rate-limit it in front of the app -- see the README.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	user, err := s.identity.Register(r.Context(), req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	// Token is shown exactly once. The server keeps only its hash and cannot
	// reproduce it; a client that loses it must log in again.
	Token string        `json:"token"`
	User  identity.User `json:"user"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	token, user, err := s.identity.Login(r.Context(), req.Email, req.Password, s.requestMeta(r))
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{Token: token, User: user})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r.Context())

	// Revoke the exact token this request presented, not every session the user
	// has: logging out of a laptop should not sign you out of your phone.
	if err := s.identity.Logout(r.Context(), bearerToken(r), user.ID); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, userFrom(r.Context()))
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// handleChangePassword rotates the password and signs the user out everywhere --
// including this session. The client must log in again with the new password.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	user := userFrom(r.Context())
	if err := s.identity.ChangePassword(r.Context(), user.ID, req.CurrentPassword, req.NewPassword); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	user := userFrom(r.Context())
	current := sessionFrom(r.Context())

	sessions, err := s.identity.ListSessions(r.Context(), user.ID)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}

	// Flag the session making this request, so a UI can label it "this device"
	// and avoid inviting the user to revoke the session they are using.
	type sessionView struct {
		identity.Session
		Current bool `json:"current"`
	}
	views := make([]sessionView, 0, len(sessions))
	for _, sess := range sessions {
		views = append(views, sessionView{Session: sess, Current: sess.ID == current.ID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": views})
}

// handleRevokeSession signs one device out.
//
// The service puts the caller's user id in the WHERE clause, so this cannot revoke
// anybody else's session even with a guessed id.
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	sessionID, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "sessionID must be a UUID")
		return
	}

	if err := s.identity.RevokeSession(r.Context(), userFrom(r.Context()), sessionID); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- users

// usersPageSize is how many users one page of the directory holds.
const usersPageSize = 50

// handleListUsers returns every user in the installation, newest first, each
// with the roles they hold. Requires users.read.
//
// Pagination is keyset: ?before=<user uuid> fetches the next page. Because ids
// are uuidv7 and therefore time-ordered, "id < before" costs the same on page
// 100 as on page 1.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	before, ok := pageBefore(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "before must be a UUID")
		return
	}

	users, err := s.identity.ListUsers(r.Context(), before, usersPageSize)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}

	var next string
	if len(users) == usersPageSize {
		next = users[len(users)-1].User.ID.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users, "next_before": next})
}

// pageBefore reads the keyset-pagination cursor from ?before=<uuid>. The zero
// UUID means "start at the newest".
func pageBefore(r *http.Request) (uuid.UUID, bool) {
	raw := r.URL.Query().Get("before")
	if raw == "" {
		return uuid.Nil, true
	}
	parsed, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, false
	}
	return parsed, true
}

type setUserActiveRequest struct {
	IsActive bool `json:"is_active"`
}

// handleSetUserActive activates or deactivates a user account. Requires
// users.update.
//
// Deactivating also revokes every session the user holds, in the same
// transaction, so the lockout takes effect on their next request rather than
// whenever their 30-day token happens to expire.
func (s *Server) handleSetUserActive(w http.ResponseWriter, r *http.Request) {
	targetID, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "userID must be a UUID")
		return
	}

	var req setUserActiveRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	user, err := s.identity.SetUserActive(r.Context(), userFrom(r.Context()), targetID, req.IsActive)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// Changing a user's roles lives in handlers_roles.go -- it is a role operation,
// and the escalation guard in the service is what makes it safe.

// ---------------------------------------------------------------- invitations

type createInvitationRequest struct {
	Email string `json:"email"`
	// RoleID is the role the invitee will hold once they accept. The caller must
	// hold every permission it carries; enforced in the service.
	RoleID uuid.UUID `json:"role_id"`
}

// handleCreateInvitation issues an invitation and EMAILS it.
//
// The response deliberately does NOT contain the token. It used to, which was a
// hole: an admin could mint a working invitation link for carol@example.com, keep
// it, and redeem it themselves by creating that address's account. The only copy
// now goes to the invitee's inbox.
//
// In development (MAIL_BACKEND=log) that "inbox" is the application log, so the
// link is in `docker compose logs app`. Startup refuses that backend in production.
func (s *Server) handleCreateInvitation(w http.ResponseWriter, r *http.Request) {
	var req createInvitationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.RoleID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "role_id is required -- GET /roles to list the roles you can offer")
		return
	}

	ctx := r.Context()
	inv, err := s.identity.Invite(ctx, userFrom(ctx), accessFrom(ctx), req.Email, req.RoleID)
	if err != nil {
		// ErrMailFailed is special: the invitation EXISTS, the email did not send.
		// The error handler turns it into a 502 saying exactly that, so the admin
		// resends instead of re-inviting and piling up dead tokens.
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, inv)
}

func (s *Server) handleListInvitations(w http.ResponseWriter, r *http.Request) {
	invitations, err := s.identity.ListInvitations(r.Context())
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invitations": invitations})
}

func (s *Server) handleRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	invitationID, err := uuid.Parse(chi.URLParam(r, "invitationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invitationID must be a UUID")
		return
	}

	ctx := r.Context()
	if err := s.identity.RevokeInvitation(ctx, userFrom(ctx), invitationID); err != nil {
		s.errors.handle(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type acceptInvitationRequest struct {
	Token     string `json:"token"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// handleAcceptInvitation creates the invitee's account, with the invited role
// already assigned.
//
// It is public: the invitee has no session yet to authenticate with -- that is
// the whole reason they were invited. It does not sit under requireAuth for
// that reason, and the rate limiter guards it instead.
func (s *Server) handleAcceptInvitation(w http.ResponseWriter, r *http.Request) {
	var req acceptInvitationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	user, err := s.identity.AcceptInvitation(r.Context(), req.Token, req.Password, req.FirstName, req.LastName)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

// ---------------------------------------------------------------- audit

// auditPageSize is how many entries one page of the audit log holds.
const auditPageSize = 50

// handleListAuditLog returns the installation's activity, newest first, with
// filters.
//
//	?action=roles.created     one exact action
//	?actor=<user uuid>        everything one person did
//	?from=2026-01-01T00:00:00Z&to=...   a time window (RFC 3339)
//	?before=<entry uuid>      the next page
//
// The filters are not decoration. Pagination alone is useless once the log has
// 100k rows in it: "did anybody touch roles last March" is not a question you can
// answer by scrolling, and an audit log you cannot query is an audit log nobody
// reads.
//
// Pagination is keyset. Because ids are uuidv7 and therefore time-ordered,
// "id < before" means "older than" -- so a page is an index walk with no sort,
// page 100 costs what page 1 costs, and a row arriving mid-scroll cannot shift the
// pages under the reader. OFFSET fails all three.
func (s *Server) handleListAuditLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := audit.Filter{Limit: auditPageSize, Action: audit.Action(q.Get("action"))}

	if raw := q.Get("before"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "before must be a UUID")
			return
		}
		filter.Before = parsed
	}

	if raw := q.Get("actor"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "actor must be a user UUID")
			return
		}
		filter.ActorUserID = &parsed
	}

	for _, f := range []struct {
		name string
		dest *time.Time
	}{
		{"from", &filter.From},
		{"to", &filter.To},
	} {
		if raw := q.Get(f.name); raw != "" {
			parsed, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				writeError(w, http.StatusBadRequest, f.name+" must be an RFC 3339 timestamp")
				return
			}
			*f.dest = parsed
		}
	}

	entries, err := audit.NewRecorder(s.pool).List(r.Context(), filter)
	if err != nil {
		s.errors.handle(w, r, err)
		return
	}

	// The cursor for the next page is the last id on this one; absent when the
	// page was not full, which means there is nothing more to fetch.
	var next string
	if len(entries) == auditPageSize {
		next = entries[len(entries)-1].ID.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "next_before": next})
}
