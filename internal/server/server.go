// Package server wires the HTTP API: routing, middleware, and lifecycle.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/miguelrosalesmtl/go-template/internal/identity"
	"github.com/miguelrosalesmtl/go-template/internal/settings"
)

// Server holds the HTTP server and its dependencies.
type Server struct {
	http     *http.Server
	identity *identity.Service
	pool     *pgxpool.Pool
	log      *slog.Logger
	errors   errorHandler
	config   settings.Server
	corsCfg  settings.CORS
	limiter  *limiter // nil when disabled
	done     chan struct{}
}

// New builds a Server with every route registered.
func New(
	cfg settings.Server,
	rateCfg settings.RateLimit,
	corsCfg settings.CORS,
	debug bool,
	identityService *identity.Service,
	pool *pgxpool.Pool,
	log *slog.Logger,
) *Server {
	s := &Server{
		identity: identityService,
		pool:     pool,
		log:      log,
		errors:   errorHandler{log: log, debug: debug, pool: pool},
		config:   cfg,
		corsCfg:  corsCfg,
		done:     make(chan struct{}),
	}

	if len(corsCfg.AllowedOrigins) > 0 {
		log.Info("CORS enabled", slog.Any("origins", corsCfg.AllowedOrigins))
	}

	if rateCfg.Enabled {
		s.limiter = newLimiter(rateCfg)
		// Prune expired buckets. Without this the map is an unbounded,
		// attacker-controlled allocation: every new IP adds an entry forever.
		go s.limiter.runReaper(s.done)
		log.Info("rate limiting enabled (in-memory, PER-REPLICA -- put the real limiter at your proxy)",
			slog.Int("attempts", rateCfg.Attempts),
			slog.Duration("window", rateCfg.Window),
		)
	} else {
		log.Warn("RATE LIMITING IS DISABLED: /auth/login and /auth/register are open to brute force")
	}

	s.http = &http.Server{
		Addr:         cfg.Addr(),
		Handler:      s.routes(),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}
	return s
}

// routes is the whole API surface on one screen. Read it top to bottom and you
// can see exactly which middleware guards which endpoint -- which is the point
// of keeping it in one function.
func (s *Server) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)
	r.Use(s.cors)
	r.Use(requestLogger(s.log))

	// Put the request id, IP, and user agent on the context, so that EVERY audit
	// entry written during this request carries them without a single service
	// method having to know they exist. See audit.WithRequestMeta.
	r.Use(s.withAuditMeta)

	// Note: chi's middleware.RealIP is deliberately NOT used. It rewrites
	// RemoteAddr from X-Forwarded-For unconditionally, with no way to say whether
	// a trustworthy proxy set that header -- so with a directly-reachable server
	// any caller could forge the IP recorded against their own session and audit
	// entries. clientIP() in middleware.go does the same job, gated on
	// SERVER_TRUST_PROXY_HEADERS.

	// Probes. Unauthenticated by necessity: the load balancer has no credentials.
	r.Get("/healthz", s.handleHealth)
	r.Get("/readyz", s.handleReady)

	r.Route("/api/v1", func(r chi.Router) {
		// --- Public: no session required. -------------------------------------
		//
		// Every one of these is rate limited, and they are the only ones that need
		// to be: an attacker who already holds a session token has better things to
		// do than brute-force it. Login and reset are limited by IP AND by email --
		// IP alone lets one attacker spray a thousand accounts from one address at
		// one attempt each; email alone lets a botnet hammer one account from a
		// thousand addresses.
		r.With(s.rateLimit(s.byIPAndEmail("register"))).
			Post("/auth/register", s.handleRegister)
		r.With(s.rateLimit(s.byIPAndEmail("login"))).
			Post("/auth/login", s.handleLogin)

		// Password reset. Request always answers 204 -- even for an address with no
		// account -- because anything else is a free account-enumeration oracle on
		// an unauthenticated endpoint.
		r.With(s.rateLimit(s.byIPAndEmail("reset"))).
			Post("/auth/password/reset", s.handleRequestPasswordReset)
		r.With(s.rateLimit(s.byIP("reset-confirm"))).
			Post("/auth/password/reset/confirm", s.handleResetPassword)

		// Email verification. Public, because the user clicks the link from their
		// inbox and may not have a session in that browser.
		r.With(s.rateLimit(s.byIP("verify"))).
			Post("/auth/email/verify", s.handleVerifyEmail)

		// Accepting an invitation CREATES the account, so it must stay public: the
		// invitee has no session to authenticate with yet. Rate limited even so --
		// the token is a bearer credential in a URL, and this is where somebody
		// would guess at one.
		r.With(s.rateLimit(s.byIP("invitation-accept"))).
			Post("/invitations/accept", s.handleAcceptInvitation)

		// The permission catalog: every permission this build enforces, with its
		// description. A role editor renders its checkbox list from this, which is
		// what stops a UI from ever offering a permission that no code checks.
		//
		// It is public because it is not secret -- it is the same list that is in
		// the open-source code -- and a login screen may want it.
		r.Get("/permissions", s.handleListPermissions)

		// --- Authenticated: account self-management, human session only. ------
		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			// A personal API key must not be able to change its owner's password
			// or reach account-management endpoints.
			r.Use(s.sessionOnly)

			r.Post("/auth/logout", s.handleLogout)
			r.Get("/auth/me", s.handleMe)
			r.Post("/auth/password", s.handleChangePassword)

			// Listing your sessions and being unable to do anything about them was an
			// odd half-feature: it showed you the compromise and offered no way to
			// end it.
			r.Get("/auth/sessions", s.handleListSessions)
			r.Delete("/auth/sessions/{sessionID}", s.handleRevokeSession)

			r.With(s.rateLimit(s.byIP("verify-resend"))).
				Post("/auth/email/verify/resend", s.handleResendVerification)
		})

		// --- Permission-gated: session or API key. -----------------------------
		// Each route names the ONE permission it needs. Read the block top to
		// bottom and you have the application's entire authorization policy --
		// which is the point of putting it here rather than scattering checks
		// through the handlers.
		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Use(s.requireAccess)

			r.With(s.requirePermission(identity.PermUsersRead)).
				Get("/users", s.handleListUsers)
			r.With(s.requirePermission(identity.PermUsersUpdate)).
				Put("/users/{userID}/roles", s.handleSetUserRoles)
			r.With(s.requirePermission(identity.PermUsersUpdate)).
				Patch("/users/{userID}", s.handleSetUserActive)

			// Invitations. Issuing one hands out a role, so the service ALSO
			// applies the escalation guard -- invitations.create lets you invite,
			// it does not let you invite somebody into a role more powerful than
			// your own.
			r.With(s.requirePermission(identity.PermInvitationsRead)).
				Get("/invitations", s.handleListInvitations)
			r.With(s.requirePermission(identity.PermInvitationsCreate)).
				Post("/invitations", s.handleCreateInvitation)
			r.With(s.requirePermission(identity.PermInvitationsDelete)).
				Delete("/invitations/{invitationID}", s.handleRevokeInvitation)

			// Roles: the configurable part of RBAC. Split into create/update/delete,
			// so you can grant "may edit roles but not delete them".
			r.With(s.requirePermission(identity.PermRolesRead)).
				Get("/roles", s.handleListRoles)
			r.With(s.requirePermission(identity.PermRolesCreate)).
				Post("/roles", s.handleCreateRole)
			r.With(s.requirePermission(identity.PermRolesUpdate)).
				Put("/roles/{roleID}", s.handleUpdateRole)
			r.With(s.requirePermission(identity.PermRolesDelete)).
				Delete("/roles/{roleID}", s.handleDeleteRole)

			r.With(s.requirePermission(identity.PermAuditRead)).
				Get("/audit", s.handleListAuditLog)

			// API keys. Minting one is additionally subject to the escalation
			// guard in the service -- apikeys.create lets you make a key, it does
			// not let you make one more powerful than you are.
			r.With(s.requirePermission(identity.PermAPIKeysRead)).
				Get("/api-keys", s.handleListAPIKeys)
			r.With(s.requirePermission(identity.PermAPIKeysCreate)).
				Post("/api-keys", s.handleCreateAPIKey)
			r.With(s.requirePermission(identity.PermAPIKeysDelete)).
				Delete("/api-keys/{keyID}", s.handleRevokeAPIKey)
		})
	})

	return r
}

// Start begins serving HTTP. It blocks until the server stops.
func (s *Server) Start() error {
	s.log.Info("http server listening", slog.String("addr", s.config.Addr()))
	if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown drains in-flight requests, up to the caller's deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	s.log.Info("http server shutting down")
	close(s.done) // stop the limiter's reaper
	return s.http.Shutdown(ctx)
}

// handleHealth is the liveness probe: the process is running. It must not touch
// the database -- if it did, a brief database blip would make Kubernetes kill
// every replica, turning a recoverable outage into a total one.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady is the readiness probe: dependencies are reachable, so this
// replica can serve traffic. Unlike liveness, this one does check the database:
// a replica that cannot reach Postgres should be taken out of the load balancer,
// not restarted.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.pool.Ping(ctx); err != nil {
		s.log.Warn("readiness check failed", slog.String("error", err.Error()))
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
