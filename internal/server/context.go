package server

import (
	"context"

	"github.com/miguelrosalesmtl/go-template/internal/identity"
)

// contextKey is unexported so no other package can write these keys. That is the
// whole security property of this file: the only way a request context can come
// to hold a user or an access decision is by passing through the middleware
// below, which means a handler that reads one is guaranteed it was authenticated
// and authorized rather than supplied by the caller.
type contextKey int

const (
	userKey contextKey = iota
	sessionKey
	accessKey
	apiKeyKey
)

// withAPIKey records that this request authenticated with an API key. Called only
// by requireAuth. Its presence is what marks a request as key-authenticated
// rather than session-authenticated.
func withAPIKey(ctx context.Context, key identity.APIKey) context.Context {
	return context.WithValue(ctx, apiKeyKey, key)
}

// apiKeyFrom returns the API key a request authenticated with, if any.
func apiKeyFrom(ctx context.Context) (identity.APIKey, bool) {
	key, ok := ctx.Value(apiKeyKey).(identity.APIKey)
	return key, ok
}

// withUser attaches the authenticated user. Called only by requireAuth.
func withUser(ctx context.Context, u identity.User, s identity.Session) context.Context {
	ctx = context.WithValue(ctx, userKey, u)
	return context.WithValue(ctx, sessionKey, s)
}

// withAccess attaches the caller's resolved authority. Called only by
// requireAccess.
func withAccess(ctx context.Context, access identity.Access) context.Context {
	return context.WithValue(ctx, accessKey, access)
}

// accessFrom returns the caller's full authority, including whether it came
// from assigned roles, the superuser bypass, or an API key.
//
// It panics if there is none, and that is deliberate: it can only happen if a
// route was registered outside the requireAccess middleware, which is a
// programming error that must surface loudly in development. chi's Recoverer
// turns the panic into a 500.
func accessFrom(ctx context.Context) identity.Access {
	a, ok := ctx.Value(accessKey).(identity.Access)
	if !ok {
		panic("server: no access in context -- this route is missing the requireAccess middleware")
	}
	return a
}

// userFrom returns the authenticated user.
//
// It panics if there is none, and that is deliberate: it can only happen if a
// route was registered outside the requireAuth middleware, which is a programming
// error that must surface loudly in development rather than turn into a nil-user
// request that quietly reads somebody else's data in production. chi's Recoverer
// turns the panic into a 500.
func userFrom(ctx context.Context) identity.User {
	u, ok := ctx.Value(userKey).(identity.User)
	if !ok {
		panic("server: no user in context -- this route is missing the requireAuth middleware")
	}
	return u
}

// sessionFrom returns the session the request authenticated with.
func sessionFrom(ctx context.Context) identity.Session {
	s, ok := ctx.Value(sessionKey).(identity.Session)
	if !ok {
		panic("server: no session in context -- this route is missing the requireAuth middleware")
	}
	return s
}

// The tryX accessors are the non-panicking variants, for code that runs on paths
// where the middleware may not have got as far as populating the context -- above
// all the error handler, which has to record a denial for a request that failed
// BEFORE authentication or authorization. It cannot assume either, and it must
// never panic while trying to log a refusal.

// tryUserFrom returns the authenticated user, if there is one.
func tryUserFrom(ctx context.Context) (identity.User, bool) {
	u, ok := ctx.Value(userKey).(identity.User)
	return u, ok
}
