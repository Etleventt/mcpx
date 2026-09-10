package auth

import "context"

type ctxKey int

const (
	authorizationKey ctxKey = 1
	principalKey     ctxKey = 2
)

// ContextWithAuthorization stores the raw Authorization header value.
func ContextWithAuthorization(ctx context.Context, header string) context.Context {
	if header == "" {
		return ctx
	}
	return context.WithValue(ctx, authorizationKey, header)
}

// AuthorizationFromContext returns the Authorization header if present.
func AuthorizationFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(authorizationKey).(string)
	return v
}

// ContextWithPrincipal stores an already validated principal. This is used for
// transport credentials such as SubDesk's hashed MCP API token that are not
// represented by the Runtime's legacy static bearer configuration.
func ContextWithPrincipal(ctx context.Context, principal Principal) context.Context {
	if principal.ID == "" {
		return ctx
	}
	return context.WithValue(ctx, principalKey, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	if ctx == nil {
		return Principal{}, false
	}
	principal, ok := ctx.Value(principalKey).(Principal)
	return principal, ok && principal.ID != ""
}
