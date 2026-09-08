package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"mcpx/internal/accesspolicy"
	"time"
)

func (s *Server) fixedGrant() (accesspolicy.Grant, error) {
	if s.Access == nil {
		return accesspolicy.Grant{}, nil
	}
	return s.Access.FixedGrant()
}
func (s *Server) validGrant(g accesspolicy.Grant) bool {
	if s.Access == nil {
		return g == (accesspolicy.Grant{})
	}
	return s.Access.Valid(g)
}
func claimGrant(claims jwt.MapClaims) (accesspolicy.Grant, error) {
	var g accesspolicy.Grant
	value, ok := claims["device_grant"]
	if !ok {
		return g, nil
	}
	raw, err := json.Marshal(value)
	if err != nil || string(raw) == "null" || json.Unmarshal(raw, &g) != nil {
		return g, fmt.Errorf("invalid_grant")
	}
	return g, nil
}

// AuthorizeCredential joins credential verification and grant creation; temporary
// credentials must never go through a boolean check that loses their restrictions.
func (s *Server) AuthorizeCredential(password, clientID, redirectURI, challenge, method, resource, scope string) (string, error) {
	if !s.AcceptsClientRedirect(clientID, redirectURI) || !ValidChallenge(challenge) || (method != "" && method != "S256") {
		return "", fmt.Errorf("invalid authorization request")
	}
	if scope != "" && scope != DefaultScope {
		return "", fmt.Errorf("invalid scope")
	}
	if s.ServerURL != "" && resource != s.ResourceURL(s.ServerURL) {
		return "", fmt.Errorf("invalid resource")
	}
	// Also bound legacy-password attempts before a durable local policy exists.
	s.mu.Lock()
	if time.Since(s.passwordWindow) >= time.Minute {
		s.passwordWindow = time.Now()
		s.passwordAttempts = 0
	}
	limited := s.passwordAttempts >= 10
	if !limited {
		s.passwordAttempts++
	}
	s.mu.Unlock()
	if limited {
		return "", accesspolicy.ErrLimited
	}
	var g accesspolicy.Grant
	var err error
	if s.Access != nil {
		g, err = s.Access.Verify(password)
	} else if !s.CheckPassword(password) {
		err = accesspolicy.ErrDenied
	}
	if err != nil {
		return "", err
	}
	return s.issueCode(clientID, redirectURI, challenge, method, resource, scope, g)
}

// RefreshForAccessToken retains the authenticated grant, rather than silently
// upgrading a short temporary approval to a thirty-day fixed-password grant.
func (s *Server) RefreshForAccessToken(token, scope string) (string, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("invalid_grant")
		}
		return s.TokenSecret, nil
	}, jwt.WithExpirationRequired())
	if err != nil || !parsed.Valid {
		return "", fmt.Errorf("invalid_grant")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid_grant")
	}
	g, err := claimGrant(claims)
	if err != nil || !s.validGrant(g) {
		return "", fmt.Errorf("invalid_grant")
	}
	cid, _ := claims["client_id"].(string)
	audiences, err := claims.GetAudience()
	if err != nil || len(audiences) != 1 || cid == "" {
		return "", fmt.Errorf("invalid_grant")
	}
	next := s.issueRefresh(cid, audiences[0], scope, g, time.Now().Add(RefreshTokenTTLSeconds*time.Second))
	if next == "" {
		return "", fmt.Errorf("invalid_grant")
	}
	return next, nil
}
