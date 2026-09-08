// Package accesspolicy enforces credentials owned by the local device, not the Hub.
package accesspolicy

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

var ErrState = errors.New("local access policy unavailable; preserve its files and repair local storage")
var ErrDenied = errors.New("invalid or expired device credential")
var ErrLimited = errors.New("too many device authorization attempts; retry in one minute")

const TemporaryTTL = 10 * time.Minute

type Grant struct {
	Kind  string `json:"kind,omitempty"`
	ID    string `json:"id,omitempty"`
	Until int64  `json:"until,omitempty"`
}

type Status struct {
	Enabled            bool       `json:"enabled"`
	FixedPasswordSet   bool       `json:"fixed_password_set"`
	TemporaryActive    bool       `json:"temporary_active"`
	TemporaryExpiresAt *time.Time `json:"temporary_expires_at,omitempty"`
}

type Store struct {
	Home           string
	LegacyPassword string
	Now            func() time.Time
}

type policy struct {
	Version             int    `json:"version"`
	Salt                string `json:"salt"`
	FixedHash           string `json:"fixed_hash"`
	FixedGeneration     string `json:"fixed_generation"`
	TemporaryHash       string `json:"temporary_hash"`
	TemporaryGeneration string `json:"temporary_generation"`
	TemporaryUntil      int64  `json:"temporary_until"`
	TemporaryUsed       bool   `json:"temporary_used"`
	Window              int64  `json:"attempt_window"`
	Attempts            int    `json:"attempts"`
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func secret(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, ErrState
	}
	return b, nil
}

func digest(v string) string { b := sha256.Sum256([]byte(v)); return hex.EncodeToString(b[:]) }
func passwordHash(password, salt string) (string, error) {
	b, err := hex.DecodeString(salt)
	if err != nil || len(b) != 16 {
		return "", ErrState
	}
	key, err := pbkdf2.Key(sha256.New, password, b, 600000, 32)
	if err != nil {
		return "", ErrState
	}
	return hex.EncodeToString(key), nil
}
func validPassword(v string) bool {
	return len(v) >= 12 && len(v) <= 1024 && !strings.ContainsAny(v, "\r\n")
}
func (s *Store) initial() (*policy, error) {
	salt, err := secret(16)
	if err != nil {
		return nil, err
	}
	p := &policy{Version: 1, Salt: hex.EncodeToString(salt)}
	p.FixedHash, err = passwordHash(s.LegacyPassword, p.Salt)
	return p, err
}
func (s *Store) status(p *policy) Status {
	if p == nil {
		return Status{FixedPasswordSet: s.LegacyPassword != ""}
	}
	out := Status{Enabled: true, FixedPasswordSet: p.FixedHash != ""}
	if p.TemporaryUntil > 0 {
		until := time.Unix(p.TemporaryUntil, 0).UTC()
		out.TemporaryExpiresAt = &until
		out.TemporaryActive = p.TemporaryHash != "" && !p.TemporaryUsed && s.now().Before(until)
	}
	return out
}
func (s *Store) Status() (Status, error) {
	var out Status
	err := s.withPolicy(false, func(p *policy) (bool, error) { out = s.status(p); return false, nil })
	return out, err
}
func (s *Store) CreateTemporary() (Status, string, error) {
	raw, err := secret(10)
	if err != nil {
		return Status{}, "", err
	}
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	display := code[:4] + "-" + code[4:8] + "-" + code[8:12] + "-" + code[12:]
	generation, err := secret(16)
	if err != nil {
		return Status{}, "", err
	}
	var out Status
	err = s.withPolicy(true, func(p *policy) (bool, error) {
		p.TemporaryHash = digest(code)
		p.TemporaryGeneration = hex.EncodeToString(generation)
		p.TemporaryUntil = s.now().Add(TemporaryTTL).Unix()
		p.TemporaryUsed = false
		out = s.status(p)
		return true, nil
	})
	if err != nil {
		return Status{}, "", err
	}
	return out, display, nil
}
func (s *Store) RevokeTemporary() (Status, error) {
	var out Status
	err := s.withPolicy(false, func(p *policy) (bool, error) {
		if p == nil {
			out = s.status(p)
			return false, nil
		}
		p.TemporaryHash = ""
		p.TemporaryGeneration = ""
		p.TemporaryUntil = 0
		p.TemporaryUsed = true
		out = s.status(p)
		return true, nil
	})
	return out, err
}
func (s *Store) SetFixed(password string) (Status, error) {
	if !validPassword(password) {
		return Status{}, ErrDenied
	}
	salt, err := secret(16)
	if err != nil {
		return Status{}, err
	}
	generation, err := secret(16)
	if err != nil {
		return Status{}, err
	}
	encoded, err := passwordHash(password, hex.EncodeToString(salt))
	if err != nil {
		return Status{}, err
	}
	var out Status
	err = s.withPolicy(true, func(p *policy) (bool, error) {
		p.Salt = hex.EncodeToString(salt)
		p.FixedHash = encoded
		p.FixedGeneration = hex.EncodeToString(generation)
		out = s.status(p)
		return true, nil
	})
	return out, err
}
func (s *Store) GenerateFixed() (Status, string, error) {
	raw, err := secret(24)
	if err != nil {
		return Status{}, "", err
	}
	password := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	out, err := s.SetFixed(password)
	if err != nil {
		return Status{}, "", err
	}
	return out, password, nil
}

// Verify atomically consumes a temporary code before issuing its OAuth grant.
// Attempts are device-wide and durable; changing IP or restarting does not reset them.
func (s *Store) Verify(value string) (Grant, error) {
	var grant Grant
	err := s.withPolicy(false, func(p *policy) (bool, error) {
		if len(value) == 0 || len(value) > 1024 {
			return false, ErrDenied
		}
		if p == nil {
			if s.LegacyPassword != "" && hmac.Equal([]byte(s.LegacyPassword), []byte(value)) {
				return false, nil
			}
			return false, ErrDenied
		}
		now := s.now().Unix()
		if now >= p.Window+60 {
			p.Window = now
			p.Attempts = 0
		}
		if p.Attempts >= 10 {
			return false, ErrLimited
		}
		p.Attempts++
		hash, err := passwordHash(value, p.Salt)
		if err != nil {
			return false, err
		}
		if hmac.Equal([]byte(hash), []byte(p.FixedHash)) {
			grant = Grant{Kind: "fixed", ID: p.FixedGeneration}
			return true, nil
		}
		normalized := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(value))
		if len(normalized) == 16 && !p.TemporaryUsed && now < p.TemporaryUntil && p.TemporaryHash != "" && hmac.Equal([]byte(digest(normalized)), []byte(p.TemporaryHash)) {
			p.TemporaryUsed = true
			grant = Grant{Kind: "temporary", ID: p.TemporaryGeneration, Until: p.TemporaryUntil}
			return true, nil
		}
		return true, ErrDenied
	})
	return grant, err
}
func (s *Store) FixedGrant() (Grant, error) {
	var g Grant
	err := s.withPolicy(false, func(p *policy) (bool, error) {
		if p != nil {
			g = Grant{Kind: "fixed", ID: p.FixedGeneration}
		}
		return false, nil
	})
	return g, err
}
func (s *Store) Valid(g Grant) bool {
	valid := false
	err := s.withPolicy(false, func(p *policy) (bool, error) {
		switch g.Kind {
		case "", "fixed":
			valid = g.Until == 0 && ((p == nil && g.ID == "") || (p != nil && g.ID == p.FixedGeneration))
		case "temporary":
			valid = p != nil && g.ID != "" && p.TemporaryUsed && g.ID == p.TemporaryGeneration && g.Until == p.TemporaryUntil && s.now().Unix() < g.Until
		}
		return false, nil
	})
	return err == nil && valid
}
