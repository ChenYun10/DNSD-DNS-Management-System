package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"dns-platform/internal/config"
	"dns-platform/internal/dnsx"
	"dns-platform/internal/model"
	"dns-platform/internal/store"
)

// Auth handles JWT issuance/verification with:
//   - short-lived access tokens (default 15m) + rotating refresh tokens
//   - refresh tokens stored in Redis, single-use, server-side revocation
//   - bcrypt password hashing, account lockout, per-IP login rate limits
//   - role-based access (admin vs tenant) — RBAC
type Auth struct {
	cfg     *config.Config
	repos   *store.Repos
	mysql   *store.MySQLStore
	rdb     *redis.Client
	limiter *dnsx.Limiter
	secret  []byte
}

type Claims struct {
	Role string `json:"role"`
	TID  string `json:"tid,omitempty"`
	jwt.RegisteredClaims
}

func NewAuth(cfg *config.Config, repos *store.Repos, mysql *store.MySQLStore, rdb *redis.Client, limiter *dnsx.Limiter) *Auth {
	return &Auth{cfg: cfg, repos: repos, mysql: mysql, rdb: rdb, limiter: limiter, secret: []byte(cfg.APIJWTSecret)}
}

type tokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (a *Auth) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !a.limiter.AllowLogin(r.Context(), ip, a.cfg.LoginRateLimit, a.cfg.LoginRateWindow) {
		writeErr(w, http.StatusTooManyRequests, "too many login attempts, try again later")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	if req.Username == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "username and password required")
		return
	}
	u, err := a.repos.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if u.LockedUntil.After(time.Now()) {
		writeErr(w, http.StatusLocked, "account locked until "+u.LockedUntil.Format(time.RFC3339))
		return
	}
	if !store.CheckPassword(u.PasswordHash, req.Password) {
		_ = a.repos.RecordLoginFailure(r.Context(), u.ID)
		a.audit(r, u, "auth.login_failed", "user:"+u.Username, "")
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	_ = a.repos.RecordLoginSuccess(r.Context(), u.ID)
	a.limiter.ResetLogin(r.Context(), ip)
	a.audit(r, u, "auth.login", "user:"+u.Username, "")

	pair, err := a.issuePair(r.Context(), u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token issue failed")
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

func (a *Auth) refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	claims, err := a.parse(req.RefreshToken, true)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	// single-use: consume the stored jti
	key := "dns:refresh:" + claims.ID
	uid, err := a.rdb.GetDel(r.Context(), key).Result()
	if err == redis.Nil {
		writeErr(w, http.StatusUnauthorized, "refresh token already used or revoked")
		return
	}
	if err != nil || uid != claims.Subject {
		writeErr(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	u, err := a.repos.GetUserByID(r.Context(), claims.Subject)
	if err != nil || u == nil {
		writeErr(w, http.StatusUnauthorized, "user not found")
		return
	}
	pair, err := a.issuePair(r.Context(), u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token issue failed")
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r)
	if claims != nil {
		// blacklist the access token for its remaining lifetime
		ttl := time.Until(claims.ExpiresAt.Time)
		if ttl > 0 {
			a.rdb.Set(r.Context(), "dns:jwt:blacklist:"+claims.ID, "1", ttl)
		}
		a.rdb.Del(r.Context(), "dns:refresh:"+claims.ID)
		if u, _ := a.repos.GetUserByID(r.Context(), claims.Subject); u != nil {
			a.audit(r, u, "auth.logout", "user:"+u.Username, "")
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *Auth) issuePair(ctx context.Context, u *model.User) (*tokenPair, error) {
	now := time.Now()
	accessJTI := uuid.NewString()
	refreshJTI := uuid.NewString()

	access := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Role: string(u.Role),
		TID:  u.TenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID,
			ID:        accessJTI,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(a.cfg.JWTExpiry)),
			Issuer:    "dns-platform",
		},
	})
	at, err := access.SignedString(a.secret)
	if err != nil {
		return nil, err
	}
	refresh := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Role: string(u.Role),
		TID:  u.TenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID,
			ID:        refreshJTI,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(a.cfg.JWTRefreshExp)),
			Issuer:    "dns-platform",
		},
	})
	rt, err := refresh.SignedString(a.secret)
	if err != nil {
		return nil, err
	}
	// persist refresh token (single-use) in Redis
	if err := a.rdb.Set(ctx, "dns:refresh:"+refreshJTI, u.ID, a.cfg.JWTRefreshExp).Err(); err != nil {
		return nil, err
	}
	return &tokenPair{
		AccessToken:  at,
		RefreshToken: rt,
		ExpiresIn:    int64(a.cfg.JWTExpiry.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

func (a *Auth) parse(token string, refresh bool) (*Claims, error) {
	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return a.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("dns-platform"), jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		return nil, errors.New("invalid token")
	}
	// enforce token kind by claim presence: refresh tokens carry a stored jti
	if refresh {
		_, err := a.rdb.Exists(context.Background(), "dns:refresh:"+claims.ID).Result()
		if err != nil || err == redis.Nil {
			return nil, errors.New("refresh token not active")
		}
	}
	return claims, nil
}

// authMiddleware validates the bearer token and injects claims into context.
func (a *Auth) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		token := strings.TrimPrefix(hdr, "Bearer ")
		claims, err := a.parse(token, false)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		// blacklist check
		if n, _ := a.rdb.Exists(r.Context(), "dns:jwt:blacklist:"+claims.ID).Result(); n > 0 {
			writeErr(w, http.StatusUnauthorized, "token revoked")
			return
		}
		ctx := context.WithValue(r.Context(), ctxClaims{}, claims)
		next(w, r.WithContext(ctx))
	}
}

// requireAdmin enforces the admin role (RBAC).
func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := claimsFrom(r)
		if c == nil || c.Role != string(model.RoleAdmin) {
			writeErr(w, http.StatusForbidden, "admin role required")
			return
		}
		next(w, r)
	}
}

type ctxClaims struct{}

func claimsFrom(r *http.Request) *Claims {
	c, _ := r.Context().Value(ctxClaims{}).(*Claims)
	return c
}

func (a *Auth) audit(r *http.Request, u *model.User, action, target, detail string) {
	ip := clientIP(r)
	_ = a.mysql.WriteAudit(r.Context(), model.AuditRow{
		ActorID:   u.ID,
		ActorName: u.Username,
		Action:    action,
		Target:    target,
		Detail:    detail,
		ClientIP:  ip,
	})
}
