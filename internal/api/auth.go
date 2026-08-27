package api

import (
	"net/url"

	"log"

	"io"

	"encoding/base64"

	"crypto/sha256"

	"crypto/hmac"

	"bytes"

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
	Role  string `json:"role"`
	TID   string `json:"tid,omitempty"`
	Scope string `json:"scope,omitempty"` // 受限 token 的用途(如 change-password)
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
		fails := u.FailedAttempts + 1
		a.audit(r, u, "auth.login_failed", "user:"+u.Username, "")
		// 等保: 连续失败达到阈值触发安全告警
		if fails >= a.cfg.SecurityAlertMinFails {
			a.sendSecurityAlert("登录失败告警",
				fmt.Sprintf("用户 %s 连续失败 %d 次, IP=%s", u.Username, fails, ip))
		}
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	_ = a.repos.RecordLoginSuccess(r.Context(), u.ID)
	a.limiter.ResetLogin(r.Context(), ip)
	a.audit(r, u, "auth.login", "user:"+u.Username, "")

	// 等保: 强制改密 - 首次发放/管理员标记的账号必须改密后才能继续
	// 发放受限 token(仅 change-password 端点可用), 改密后自动清除标记
	if u.MustChangePwd {
		pair, err := a.issueRestrictedPair(r.Context(), u, "change-password")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "token issue failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"must_change_password": true,
			"message":              "password must be changed before continuing",
			"access_token":         pair.AccessToken,
			"token_type":           pair.TokenType,
			"expires_in":           pair.ExpiresIn,
		})
		return
	}

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

// issueRestrictedPair 签发受限 token(scope 限制, 用于强制改密等场景)
func (a *Auth) issueRestrictedPair(ctx context.Context, u *model.User, scope string) (*tokenPair, error) {
	now := time.Now()
	accessJTI := uuid.NewString()
	access := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Role:  string(u.Role),
		TID:   u.TenantID,
		Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID,
			ID:        accessJTI,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			Issuer:    "dns-platform",
		},
	})
	at, err := access.SignedString(a.secret)
	if err != nil {
		return nil, err
	}
	return &tokenPair{
		AccessToken:  at,
		ExpiresIn:    900,
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
		// 受限 token(scope)只能访问对应端点(等保: 强制改密流程的最小权限)
		if claims.Scope != "" && r.URL.Path != "/api/v1/auth/change-password" {
			writeErr(w, http.StatusForbidden, "restricted token cannot access this endpoint")
			return
		}
		ctx := context.WithValue(r.Context(), ctxClaims{}, claims)
		next(w, r.WithContext(ctx))
	}
}

// requireAdmin enforces the admin role (RBAC) — 兼容旧代码,admin 或 sysadmin 均可
func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return requireRole(model.RoleAdmin, model.RoleSysAdmin)(next)
}

// requireRole enforces that the caller holds at least one of the allowed roles.
// 三员分立:每个管理端点声明自己的角色白名单,越权访问返回 403。
func requireRole(roles ...model.Role) func(http.HandlerFunc) http.HandlerFunc {
	allowed := map[model.Role]bool{}
	for _, r := range roles {
		allowed[r] = true
	}
	// admin(旧超管)视为 sysadmin,继承业务配置权限
	allowed[model.RoleAdmin] = allowed[model.RoleSysAdmin]
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			c := claimsFrom(r)
			if c == nil || !allowed[model.Role(c.Role)] {
				writeErr(w, http.StatusForbidden, "insufficient role")
				return
			}
			next(w, r)
		}
	}
}

type ctxClaims struct{}

// PasswordPolicy 等保密码策略:长度≥10,含大小写字母+数字+特殊字符,禁止与用户名相同
const (
	passwordMinLen  = 10
	passwordMaxLen  = 72 // bcrypt 输入上限
)

// ValidatePasswordStrength 校验密码复杂度,返回错误描述(空串=通过)
func ValidatePasswordStrength(username, password string) string {
	if len(password) < passwordMinLen {
		return fmt.Sprintf("password must be at least %d characters", passwordMinLen)
	}
	if len(password) > passwordMaxLen {
		return fmt.Sprintf("password must be at most %d characters", passwordMaxLen)
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return "password must contain upper, lower, digit and special characters"
	}
	if strings.Contains(strings.ToLower(password), strings.ToLower(username)) && username != "" {
		return "password must not contain the username"
	}
	return ""
}

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

// sendSecurityAlert 发送安全告警到 webhook(钉钉/企微兼容), 带冷却防刷屏
// 等保: 安全管理中心 - 异常登录/权限变更实时告警
func (a *Auth) sendSecurityAlert(title, content string) {
	if a.cfg.SecurityAlertWebhook == "" {
		return
	}
	key := "dns:alert:cooldown:" + title
	if n, err := a.rdb.Exists(context.Background(), key).Result(); err == nil && n > 0 {
		return // 冷却中
	}
	if a.cfg.SecurityAlertCooldown > 0 {
		a.rdb.Set(context.Background(), key, "1", a.cfg.SecurityAlertCooldown)
	}
	msg := map[string]any{
		"msgtype": "text",
		"text": map[string]string{
			"content": "[dns-platform安全告警] " + title + "\n" + content + "\n时间: " + time.Now().Format("2006-01-02 15:04:05"),
		},
	}
	body, _ := json.Marshal(msg)
	webhookURL := a.cfg.SecurityAlertWebhook
	if a.cfg.SecurityAlertToken != "" {
		ts := time.Now().UnixMilli()
		h := hmac.New(sha256.New, []byte(a.cfg.SecurityAlertToken))
		h.Write([]byte(fmt.Sprintf("%d\n%s", ts, a.cfg.SecurityAlertToken)))
		sign := url.QueryEscape(base64.StdEncoding.EncodeToString(h.Sum(nil)))
		webhookURL = fmt.Sprintf("%s&timestamp=%d&sign=%s", webhookURL, ts, sign)
	}
	req, err := http.NewRequest("POST", webhookURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	cli := &http.Client{Timeout: 5 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		log.Printf("[alert] send failed: %v", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

// changePassword 自助改密(等保: 用户可自行更换密码, 校验旧密码+复杂度+历史)
func (a *Auth) changePassword(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r)
	if c == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var in struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	u, err := a.repos.GetUserByID(r.Context(), c.Subject)
	if err != nil || u == nil {
		writeErr(w, http.StatusUnauthorized, "user not found")
		return
	}
	if !store.CheckPassword(u.PasswordHash, in.OldPassword) {
		writeErr(w, http.StatusBadRequest, "old password incorrect")
		return
	}
	if msg := ValidatePasswordStrength(u.Username, in.NewPassword); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	reused, err := a.repos.CheckPasswordHistory(r.Context(), u.ID, in.NewPassword, 5)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if reused {
		writeErr(w, http.StatusBadRequest, "password was used recently, choose a new one")
		return
	}
	if err := a.repos.SetPassword(r.Context(), u.ID, in.NewPassword); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// 改密后吊销其它会话
	_ = a.repos.RevokeAllSessions(r.Context(), u.ID, a.rdb)
	a.audit(r, u, "auth.password_changed", "user:"+u.Username, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
