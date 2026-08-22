// Package certmgr implements admin-managed SSL for the DNS platform (后台做
// SSL): ACME issuance and automatic renewal for tenant custom main domains.
//
//   - HTTP-01 (default): the customer points an A record at this server; the
//     CA validates via /.well-known/acme-challenge/ which nginx proxies to
//     the challenge listener (ACME_HTTP_PORT, default 127.0.0.1:5002).
//   - DNS-01 (Aliyun): for domains hosted on Aliyun DNS (wildcard-capable),
//     using ALIYUN_ACCESS_KEY_ID / ALIYUN_ACCESS_KEY_SECRET.
//
// Certificates are stored under {CertDir}/domains/<domain>/ as
// fullchain.pem + privkey.pem; the DNS data plane (dnsd) picks them up by SNI.
package certmgr

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/registration"
	"github.com/redis/go-redis/v9"

	"dns-platform/internal/config"
	"dns-platform/internal/model"
	"dns-platform/internal/store"
)

type acmeUser struct {
	email        string
	key          *ecdsa.PrivateKey
	registration *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// Manager issues and renews certificates for tenant domains.
type Manager struct {
	cfg   *config.Config
	repos *store.Repos
	rdb   redisClient

	mu           sync.Mutex
	client       *lego.Client
	user         *acmeUser
	directoryURL string
}

// redisClient is a minimal subset used to bump the config version.
type redisClient interface {
	Incr(ctx context.Context, key string) *redis.IntCmd
}

func New(cfg *config.Config, repos *store.Repos, rdb redisClient) (*Manager, error) {
	m := &Manager{cfg: cfg, repos: repos, rdb: rdb}
	if !cfg.ACMEEnabled {
		return m, nil
	}
	if cfg.ACMEEmail == "" {
		return nil, errors.New("ACME_EMAIL is required when ACME_ENABLED=true")
	}
	if err := os.MkdirAll(filepath.Join(cfg.CertDir, "domains"), 0o755); err != nil {
		return nil, err
	}
	if err := m.initClient(); err != nil {
		return nil, err
	}
	// HTTP-01 challenge listener (nginx proxies /.well-known/acme-challenge/).
	host, port, err := net.SplitHostPort(cfg.ACMEHTTPPort)
	if err != nil {
		host, port = "127.0.0.1", cfg.ACMEHTTPPort
	}
	provider := http01.NewProviderServer(host, port)
	if err := m.client.Challenge.SetHTTP01Provider(provider); err != nil {
		return nil, fmt.Errorf("http01 provider: %w", err)
	}
	log.Printf("[certmgr] ready (CA=%s email=%s http01=%s)", m.directoryURL, cfg.ACMEEmail, cfg.ACMEHTTPPort)
	return m, nil
}

func (m *Manager) initClient() error {
	acctDir := filepath.Join(m.cfg.CertDir, "acme")
	if err := os.MkdirAll(acctDir, 0o700); err != nil {
		return err
	}
	keyPath := filepath.Join(acctDir, "account.key")
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return err
	}
	m.user = &acmeUser{email: m.cfg.ACMEEmail, key: key}

	lc := lego.NewConfig(m.user)
	lc.Certificate.KeyType = certcrypto.EC384
	switch {
	case m.cfg.ACMEDirectoryURL != "":
		lc.CADirURL = m.cfg.ACMEDirectoryURL
	case m.cfg.ACMEStaging:
		lc.CADirURL = lego.LEDirectoryStaging
	default:
		lc.CADirURL = lego.LEDirectoryProduction
	}
	client, err := lego.NewClient(lc)
	if err != nil {
		return err
	}
	m.directoryURL = lc.CADirURL
	// Reuse an existing registration if we already registered before.
	if reg, err := client.Registration.ResolveAccountByKey(); err == nil && reg != nil {
		m.user.registration = reg
	} else {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("acme register: %w", err)
		}
		m.user.registration = reg
	}
	m.client = client
	return nil
}

func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
				return k, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// DomainCertDir returns the on-disk directory for a domain's certificate.
func (m *Manager) DomainCertDir(domain string) string {
	return filepath.Join(m.cfg.CertDir, "domains", strings.ToLower(domain))
}

func (m *Manager) certPaths(domain string) (certFile, keyFile string) {
	d := m.DomainCertDir(domain)
	return filepath.Join(d, "fullchain.pem"), filepath.Join(d, "privkey.pem")
}

// LoadDomainCert loads a domain's certificate as a tls.Certificate.
func (m *Manager) LoadDomainCert(domain string) (*tls.Certificate, error) {
	certFile, keyFile := m.certPaths(domain)
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// CertExpiryFromFile parses the first certificate in a PEM file and returns
// its NotAfter. Used by the API daemon to report base-cert status.
func CertExpiryFromFile(certFile string) (time.Time, error) {
	b, err := os.ReadFile(certFile)
	if err != nil {
		return time.Time{}, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return time.Time{}, errors.New("no PEM block")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter, nil
}

// DomainCertExpiry parses the stored certificate and returns its expiry.
func (m *Manager) DomainCertExpiry(domain string) (time.Time, error) {
	certFile, _ := m.certPaths(domain)
	b, err := os.ReadFile(certFile)
	if err != nil {
		return time.Time{}, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return time.Time{}, errors.New("no PEM block in fullchain")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return c.NotAfter, nil
}

func (m *Manager) persist(domain string, res *certificate.Resource) error {
	dir := m.DomainCertDir(domain)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	certFile, keyFile := m.certPaths(domain)
	if err := os.WriteFile(certFile, res.Certificate, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, res.PrivateKey, 0o600); err != nil {
		return err
	}
	log.Printf("[certmgr] stored cert for %s", domain)
	return nil
}

// Issue issues (or renews) a certificate for a tenant domain and persists it.
// method: "http01" (default) or "dns01" (Aliyun, wildcard-capable).
func (m *Manager) Issue(ctx context.Context, td *model.TenantDomain, method string) error {
	if !m.cfg.ACMEEnabled {
		return errors.New("ACME manager disabled (ACME_ENABLED=false)")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	domain := strings.ToLower(strings.TrimSuffix(td.Domain, "."))
	m.repos.SetDomainCert(ctx, td.ID, model.CertIssuing, nil, "")

	domains := []string{domain}
	if method == "dns01" {
		if m.cfg.AliyunAccessKeyID == "" || m.cfg.AliyunAccessKeySecret == "" {
			return errors.New("dns01 requires ALIYUN_ACCESS_KEY_ID/SECRET")
		}
		domains = append(domains, "*."+domain)
		if err := m.setDNS01Provider(); err != nil {
			m.repos.SetDomainCert(ctx, td.ID, model.CertError, nil, err.Error())
			return err
		}
	} else {
		domains = []string{domain}
	}

	req := certificate.ObtainRequest{Domains: domains}
	res, err := m.client.Certificate.Obtain(req)
	if err != nil {
		m.repos.SetDomainCert(ctx, td.ID, model.CertError, nil, err.Error())
		return fmt.Errorf("obtain %s: %w", domain, err)
	}
	if err := m.persist(domain, res); err != nil {
		m.repos.SetDomainCert(ctx, td.ID, model.CertError, nil, err.Error())
		return err
	}
	exp, _ := m.DomainCertExpiry(domain)
	m.repos.SetDomainCert(ctx, td.ID, model.CertActive, &exp, "")
	m.bumpConfigVersion()
	return nil
}

func (m *Manager) setDNS01Provider() error {
	cfg := alidns.NewDefaultConfig()
	cfg.APIKey = m.cfg.AliyunAccessKeyID
	cfg.SecretKey = m.cfg.AliyunAccessKeySecret
	cfg.RegionID = "cn-hangzhou"
	provider, err := alidns.NewDNSProviderConfig(cfg)
	if err != nil {
		return err
	}
	// lego v4.35+: CNAME following is enabled by default (no option needed)
	return m.client.Challenge.SetDNS01Provider(provider)
}

// RenewLoop runs forever: every 12h (plus once at startup) it renews every
// tenant-domain certificate that is missing or expiring within
// CERT_RENEW_BEFORE (default 30 days), then bumps the dnsd config version so
// the data plane reloads the new certificate files.
func (m *Manager) RenewLoop(ctx context.Context) {
	if !m.cfg.ACMEEnabled {
		log.Printf("[certmgr] ACME disabled — renewal loop not started")
		return
	}
	run := func() {
		domains, err := m.repos.ListTenantDomains(ctx, "")
		if err != nil {
			log.Printf("[certmgr] list domains: %v", err)
			return
		}
		for _, td := range domains {
			if !td.Enabled {
				continue
			}
			need := false
			if td.CertStatus == model.CertError {
				need = true // retry failed issuance
			} else if td.CertExpiry == nil {
				need = true
			} else if time.Until(*td.CertExpiry) < m.cfg.CertRenewBefore {
				need = true
			} else {
				if _, err := m.DomainCertExpiry(td.Domain); err != nil {
					need = true // cert files missing
				}
			}
			if need {
				log.Printf("[certmgr] renewing %s (status=%s expiry=%v)", td.Domain, td.CertStatus, td.CertExpiry)
				if err := m.Issue(ctx, td, "http01"); err != nil {
					log.Printf("[certmgr] renew %s failed: %v", td.Domain, err)
				}
			}
		}
	}
	run()
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// BumpConfigVersion tells dnsd to hot-reload (tenants + cert files).
func (m *Manager) bumpConfigVersion() {
	if m.rdb != nil {
		if _, err := m.rdb.Incr(context.Background(), "dns:config:version").Result(); err != nil {
			log.Printf("[certmgr] bump version: %v", err)
		}
	}
}
