package dnsx

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// CertStore loads per-domain TLS certificates from {CertDir}/domains/<domain>/
// (fullchain.pem + privkey.pem), which the ACME manager (apid) writes. The
// data plane picks the right certificate per SNI for customer custom main
// domains; unknown names fall back to the base wildcard certificate.
type CertStore struct {
	mu    sync.RWMutex
	dir   string
	certs map[string]*certEntry
}

type certEntry struct {
	cert    *tls.Certificate
	covered []string // lowercase names the leaf cert covers (exact + wildcard expanded)
}

// NewCertStore scans the cert directory once at startup.
func NewCertStore(certDir string) *CertStore {
	cs := &CertStore{dir: filepath.Join(certDir, "domains"), certs: map[string]*certEntry{}}
	cs.Reload()
	return cs
}

// Reload rescans the certificate directory (called at startup, on config
// reload, and periodically to pick up newly issued certificates).
func (cs *CertStore) Reload() {
	entries, err := os.ReadDir(cs.dir)
	if err != nil {
		return // directory may not exist yet
	}
	loaded := map[string]*certEntry{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		cert, err := tls.LoadX509KeyPair(
			filepath.Join(cs.dir, name, "fullchain.pem"),
			filepath.Join(cs.dir, name, "privkey.pem"))
		if err != nil {
			continue
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			continue
		}
		covered := []string{}
		for _, n := range leaf.DNSNames {
			covered = append(covered, strings.ToLower(strings.TrimSuffix(n, ".")))
		}
		if leaf.Subject.CommonName != "" {
			covered = append(covered, strings.ToLower(strings.TrimSuffix(leaf.Subject.CommonName, ".")))
		}
		loaded[name] = &certEntry{cert: &cert, covered: covered}
	}
	cs.mu.Lock()
	cs.certs = loaded
	cs.mu.Unlock()
	log.Printf("[certstore] %d domain cert(s) loaded", len(loaded))
}

// Get returns the certificate that covers host (exact match, or a wildcard
// cert of an ancestor apex), or nil.
func (cs *CertStore) Get(host string) *tls.Certificate {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	// exact
	if e, ok := cs.certs[host]; ok && covers(e, host) {
		return e.cert
	}
	// ancestor wildcard (dns01-issued "*.apex" certs are stored under apex)
	rest := host
	for {
		i := strings.Index(rest, ".")
		if i < 0 {
			break
		}
		parent := rest[i+1:]
		if e, ok := cs.certs[parent]; ok && covers(e, host) {
			return e.cert
		}
		rest = parent
	}
	return nil
}

func covers(e *certEntry, host string) bool {
	for _, n := range e.covered {
		if n == host {
			return true
		}
		if strings.HasPrefix(n, "*.") && strings.HasSuffix(host, n[1:]) && host != n[2:] {
			return true
		}
	}
	return false
}
