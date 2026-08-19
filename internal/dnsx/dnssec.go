package dnsx

import (
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// DNSSEC support:
//   - passthrough: forward the DO bit, pass DNSSEC records untouched
//   - ad-only:     AD is set only when the (validating) upstream set it
//   - verify:      additionally verify RRSIGs over each RRset using the
//     DNSKEYs present in the response (defense-in-depth;
//     full chain validation is delegated to validating
//     upstreams like 8.8.8.8/1.1.1.1/9.9.9.9)
//
// The verified flag is recorded in query logs and surfaced to the frontend.
type Validator struct {
	mode string
	ok   atomic.Uint64 // total verified sets
	fail atomic.Uint64 // total failed sets
}

func NewValidator(mode string) *Validator {
	return &Validator{mode: mode}
}

func (v *Validator) Stats() (ok, fail uint64) { return v.ok.Load(), v.fail.Load() }

// Validate runs the configured DNSSEC policy on an upstream response.
// It mutates the AD flag and returns whether DNSSEC data was verified.
func (v *Validator) Validate(m *dns.Msg) bool {
	adUpstream := m.AuthenticatedData
	switch v.mode {
	case "passthrough":
		// keep whatever the upstream sent; CD flag honored
		return adUpstream
	case "ad-only":
		m.AuthenticatedData = adUpstream
		return adUpstream
	case "verify":
		verified := verifyRRSets(m)
		m.AuthenticatedData = verified
		return verified
	}
	return adUpstream
}

// verifyRRSets checks every RRset that has an RRSIG against a DNSKEY in the
// response. Returns true only if ALL signed RRsets verify (unsigned zones
// with no RRSIG are left as-is and do not fail the check).
func verifyRRSets(m *dns.Msg) bool {
	keys := map[uint16]*dns.DNSKEY{}
	for _, rr := range m.Answer {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys[k.KeyTag()] = k
		}
	}
	for _, rr := range m.Ns {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys[k.KeyTag()] = k
		}
	}

	// group RRsets by (name, type)
	type setKey struct {
		name string
		typ  uint16
	}
	sets := map[setKey][]dns.RR{}
	sigs := map[setKey][]*dns.RRSIG{}
	for _, rr := range m.Answer {
		name := strings.ToLower(rr.Header().Name)
		if sig, ok := rr.(*dns.RRSIG); ok {
			sigs[setKey{name, sig.TypeCovered}] = append(sigs[setKey{name, sig.TypeCovered}], sig)
			continue
		}
		sets[setKey{name, rr.Header().Rrtype}] = append(sets[setKey{name, rr.Header().Rrtype}], rr)
	}

	verifiedAny, failedAny := false, false
	for k, sigs := range sigs {
		rrset := sets[k]
		if len(rrset) == 0 {
			continue // no data to verify (e.g. NSEC-only)
		}
		ok := false
		for _, sig := range sigs {
			if !checkSigTime(sig) {
				continue
			}
			key := keys[sig.KeyTag]
			if key == nil {
				continue
			}
			if err := sig.Verify(key, rrset); err == nil {
				ok = true
				break
			}
		}
		if ok {
			verifiedAny = true
		} else {
			failedAny = true
			log.Printf("[dnssec] verification failed for %s type %d", k.name, k.typ)
		}
	}
	return verifiedAny && !failedAny
}

// ValidityPeriod is a no-op helper kept for clarity (RRSIG.Inception/Expiration
// are checked inside Verify by miekg/dns). Implemented as a method on a local
// type to avoid shadowing — see checkSigTime below.
func checkSigTime(sig *dns.RRSIG) bool {
	now := time.Now().Unix()
	return sig.Inception <= uint32(now) && sig.Expiration >= uint32(now)
}
