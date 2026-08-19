package dnsx

import (
	"regexp"
	"strings"
	"sync"

	"dns-platform/internal/model"
)

// Splitter implements the upstream 分流 (traffic splitting) engine:
//   - rules are evaluated highest-priority first
//   - tenant-specific rules shadow global rules
//   - first match wins
//
// Rules are cached in memory and refreshed whenever the manager reloads.
type Splitter struct {
	mu    sync.RWMutex
	rules []*model.SplitRule
	regex map[string]*regexp.Regexp // precompiled regex rules
}

func NewSplitter() *Splitter {
	return &Splitter{regex: make(map[string]*regexp.Regexp)}
}

func (s *Splitter) Reload(rules []*model.SplitRule) {
	re := make(map[string]*regexp.Regexp, len(rules))
	for _, r := range rules {
		if r.MatchType == model.MatchRegex && r.MatchValue != "" {
			if rgx, err := regexp.Compile(r.MatchValue); err == nil {
				re[r.ID] = rgx
			}
		}
	}
	s.mu.Lock()
	s.rules = rules
	s.regex = re
	s.mu.Unlock()
}

// Match resolves the upstream group for (tenant, qname).
// Returns the group ID and the rule name ("" when no rule matched).
func (s *Splitter) Match(tenantID, qname string) (groupID, ruleName string) {
	q := strings.ToLower(strings.TrimSuffix(qname, "."))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.rules {
		if !r.Enabled {
			continue
		}
		if r.TenantID != "" && r.TenantID != tenantID {
			continue
		}
		if !s.matchRule(r, q) {
			continue
		}
		return r.GroupID, r.Name
	}
	return "", ""
}

func (s *Splitter) matchRule(r *model.SplitRule, q string) bool {
	switch r.MatchType {
	case model.MatchAll:
		return true
	case model.MatchExact:
		return q == strings.ToLower(r.MatchValue)
	case model.MatchSuffix:
		v := strings.ToLower(r.MatchValue)
		if !strings.HasPrefix(v, ".") {
			v = "." + v
		}
		return strings.HasSuffix(q, v) || q == strings.TrimPrefix(v, ".")
	case model.MatchPrefix:
		return strings.HasPrefix(q, strings.ToLower(r.MatchValue))
	case model.MatchRegex:
		s.mu.RLock()
		rgx := s.regex[r.ID]
		s.mu.RUnlock()
		return rgx != nil && rgx.MatchString(q)
	}
	return false
}

// GroupForQuery is the single entry point used by the handler:
// pinned VIP group wins, then split rules, then defaults.
func (s *Splitter) GroupForQuery(tenant *model.Tenant, qname string) (groupID, ruleName string) {
	if tenant != nil && tenant.UpstreamGroup != "" {
		return tenant.UpstreamGroup, "tenant-pinned(vip)"
	}
	gid, name := s.Match(tenantID(tenant), qname)
	if gid != "" {
		return gid, name
	}
	return "", ""
}

func tenantID(t *model.Tenant) string {
	if t == nil {
		return ""
	}
	return t.ID
}
