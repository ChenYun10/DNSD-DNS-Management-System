package api

import (
	"net/http"
	"strings"

	"github.com/miekg/dns"

	"dns-platform/internal/dnsx"
	"dns-platform/internal/model"
	"dns-platform/internal/store"
)

// simulate implements 前端 ECS 模拟: an authenticated caller submits a qname,
// qtype and an optional ECS subnet; the API runs it through the exact same
// pipeline as a real query (cache lookup → 分流 → upstream → DNSSEC) and
// returns the full trace so the frontend can show how the query would be
// answered for that subnet, before any client actually sends it.
func (a *API) simulate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		QName    string `json:"qname"`
		QType    string `json:"qtype"`
		ECS      string `json:"ecs"`       // e.g. "203.0.113.0/24" (optional)
		TenantID string `json:"tenant_id"` // optional; default = caller's tenant
		Flush    bool   `json:"flush"`     // purge the cache key first
	}
	if err := readJSON(w, r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	qname := strings.TrimSpace(in.QName)
	if qname == "" {
		writeErr(w, http.StatusBadRequest, "qname required")
		return
	}
	qtype := in.QType
	if qtype == "" {
		qtype = "A"
	}
	if _, ok := dns.StringToType[qtype]; !ok {
		writeErr(w, http.StatusBadRequest, "invalid qtype")
		return
	}

	// tenant selection with RBAC scoping
	c := claimsFrom(r)
	tenantID := in.TenantID
	if tenantID == "" {
		tenantID = c.TID
	}
	if c.Role != string(model.RoleAdmin) && c.TID != tenantID {
		writeErr(w, http.StatusForbidden, "not your tenant")
		return
	}
	var tenant *model.Tenant
	if tenantID != "" {
		t, err := a.repos.GetTenant(r.Context(), tenantID)
		if err != nil || t == nil {
			writeErr(w, http.StatusNotFound, "tenant not found")
			return
		}
		tenant = t
	}

	// parse simulated ECS
	var ecs *dnsx.ECSInfo
	var err error
	if in.ECS != "" {
		ecs, err = dnsx.ParseECS(in.ECS)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// optional: flush the target cache key so the simulation shows a cold path
	if in.Flush && tenant != nil {
		ecsKey := ""
		if ecs != nil {
			ecsKey = ecs.String()
		}
		key := store.CacheKey(tenant.ID, ecsKey, strings.ToLower(qname), qtype)
		a.core.CacheDriver().Del(r.Context(), key)
	}

	// build the query exactly like a client would
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), dns.StringToType[qtype])
	req.SetEdns0(1232, true) // DO bit on: DNSSEC data requested
	meta := &dnsx.RequestMeta{
		Via:           "simulate",
		Tenant:        tenant,
		ClientIP:      nil,
		SimulateECS:   ecs,
		SkipRateLimit: true,
	}
	resp, rm := a.core.Process(r.Context(), req, meta)

	out := &model.SimulateResult{
		QName:           strings.ToLower(qname),
		QType:           qtype,
		ECSRequested:    in.ECS,
		CacheHit:        rm.CacheHit,
		RCode:           rm.RCode,
		DNSSECValidated: rm.DNSSECOK,
	}
	if tenant != nil {
		out.TenantID = tenant.ID
		out.TenantName = tenant.Name
		out.VIP = tenant.VIP
	}
	if ecs != nil {
		out.ECSUsed = ecs.String()
	}
	out.UpstreamGroup = rm.UpstreamGroup
	out.Upstream = rm.Upstream
	out.RTTMS = rm.RTTMS
	out.RuleMatched = rm.RuleMatched
	if resp != nil {
		out.Answers = briefAnswers(resp)
	}
	writeJSON(w, http.StatusOK, out)
}

func briefAnswers(m *dns.Msg) []model.AnswerBrief {
	var out []model.AnswerBrief
	rrToBrief := func(rr dns.RR) model.AnswerBrief {
		return model.AnswerBrief{
			Name: rr.Header().Name,
			Type: dns.TypeToString[rr.Header().Rrtype],
			TTL:  rr.Header().Ttl,
			Data: rrString(rr),
		}
	}
	for _, rr := range m.Answer {
		out = append(out, rrToBrief(rr))
	}
	if len(out) == 0 {
		for _, rr := range m.Ns {
			out = append(out, rrToBrief(rr))
		}
	}
	return out
}

func rrString(rr dns.RR) string {
	s := rr.String()
	// strip the header prefix "name. ttl IN type " — keep the RDATA
	parts := strings.SplitN(s, "\t", 5)
	if len(parts) == 5 {
		return parts[4]
	}
	return s
}
