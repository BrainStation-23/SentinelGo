// Package pii finds personal data (card numbers, IBANs, national IDs, email
// addresses, phone numbers) using github.com/hoophq/alcatraz: Go ports of
// Microsoft Presidio's pattern recognizers with checksum validators (Luhn for
// cards, ISO 7064 mod-97 for IBANs, …), so a number that fails its checksum is
// dropped rather than flagged.
//
// alcatraz is pre-1.0, so it is pinned in go.mod and used only through this
// package; pii_test.go holds golden results that an upgrade must keep.
package pii

import (
	"sort"
	"strings"
	"sync"

	"github.com/hoophq/alcatraz"
	"github.com/hoophq/alcatraz/entities"
)

// Detector maps a detector id to its alcatraz entity type.
type Detector struct {
	ID     string // e.g. "pii.credit_card"
	Entity string // e.g. "CREDIT_CARD"
	OptIn  bool   // noisy on a clipboard; not preselected in the console
}

// named are the detectors whose id isn't just the lowercased entity type, and
// the defaults (OptIn false) from the backend catalog.
var named = []Detector{
	{ID: "pii.credit_card", Entity: entities.CreditCard},
	{ID: "pii.iban", Entity: entities.IBANCode},
	{ID: "pii.us_ssn", Entity: entities.USSSN},
	{ID: "pii.uk_nino", Entity: entities.UKNINO},
	{ID: "pii.uk_nhs", Entity: entities.UKNHS},
	{ID: "pii.email", Entity: entities.EmailAddress, OptIn: true},
	{ID: "pii.phone", Entity: entities.PhoneNumber, OptIn: true},
}

// excluded entities are never offered: too noisy on a clipboard (US_BANK_NUMBER
// is any 8–17 digits) or needing a statistical model the agent doesn't ship.
var excluded = map[string]bool{
	entities.USBankNumber: true,
	entities.DateTime:     true,
	entities.URL:          true,
	entities.IPAddress:    true,
	entities.Person:       true,
	entities.Location:     true,
	entities.NRP:          true,
}

var (
	engineOnce sync.Once
	engine     *alcatraz.Engine
	detectors  []Detector
	byID       map[string]Detector
)

// load builds the shared engine and the detector list: the named detectors
// plus every other supported entity as an opt-in "pii.<entity>" (country IDs
// such as pii.in_pan).
func load() {
	engineOnce.Do(func() {
		engine = alcatraz.NewEngine()
		byID = map[string]Detector{}
		known := map[string]bool{}
		for _, d := range named {
			byID[d.ID] = d
			known[d.Entity] = true
		}
		for _, e := range engine.SupportedEntities("en") {
			if known[e] || excluded[e] {
				continue
			}
			d := Detector{ID: "pii." + strings.ToLower(e), Entity: e, OptIn: true}
			byID[d.ID] = d
		}
		for _, d := range byID {
			detectors = append(detectors, d)
		}
		sort.Slice(detectors, func(i, j int) bool { return detectors[i].ID < detectors[j].ID })
	})
}

// Detectors returns every supported PII detector, sorted by id.
func Detectors() []Detector {
	load()
	return append([]Detector(nil), detectors...)
}

// Match is one finding. Start and End are byte offsets into the scanned text.
type Match struct {
	DetectorID string
	Start, End int
}

// Scanner runs a fixed set of PII detectors.
type Scanner struct {
	opts     alcatraz.Options
	idOf     map[string]string // entity -> detector id
	disabled bool
}

// New returns a scanner for ids. Ids it doesn't support are returned in
// unknown and ignored.
func New(ids []string) (s *Scanner, unknown []string) {
	load()
	s = &Scanner{idOf: map[string]string{}}
	for _, id := range ids {
		d, ok := byID[id]
		if !ok {
			unknown = append(unknown, id)
			continue
		}
		if _, dup := s.idOf[d.Entity]; !dup {
			s.idOf[d.Entity] = d.ID
			s.opts.Entities = append(s.opts.Entities, d.Entity)
		}
	}
	sort.Strings(s.opts.Entities)
	s.disabled = len(s.opts.Entities) == 0
	return s, unknown
}

// Find returns the PII in text, ordered by offset.
func (s *Scanner) Find(text string) []Match {
	if s == nil || s.disabled {
		return nil
	}
	var out []Match
	for _, r := range engine.Analyze(text, s.opts) {
		if id, ok := s.idOf[r.EntityType]; ok {
			out = append(out, Match{DetectorID: id, Start: r.Start, End: r.End})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		return out[i].DetectorID < out[j].DetectorID
	})
	return out
}
