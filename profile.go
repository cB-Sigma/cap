// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cap

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Profile is a set of rules a community adds to CAP 1.2, such as a
// national alerting authority's profile. Pass profiles in Options.Profiles;
// Check and Validate run them after the CAP 1.2 rules. The profiles this
// module provides (CAPCP, IPAWS, India) are written from each profile's
// public document in our own words; an application adds its own by
// implementing Profile or with NewProfile.
type Profile interface {
	// Name identifies the profile in problems, such as "CAP-CP".
	Name() string
	// Check returns the alert's problems under the profile's rules (nil
	// when it complies). The alert has already been read; it may not be
	// valid CAP 1.2.
	Check(a *Alert) []Problem
}

type funcProfile struct {
	name  string
	check func(a *Alert) []Problem
}

func (p funcProfile) Name() string             { return p.name }
func (p funcProfile) Check(a *Alert) []Problem { return p.check(a) }

// NewProfile makes a profile from a name and a check function.
func NewProfile(name string, check func(a *Alert) []Problem) Profile {
	return funcProfile{name: name, check: check}
}

var (
	registryMu sync.RWMutex
	registry   = map[string]func() Profile{}
)

// RegisterProfile makes a profile available to ProfileByName (for
// configurations that name profiles). The built-in profiles are
// registered as "CAP-CP", "IPAWS" and "India". Registering a name again
// replaces it.
func RegisterProfile(name string, make func() Profile) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[strings.ToLower(name)] = make
}

// ProfileByName returns a registered profile; the name's case is ignored.
func ProfileByName(name string) (Profile, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	m, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return nil, false
	}
	return m(), true
}

// ProfileNames lists the registered profiles, sorted.
func ProfileNames() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	var out []string
	for _, m := range registry {
		out = append(out, m().Name())
	}
	sort.Strings(out)
	return out
}

// DetectProfiles returns the built-in profiles an alert declares in its
// code elements (CAP-CP and IPAWS name themselves there). India's profile
// is not declared in alerts and is never detected.
func DetectProfiles(a *Alert) []Profile {
	var out []Profile
	seen := map[string]bool{}
	for _, c := range a.Code {
		c = strings.TrimSpace(c)
		switch {
		case strings.HasPrefix(c, "profile:CAP-CP:") && !seen["cp"]:
			seen["cp"] = true
			out = append(out, CAPCP())
		case strings.HasPrefix(c, "IPAWSv") && !seen["ipaws"]:
			seen["ipaws"] = true
			out = append(out, IPAWS())
		}
	}
	return out
}

// problems collects a profile's findings.
type problems struct {
	profile string
	list    []Problem
}

func (p *problems) err(rule, field, format string, args ...any) {
	p.list = append(p.list, Problem{Field: field, Issue: fmt.Sprintf(format, args...), Profile: p.profile, Rule: rule})
}

func (p *problems) warn(rule, field, format string, args ...any) {
	p.list = append(p.list, Problem{Field: field, Issue: fmt.Sprintf(format, args...), Profile: p.profile, Rule: rule, Warning: true})
}

// values returns the values of the named entries.
func values(nv []NamedValue, name string) []string {
	var out []string
	for _, v := range nv {
		if v.ValueName == name {
			out = append(out, v.Value)
		}
	}
	return out
}

func hasPrefixName(nv []NamedValue, prefix string) bool {
	for _, v := range nv {
		if strings.HasPrefix(v.ValueName, prefix) {
			return true
		}
	}
	return false
}
