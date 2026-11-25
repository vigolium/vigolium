package config

// PaceFields lists the three pace dials, in the order every table prints them.
var PaceFields = []string{PaceFieldConcurrency, PaceFieldRateLimit, PaceFieldMaxPerHost}

// PhaseDial is one (phase, dial) pair of the pace vocabulary.
type PhaseDial struct {
	Phase string
	Dial  string
}

// PhasePacePair is one (phase, dial) pair and whether the phase enforces it.
type PhasePacePair struct {
	PhaseDial
	Enforced bool
}

// PhasePacePairs lists every (phase, dial) pair with whether the phase
// enforces it (phasePaceSupport), phases sorted, dials in PaceFields order.
// `schema pace` publishes it so a caller reads which pairs bind instead of
// mirroring the table.
func PhasePacePairs() []PhasePacePair {
	var out []PhasePacePair
	for _, phase := range PhaseSectionNames() {
		for _, dial := range PaceFields {
			out = append(out, PhasePacePair{PhaseDial{phase, dial}, PhasePaceSupports(phase, dial)})
		}
	}
	return out
}

// EnforcedPhaseDials lists the pairs that bind, as "phase=dial" in
// PhasePacePairs order, for messages.
func EnforcedPhaseDials() []string {
	var out []string
	for _, p := range PhasePacePairs() {
		if p.Enforced {
			out = append(out, p.Phase+"="+p.Dial)
		}
	}
	return out
}

// UnenforcedPhasePace returns, for the given phases, the dials their pace
// section sets that the phase does not enforce: values a config file (or a
// profile, project overlay or --set) put where nothing reads them. Phases in
// the order given, dials in PaceFields order.
func (c *ScanningPaceConfig) UnenforcedPhasePace(phases []string) []PhaseDial {
	if c == nil {
		return nil
	}
	var out []PhaseDial
	for _, phase := range phases {
		section := c.Section(phase)
		if section == nil {
			continue
		}
		for _, dial := range PaceFields {
			if PhasePaceSupports(phase, dial) || phasePaceValue(section, dial) == 0 {
				continue
			}
			out = append(out, PhaseDial{Phase: phase, Dial: dial})
		}
	}
	return out
}

func phasePaceValue(p *PhasePace, dial string) int {
	switch dial {
	case PaceFieldConcurrency:
		return p.Concurrency
	case PaceFieldRateLimit:
		return p.RateLimit
	case PaceFieldMaxPerHost:
		return p.MaxPerHost
	}
	return 0
}
