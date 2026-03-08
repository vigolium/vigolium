package diffscan

type Probe struct {
	Base string
	Name string

	breakStrings  []string
	escapeStrings [][]string

	InjectType ProbeInjectType

	RandomAnchor              bool
	UseCacheBuster            bool
	RequireConsistentEvidence bool
	Severity                  int

	nextBreak  int
	nextEscape int
}

func NewProbe(name string, severity int, breakStrings ...string) *Probe {
	if len(breakStrings) == 0 {
		panic("breakStrings cannot be empty")
	}
	return &Probe{
		Name:                      name,
		Base:                      "'",
		breakStrings:              breakStrings,
		RandomAnchor:              true,
		UseCacheBuster:            false,
		RequireConsistentEvidence: true,
		Severity:                  severity,
		InjectType:                InjectType_Append,
		nextBreak:                 -1,
		nextEscape:                -1,
	}
}

func (p *Probe) GetBreakStrings() []string {
	return p.breakStrings
}

func (p *Probe) GetEscapeStrings() [][]string {
	return p.escapeStrings
}

func (p *Probe) GetAllEscapeSets() [][]string {
	return p.escapeStrings
}

func (p *Probe) SetEscapeStrings(args ...string) {
	for _, escapeString := range args {
		p.escapeStrings = append(p.escapeStrings, []string{escapeString})
	}
}

func (p *Probe) AddEscapePair(args ...string) {
	p.escapeStrings = append(p.escapeStrings, args)
}

func (p *Probe) SetRandomAnchor(randomAnchor bool) {
	p.RandomAnchor = randomAnchor
	p.UseCacheBuster = !randomAnchor
}

func (p *Probe) SetUseCacheBuster(useCacheBuster bool) {
	p.UseCacheBuster = useCacheBuster
}

func (p *Probe) GetNextBreakPayload() string {
	p.nextBreak++
	return p.breakStrings[p.nextBreak%len(p.breakStrings)]
}

func (p *Probe) GetNextEscapePayloadSet() []string {
	p.nextEscape++
	return p.escapeStrings[p.nextEscape%len(p.escapeStrings)]
}
