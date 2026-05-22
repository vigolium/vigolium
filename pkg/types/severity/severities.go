package severity

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/types/stringslice"
)

// Severities is an array of Severity types
type Severities []Severity

// Set implements pflag.Value interface for parsing comma-separated severity values
func (severities *Severities) Set(values string) error {
	// Parse comma-separated values, trimming whitespace
	for _, value := range strings.Split(values, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if err := setSeverity(severities, value); err != nil {
			return err
		}
	}
	return nil
}

// Type implements pflag.Value interface
func (severities *Severities) Type() string {
	return "severities"
}

func (severities *Severities) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var stringSliceValue stringslice.StringSlice
	if err := unmarshal(&stringSliceValue); err != nil {
		return err
	}

	stringSLice := stringSliceValue.ToSlice()
	var result = make(Severities, 0, len(stringSLice))
	for _, severityString := range stringSLice {
		if err := setSeverity(&result, severityString); err != nil {
			return err
		}
	}
	*severities = result
	return nil
}

func (severities *Severities) UnmarshalJSON(data []byte) error {
	var stringSliceValue stringslice.StringSlice
	if err := json.Unmarshal(data, &stringSliceValue); err != nil {
		return err
	}

	stringSLice := stringSliceValue.ToSlice()
	var result = make(Severities, 0, len(stringSLice))
	for _, severityString := range stringSLice {
		if err := setSeverity(&result, severityString); err != nil {
			return err
		}
	}
	*severities = result
	return nil
}

func (severities Severities) String() string {
	var stringSeverities = make([]string, 0, len(severities))
	for _, severity := range severities {
		stringSeverities = append(stringSeverities, severity.String())
	}
	return strings.Join(stringSeverities, ", ")
}

func (severities Severities) MarshalJSON() ([]byte, error) {
	var stringSeverities = make([]string, 0, len(severities))
	for _, severity := range severities {
		stringSeverities = append(stringSeverities, severity.String())
	}
	return json.Marshal(stringSeverities)
}

func setSeverity(severities *Severities, value string) error {
	computedSeverity, err := toSeverity(value)
	if err != nil {
		return fmt.Errorf("'%s' is not a valid severity", value)
	}

	// Keep Severities set-like: skip values already present so repeated flags
	// (e.g. --severity high --severity high) don't accumulate duplicates. A slice
	// is retained over a map to preserve insertion order for stable output.
	for _, existing := range *severities {
		if existing == computedSeverity {
			return nil
		}
	}
	*severities = append(*severities, computedSeverity)
	return nil
}
