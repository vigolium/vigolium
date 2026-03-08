package dom_xss_detect

import (
	"fmt"
	"regexp"
	"strings"
)

// analyseOpenRedirect checks if controllable sources flow into redirect sinks.
func analyseOpenRedirect(response string) string {
	scripts := scriptExtract.FindAllStringSubmatch(response, -1)
	for _, script := range scripts {
		body := script[1]
		if !sources.MatchString(body) {
			continue
		}
		if openRedirectSinks.MatchString(body) {
			// Found a script block with both a user-controllable source and a redirect sink
			matches := openRedirectSinks.FindAllString(body, 3)
			return fmt.Sprintf("Redirect sinks found: %s", strings.Join(matches, ", "))
		}
	}
	return ""
}

func analyse(response string) string {
	var highlighted []string

	scripts := scriptExtract.FindAllStringSubmatch(response, -1)
	sinkFound, sourceFound := false, false
	for _, script := range scripts {
		lines := strings.Split(script[1], "\n")
		num := 1
		allControlledVariables := make(map[string]bool)
		for _, newLine := range lines {
			line := newLine
			parts := strings.Split(line, "var ")

			controlledVariables := make(map[string]bool)
			if len(parts) > 1 {
				for _, part := range parts {
					for controlledVariable := range allControlledVariables {
						if strings.Contains(part, controlledVariable) {
							controlledVariables[regexp.MustCompile(`[a-zA-Z$_][a-zA-Z0-9$_]+`).FindString(part)] = true
						}
					}
				}
			}
			pattern := sources.FindAllStringIndex(newLine, -1)

			// 寻找 source
			for _, grp := range pattern {
				if grp != nil {
					source := strings.ReplaceAll(newLine[grp[0]:grp[1]], " ", "")
					if len(source) > 0 {
						if len(parts) > 1 {
							for _, part := range parts {
								if strings.Contains(part, source) {
									controlledVariables[regexp.MustCompile(`[a-zA-Z$_][a-zA-Z0-9$_]+`).FindString(part)] = true
								}
							}
						}
						line = strings.ReplaceAll(line, source, "*"+source+"*")
					}
				}
			}

			for controlledVariable := range controlledVariables {
				allControlledVariables[controlledVariable] = true
			}

			for controlledVariable := range allControlledVariables {
				matches := regexp.MustCompile(`\b`+controlledVariable+`\b`).FindAllStringIndex(line, -1)
				if len(matches) > 0 {
					sourceFound = true
					line = regexp.MustCompile(`\b`+controlledVariable+`\b`).ReplaceAllString(line, "**"+controlledVariable+"**")
				}
			}

			// 寻找 sink
			pattern = sinks.FindAllStringIndex(newLine, -1)

			for _, grp := range pattern {
				if grp != nil {
					sink := strings.ReplaceAll(newLine[grp[0]:grp[1]], " ", "")
					if len(sink) > 0 {
						line = strings.ReplaceAll(line, sink, "*"+sink+"*")
						sinkFound = true
					}
				}
			}
			if line != newLine {
				highlighted = append(highlighted, fmt.Sprintf("%-3d %s", num, strings.TrimLeft(line, " ")))
			}
			num += 1
		}
	}
	if sinkFound || sourceFound {
		return strings.Join(highlighted, "\t")
	}
	return ""
}
