package writer

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
)

func writeMatchedResponse(matches map[string][]string) string {
	response := ""
	for _, match := range matches {
		response += fmt.Sprintln(fmt.Sprintf("%s", strings.Join(match, ", ")))
	}

	return response
}

// WriteResult is a helper for writing results to the output
func WriteResult(data *output.InternalWrappedEvent, output output.Writer, progress progress.Progress, issuesClient reporting.Client) bool {
	// Handle the case where no result found for the template.
	// In this case, we just show misc information about the failed
	// match for the template.
	if !data.HasOperatorResult() {
		return false
	}
	var matched bool
	for _, result := range data.Results {
		result.MatchedResponse = data.OperatorsResult.MatchedResponse
		if issuesClient != nil {
			if err := issuesClient.CreateIssue(result); err != nil {
				gologger.Warning().Msgf("Could not create issue on tracker: %s", err)
			}
		}
		if err := output.Write(result); err != nil {
			gologger.Warning().Msgf("Could not write output event: %s\n", err)
		}
		if !matched {
			matched = true
		}
		progress.IncrementMatched()
	}
	return matched
}
