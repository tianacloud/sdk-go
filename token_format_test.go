package tiana

import (
	"fmt"
	"strings"
	"testing"
)

func TestTokenValueFormattingRedactsSecrets(t *testing.T) {
	token := syntheticToken(t)
	for name, value := range map[string]any{
		"pointer": token,
		"value":   *token,
		"slice":   []Token{*token},
		"array":   [1]Token{*token},
		"map":     map[string]Token{"token": *token},
		"field":   struct{ Token Token }{*token},
		"nil":     (*Token)(nil),
	} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			t.Run(name+"/"+format, func(t *testing.T) {
				output := fmt.Sprintf(format, value)
				if strings.Contains(output, token.value) {
					t.Fatal("formatting exposed the synthetic token")
				}
				if strings.Contains(output, "PANIC") {
					t.Fatal("formatting panicked")
				}
			})
		}
	}
}
