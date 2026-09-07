package tunneler

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveCredential(t *testing.T) {
	cases := []struct {
		name      string
		providers []func() string
		want      string
	}{
		{"first non-empty wins", []func() string{
			func() string { return "" },
			func() string { return "  value  " },
			func() string { return "ignored" },
		}, "value"},
		{"empty provider skipped", []func() string{
			nil,
			func() string { return "" },
			func() string { return "b" },
		}, "b"},
		{"all empty returns empty", []func() string{
			func() string { return "" },
			func() string { return "" },
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ResolveCredential(c.providers...))
		})
	}
}
