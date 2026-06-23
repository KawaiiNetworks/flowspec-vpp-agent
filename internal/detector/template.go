package detector

import (
	"fmt"
	"strings"
)

// template is a precompiled "{{var}}" string: a flat sequence of literal and
// variable segments. Rendering is a cheap walk with no parsing.
type template struct {
	raw  string
	segs []seg
}

type seg struct {
	lit  string // literal text when name == ""
	name string
}

// compileTemplate parses "{{name}}" placeholders out of s. Unterminated or empty
// placeholders are an error so typos fail at load time, not at emit time.
func compileTemplate(s string) (*template, error) {
	t := &template{raw: s}
	for i := 0; i < len(s); {
		open := strings.Index(s[i:], "{{")
		if open < 0 {
			t.segs = append(t.segs, seg{lit: s[i:]})
			break
		}
		open += i
		if open > i {
			t.segs = append(t.segs, seg{lit: s[i:open]})
		}
		close := strings.Index(s[open:], "}}")
		if close < 0 {
			return nil, fmt.Errorf("unterminated %q in template %q", "{{", s)
		}
		close += open
		name := strings.TrimSpace(s[open+2 : close])
		if name == "" {
			return nil, fmt.Errorf("empty placeholder in template %q", s)
		}
		t.segs = append(t.segs, seg{name: name})
		i = close + 2
	}
	return t, nil
}

// vars returns the distinct variable names referenced by the template.
func (t *template) vars() []string {
	var out []string
	seen := map[string]struct{}{}
	for _, sg := range t.segs {
		if sg.name == "" {
			continue
		}
		if _, ok := seen[sg.name]; ok {
			continue
		}
		seen[sg.name] = struct{}{}
		out = append(out, sg.name)
	}
	return out
}

// render resolves each variable through resolve. A missing variable renders
// empty; callers validate references at compile time so this should not happen.
func (t *template) render(resolve func(name string) (string, bool)) string {
	var b strings.Builder
	for _, sg := range t.segs {
		if sg.name == "" {
			b.WriteString(sg.lit)
			continue
		}
		if v, ok := resolve(sg.name); ok {
			b.WriteString(v)
		}
	}
	return b.String()
}
