package engine

import (
	"reflect"
	"strings"
	"testing"
)

func TestScanTopLevel(t *testing.T) {
	src := `import "pe"
// import "math"
/* include "x" */
external filename
import "hash"
rule r : tag {
  strings:
    $a = "import \"elf\"" // }
    $b = /include "y" \/ } {/
    $h = { 41 [2-4] 42 }
  condition:
    $a and $b and $h and (filesize \ 2) > 1
}
import "time"`
	tl := scanTopLevel(src)
	var names []string
	for _, imp := range tl.imports {
		names = append(names, imp.name)
		if got := src[imp.start:imp.end]; !strings.HasPrefix(got, "import") || !strings.HasSuffix(got, `"`) {
			t.Errorf("import span = %q", got)
		}
	}
	if !reflect.DeepEqual(names, []string{"pe", "hash", "time"}) {
		t.Errorf("imports = %v", names)
	}
	if tl.include {
		t.Error("include found in a comment or rule body")
	}
	if !tl.externals["filename"] || len(tl.externals) != 1 {
		t.Errorf("externals = %v", tl.externals)
	}
}

func TestPrepareKeepsLines(t *testing.T) {
	src := "import \"pe\"\nimport \"hash\"\nrule r { condition: true }"
	out, err := prepare(src, map[string]bool{"hash": true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "           \nimport \"hash\"\nrule r") {
		t.Errorf("prepared = %q", out)
	}
	for _, n := range externalNames {
		if !strings.Contains(out, " external "+n) {
			t.Errorf("external %s not declared: %q", n, out)
		}
	}
}
