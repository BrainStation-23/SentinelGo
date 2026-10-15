package main

import (
	"strings"
	"testing"
)

// Two packages may define fuzz targets with the same name; each shard must
// still select exactly its own target.
func TestShardsAndSelectTargets_DuplicateNames(t *testing.T) {
	ts := []target{
		{Pkg: "./internal/a", Dir: "internal/a", Target: "FuzzParse", OS: "linux", Runner: "ubuntu-latest"},
		{Pkg: "./internal/b", Dir: "internal/b", Target: "FuzzParse", OS: "linux", Runner: "ubuntu-latest"},
		{Pkg: "./internal/b", Dir: "internal/b", Target: "FuzzOther", OS: "linux", Runner: "ubuntu-latest"},
	}
	got := shards(ts, 2)
	if len(got) != 2 || got[0].Count+got[1].Count != 3 {
		t.Fatalf("shards = %+v, want 2 shards covering 3 targets", got)
	}
	var selected []string
	for _, sh := range got {
		sel, err := selectTargets(ts, sh.Targets)
		if err != nil {
			t.Fatal(err)
		}
		if len(sel) != sh.Count {
			t.Errorf("shard %s selected %d targets, want %d", sh.Name, len(sel), sh.Count)
		}
		for _, s := range sel {
			selected = append(selected, s.Pkg+":"+s.Target)
		}
	}
	if strings.Join(selected, " ") != "./internal/a:FuzzParse ./internal/b:FuzzParse ./internal/b:FuzzOther" {
		t.Errorf("selected %v, want each target exactly once", selected)
	}
}

func TestSelectTargets_UnknownTargetFails(t *testing.T) {
	ts := []target{{Pkg: "./internal/a", Target: "FuzzParse"}}
	if _, err := selectTargets(ts, "./internal/a:FuzzParse,./internal/a:FuzzMissing"); err == nil {
		t.Fatal("want an error for a target that doesn't exist")
	}
}

func TestShards_SizeBounds(t *testing.T) {
	var ts []target
	for i := 0; i < 26; i++ {
		ts = append(ts, target{Pkg: "./p", Target: "Fuzz" + strings.Repeat("x", i+1), OS: "linux"})
	}
	got := shards(ts, 9)
	total := 0
	for _, sh := range got {
		if sh.Count > 9 || sh.Count < 1 {
			t.Errorf("shard %s has %d targets, want 1..9", sh.Name, sh.Count)
		}
		total += sh.Count
	}
	if len(got) != 3 || total != 26 {
		t.Errorf("got %d shards with %d targets, want 3 with 26", len(got), total)
	}
	if shards(nil, 9) != nil {
		t.Error("no targets should give no shards")
	}
}
