// Command yaradiff is a dev tool (not part of the agent): it runs libyara's
// `yara` CLI and the agent's engine (internal/yara/engine, go-yara) over the
// same rules and corpus and prints every file where the two disagree. Run it
// before bumping go-yara:
//
//	go run ./scripts/yaradiff -rules rules.yar -corpus ./samples [-yara /usr/bin/yara]
//
// Rules the engine skips (e.g. ones using `import "pe"`) are listed and left
// out of the comparison. Exit status 1 means at least one difference.
package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"sentinelgo/internal/yara/engine"
)

func main() {
	rules := flag.String("rules", "", "YARA rule file")
	corpus := flag.String("corpus", "", "directory of files to scan")
	yaraBin := flag.String("yara", "yara", "libyara yara CLI")
	flag.Parse()
	if *rules == "" || *corpus == "" {
		flag.Usage()
		os.Exit(2)
	}
	diffs, err := run(*rules, *corpus, *yaraBin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "yaradiff:", err)
		os.Exit(2)
	}
	if diffs > 0 {
		os.Exit(1)
	}
}

func run(rulesPath, corpus, yaraBin string) (int, error) {
	src, err := os.ReadFile(rulesPath)
	if err != nil {
		return 0, err
	}
	ctx := context.Background()
	prog, skipped, err := engine.New(engine.Options{}).Compile(ctx, "diff", src)
	if err != nil {
		return 0, err
	}
	skip := map[string]bool{}
	for _, s := range skipped {
		skip[s.Rule] = true
		fmt.Printf("skipped by engine: %s (%s)\n", s.Rule, s.Reason)
	}
	want, err := libyara(yaraBin, rulesPath, corpus)
	if err != nil {
		return 0, err
	}
	diffs := 0
	err = filepath.WalkDir(corpus, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		ms, err := prog.ScanReader(ctx, f, engine.File{Type: noType}) // externals as libyara gets them
		if err != nil {
			fmt.Printf("%s: engine error: %v\n", p, err)
			diffs++
			return nil
		}
		var got []string
		for _, m := range ms {
			got = append(got, m.Rule)
		}
		var exp []string
		for _, r := range want[filepath.Clean(p)] {
			if !skip[r] {
				exp = append(exp, r)
			}
		}
		sort.Strings(got)
		sort.Strings(exp)
		if strings.Join(got, ",") != strings.Join(exp, ",") {
			fmt.Printf("%s:\n  libyara: %v\n  engine:  %v\n", p, exp, got)
			diffs++
		}
		return nil
	})
	fmt.Printf("%d difference(s)\n", diffs)
	return diffs, err
}

// noType is the filetype both engines get. The CLI can't set externals per
// file, so both sides scan with the same fixed values: empty names and this
// type.
const noType = "none"

// libyara runs `yara -r` and returns the matching rules per file.
func libyara(bin, rules, corpus string) (map[string][]string, error) {
	cmd := exec.Command(bin, "-r", "-w",
		"-d", "filename=", "-d", "filepath=", "-d", "extension=", "-d", "filetype="+noType,
		rules, corpus)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %v: %s", bin, err, stderr.String())
	}
	res := map[string][]string{}
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		rule, file, ok := strings.Cut(sc.Text(), " ")
		if ok {
			res[filepath.Clean(file)] = append(res[filepath.Clean(file)], rule)
		}
	}
	return res, sc.Err()
}
