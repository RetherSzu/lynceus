package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	casefile "DFIRFlow/internal/case"
)

// opts holds the parsed options of one command invocation.
type opts struct {
	caseDir, target, dir, host, analyst onceString
	tool, from, to, source, rules       onceString
	format                              onceString
	positionals                         []string
	argv                                []string // command arguments, for the case journal
	stdout                              io.Writer
}

type option struct {
	name, arg, help string
	required        bool
	field           func(*opts) *onceString
}

type command struct {
	name, summary, example string
	args                   string // positional arguments, as shown in usage
	minArgs, maxArgs       int    // maxArgs < 0 means unlimited
	options                []option
	check                  func(*opts) error // extra validation, may be nil
	exec                   func(context.Context, *opts) error
}

var (
	caseIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	importTools   = []string{"kape", "orc", "eztools", "hayabusa", "plaso", "volatility"}
	sources       = []string{"evtx", "mft", "usnjrnl", "registry", "prefetch", "memory"}
	formats       = []string{"html", "sqlite", "jsonl"}
)

var (
	optCase   = option{"case", "<path>", "case directory", true, func(o *opts) *onceString { return &o.caseDir }}
	optTarget = option{"target", "<path>", "evidence file or directory", true, func(o *opts) *onceString { return &o.target }}
	optFormat = option{"format", "<list>", "comma-separated output formats: " + strings.Join(formats, ", "), false, func(o *opts) *onceString { return &o.format }}
)

// commands lists the CLI commands in pipeline order; built in init because
// investigate refers back to the table.
var commands []*command

func init() {
	commands = []*command{
		{name: "case init", summary: "Create a new case directory",
			args: "<ID>", minArgs: 1, maxArgs: 1,
			options: []option{
				{"host", "<name>", "hostname of the investigated system", true, func(o *opts) *onceString { return &o.host }},
				{"analyst", "<name>", "analyst or team in charge", true, func(o *opts) *onceString { return &o.analyst }},
				{"dir", "<path>", "parent directory of cases", false, func(o *opts) *onceString { return &o.dir }},
			},
			check:   checkCaseID,
			exec:    caseInit,
			example: "dfirflow case init CASE-001 --host WIN-CLIENT01 --analyst dfir-team"},
		{name: "case verify", summary: "Recompute SHA-256 hashes and check evidence integrity",
			options: []option{optCase},
			exec:    caseVerify,
			example: "dfirflow case verify --case ./cases/CASE-001"},
		{name: "collect", summary: "Copy and hash evidence into the case",
			options: []option{optCase, optTarget},
			example: "dfirflow collect --case ./cases/CASE-001 --target ./evidence"},
		{name: "ingest", summary: "Parse collected artifacts into normalized events",
			args: "[path...]", maxArgs: -1,
			options: []option{optCase},
			example: "dfirflow ingest --case ./cases/CASE-001 ./cases/CASE-001/evidence/Security.evtx"},
		{name: "import", summary: "Read third-party tool output (never executes the tool)",
			args: "<path>", minArgs: 1, maxArgs: 1,
			options: []option{optCase,
				{"tool", "<name>", "source tool: " + strings.Join(importTools, ", "), true, func(o *opts) *onceString { return &o.tool }},
			},
			check:   checkImport,
			example: "dfirflow import --case ./cases/CASE-001 --tool hayabusa ./hayabusa.jsonl"},
		{name: "timeline", summary: "Build the consolidated timeline",
			options: []option{optCase,
				{"from", "<date-time>", "start bound, RFC 3339 (UTC if no zone)", false, func(o *opts) *onceString { return &o.from }},
				{"to", "<date-time>", "end bound, RFC 3339 (UTC if no zone)", false, func(o *opts) *onceString { return &o.to }},
				{"source", "<list>", "comma-separated sources: " + strings.Join(sources, ", "), false, func(o *opts) *onceString { return &o.source }},
			},
			check:   checkTimeline,
			example: "dfirflow timeline --case ./cases/CASE-001 --from 2026-11-01T00:00:00Z --source evtx,prefetch"},
		{name: "detect", summary: "Apply detection rules to normalized events",
			options: []option{optCase,
				{"rules", "<path>", "rules file or directory", false, func(o *opts) *onceString { return &o.rules }},
			},
			example: "dfirflow detect --case ./cases/CASE-001 --rules ./rules"},
		{name: "correlate", summary: "Reconstruct attack chains from detections",
			options: []option{optCase},
			example: "dfirflow correlate --case ./cases/CASE-001"},
		{name: "report", summary: "Generate investigation deliverables",
			options: []option{optCase, optFormat},
			check:   checkFormat,
			example: "dfirflow report --case ./cases/CASE-001 --format html,jsonl"},
		{name: "investigate", summary: "Run collect, ingest, timeline, detect, correlate and report",
			options: []option{optCase, optTarget, optFormat},
			check:   checkFormat,
			exec:    investigate,
			example: "dfirflow investigate --case ./cases/CASE-001 --target ./evidence"},
	}
	for _, c := range commands {
		if c.exec == nil {
			c.exec = notImplemented
		}
	}
}

func lookup(name string) *command {
	for _, c := range commands {
		if c.name == name {
			return c
		}
	}
	return nil
}

func notImplemented(context.Context, *opts) error { return errNotImplemented }

// investigate chains the pipeline commands; it has no logic of its own.
func investigate(ctx context.Context, o *opts) error {
	for _, step := range []string{"collect", "ingest", "timeline", "detect", "correlate", "report"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := lookup(step).exec(ctx, o); err != nil {
			return fmt.Errorf("%s: %w", step, err)
		}
	}
	return nil
}

func newOpts() *opts {
	return &opts{
		dir:    onceString{value: "./cases"},
		format: onceString{value: strings.Join(formats, ",")},
	}
}

// parse validates args entirely, without touching the filesystem.
// It returns (nil, nil) when help was requested and printed.
func (c *command) parse(args []string, stdout io.Writer) (*opts, error) {
	if wantsHelp(args) {
		c.printHelp(stdout)
		return nil, nil
	}
	o := newOpts()
	fs := flag.NewFlagSet(c.name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	for _, opt := range c.options {
		fs.Var(opt.field(o), opt.name, opt.help)
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return nil, &usageError{msg: err.Error()}
	}
	o.positionals = pos
	switch {
	case len(pos) < c.minArgs:
		return nil, &usageError{msg: fmt.Sprintf("missing argument %s", c.args)}
	case c.maxArgs >= 0 && len(pos) > c.maxArgs:
		return nil, &usageError{msg: fmt.Sprintf("unexpected argument %q", pos[c.maxArgs])}
	}
	for _, opt := range c.options {
		if opt.required && !opt.field(o).set {
			return nil, &usageError{msg: fmt.Sprintf("--%s is required", opt.name)}
		}
	}
	if c.check != nil {
		if err := c.check(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// wantsHelp reports whether -h/--help appears before any "--" terminator.
func wantsHelp(args []string) bool {
	for _, a := range args {
		switch a {
		case "--":
			return false
		case "-h", "--help", "-help", "--h":
			return true
		}
	}
	return false
}

func (c *command) printHelp(w io.Writer) {
	usage := "Usage: dfirflow " + c.name
	for _, opt := range c.options {
		part := "--" + opt.name + " " + opt.arg
		if !opt.required {
			part = "[" + part + "]"
		}
		usage += " " + part
	}
	if c.args != "" {
		usage += " " + c.args
	}
	fmt.Fprintf(w, "%s\n\n%s.\n", usage, c.summary)
	if c.args != "" {
		fmt.Fprintf(w, "\nArguments:\n  %-22s %s\n", c.args, argHelp(c))
	}
	fmt.Fprintln(w, "\nOptions:")
	defaults := newOpts()
	for _, opt := range c.options {
		status := "(required)"
		if !opt.required {
			status = "(optional"
			if d := opt.field(defaults).value; d != "" {
				status += ", default: " + d
			}
			status += ")"
		}
		fmt.Fprintf(w, "  %-22s %s %s\n", "--"+opt.name+" "+opt.arg, opt.help, status)
	}
	fmt.Fprintln(w, "  -h, --help             display this help and exit")
	fmt.Fprintf(w, "\nExample:\n  %s\n", c.example)
}

func argHelp(c *command) string {
	switch c.name {
	case "case init":
		return "case identifier: letters, digits, '-' and '_', 1 to 64 characters (required)"
	case "ingest":
		return "artifacts to parse (optional, default: all evidence of the case)"
	default:
		return "file or directory to read (required)"
	}
}

func checkCaseID(o *opts) error {
	if id := o.positionals[0]; !caseIDPattern.MatchString(id) {
		return &usageError{msg: fmt.Sprintf("invalid case ID %q: use letters, digits, '-' and '_' only, 1 to 64 characters", id)}
	}
	return nil
}

func checkImport(o *opts) error {
	if !contains(importTools, o.tool.value) {
		return &usageError{msg: fmt.Sprintf("invalid --tool %q: accepted values are %s", o.tool.value, strings.Join(importTools, ", "))}
	}
	return nil
}

func checkTimeline(o *opts) error {
	from, err := parseTime("from", o.from)
	if err != nil {
		return err
	}
	to, err := parseTime("to", o.to)
	if err != nil {
		return err
	}
	if o.from.set && o.to.set && from.After(to) {
		return &usageError{msg: "--from must not be after --to"}
	}
	if o.source.set {
		if _, err := parseList("source", o.source.value, sources); err != nil {
			return err
		}
	}
	return nil
}

func checkFormat(o *opts) error {
	_, err := parseList("format", o.format.value, formats)
	return err
}

// parseTime accepts RFC 3339, or a date-time without zone interpreted as UTC.
func parseTime(name string, v onceString) (time.Time, error) {
	if !v.set {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, v.value); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, &usageError{msg: fmt.Sprintf("invalid --%s %q: expected RFC 3339 date-time, e.g. 2026-11-02T09:00:00Z", name, v.value)}
}

func caseInit(ctx context.Context, o *opts) (err error) {
	started := time.Now()
	c, err := casefile.Create(o.dir.value, o.positionals[0], o.host.value, o.analyst.value, version, started)
	if err != nil {
		return err
	}
	defer func() { err = logOperation(ctx, c, "case init", o, started, err, nil) }()
	_, err = fmt.Fprintln(o.stdout, c.BaseDir)
	return err
}

func caseVerify(ctx context.Context, o *opts) (err error) {
	started := time.Now()
	c, err := casefile.Open(o.caseDir.value)
	if err != nil {
		return err
	}
	counts := map[string]int{casefile.StatusOK: 0, casefile.StatusModified: 0, casefile.StatusMissing: 0, casefile.StatusUntracked: 0}
	defer func() { err = logOperation(ctx, c, "case verify", o, started, err, counts) }()
	results, err := c.Verify(ctx)
	if err != nil {
		return err
	}
	for _, r := range results {
		counts[r.Status]++
		line := fmt.Sprintf("%-10s %s", r.Status, r.File)
		switch r.Status {
		case casefile.StatusOK:
			line += "  sha256=" + r.Expected
		case casefile.StatusModified:
			line += "  expected=" + r.Expected + " actual=" + r.Actual
		case casefile.StatusMissing:
			line += "  expected=" + r.Expected
		}
		fmt.Fprintln(o.stdout, line)
	}
	fmt.Fprintf(o.stdout, "%d evidence files: %d OK, %d MODIFIED, %d MISSING, %d UNTRACKED\n", len(results),
		counts[casefile.StatusOK], counts[casefile.StatusModified], counts[casefile.StatusMissing], counts[casefile.StatusUntracked])
	if counts[casefile.StatusOK] != len(results) {
		return errIntegrity
	}
	return nil
}

// logOperation journalise la commande dans le cas ; un échec d'écriture du
// journal fait échouer une commande qui avait réussi.
func logOperation(ctx context.Context, c *casefile.Case, name string, o *opts, started time.Time, err error, summary interface{}) error {
	lerr := c.Log(casefile.LogEntry{
		Command: name, Args: o.argv, StartedAt: started, FinishedAt: time.Now(),
		ToolVersion: version, ExitCode: exitCode(ctx, err), Summary: summary,
	})
	if err == nil && lerr != nil {
		return fmt.Errorf("writing case journal: %w", lerr)
	}
	return err
}
