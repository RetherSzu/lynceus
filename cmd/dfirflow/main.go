package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
)

var version = "dev"

var (
	errNotImplemented = errors.New("not implemented yet")
	errIntegrity      = errors.New("integrity check failed")
)

// usageError reports a malformed command line (exit code 2).
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// cmdError attaches the command name to an error for the "dfirflow: <cmd>:" prefix.
type cmdError struct {
	cmd string
	err error
}

func (e *cmdError) Error() string { return e.cmd + ": " + e.err.Error() }
func (e *cmdError) Unwrap() error { return e.err }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// cli runs the command line and prints the diagnostic, returning the exit code.
func cli(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	err := run(ctx, args, stdout, stderr)
	code := exitCode(ctx, err)
	if err != nil && code != 130 {
		fmt.Fprintln(stderr, formatError(err))
	}
	return code
}

func exitCode(ctx context.Context, err error) int {
	var usage *usageError
	switch {
	case err == nil:
		return 0
	case ctx.Err() != nil:
		return 130
	case errors.As(err, &usage):
		return 2
	case errors.Is(err, errNotImplemented):
		return 3
	case errors.Is(err, errIntegrity):
		return 4
	default:
		return 1
	}
}

func formatError(err error) string {
	msg := "dfirflow: " + err.Error()
	var usage *usageError
	if errors.As(err, &usage) {
		hint := "dfirflow --help"
		var ce *cmdError
		if errors.As(err, &ce) {
			hint = "dfirflow " + ce.cmd + " --help"
		}
		msg += "\nRun '" + hint + "' for usage."
	}
	return msg
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("dfirflow", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	var showHelp bool
	flags.BoolVar(&showHelp, "help", false, "display help and exit")
	flags.BoolVar(&showHelp, "h", false, "display help and exit")
	showVersion := flags.Bool("version", false, "display version and exit")

	if err := flags.Parse(args); err != nil {
		return &usageError{msg: err.Error()}
	}
	rest := flags.Args()
	switch {
	case showHelp:
		printUsage(stdout)
		return nil
	case *showVersion && len(rest) > 0:
		return &usageError{msg: "--version cannot be combined with a command"}
	case *showVersion:
		_, err := fmt.Fprintf(stdout, "DFIRFlow %s\n", version)
		return err
	case len(rest) == 0:
		printUsage(stdout)
		return nil
	}

	name := rest[0]
	rest = rest[1:]
	if name == "case" {
		if len(rest) == 0 {
			return &usageError{msg: "missing case subcommand (init, verify)"}
		}
		name += " " + rest[0]
		rest = rest[1:]
	}
	c := lookup(name)
	if c == nil {
		return &usageError{msg: fmt.Sprintf("unknown command %q", name)}
	}
	o, err := c.parse(rest, stdout)
	if err != nil || o == nil {
		return wrap(c.name, err)
	}
	o.argv, o.stdout = rest, stdout
	if err := ctx.Err(); err != nil {
		return err
	}
	return wrap(c.name, c.exec(ctx, o))
}

func wrap(cmd string, err error) error {
	if err == nil {
		return nil
	}
	return &cmdError{cmd: cmd, err: err}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dfirflow [options] <command> [arguments]")
	fmt.Fprintln(w, "\nCommands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-13s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w, "\nOptions:")
	fmt.Fprintln(w, "  -h, --help       display help and exit")
	fmt.Fprintln(w, "      --version    display version and exit")
	fmt.Fprintln(w, "\nRun 'dfirflow <command> --help' for details on a command.")
}
