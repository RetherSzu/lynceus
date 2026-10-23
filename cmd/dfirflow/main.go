package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "dfirflow:", err)
		os.Exit(2)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("dfirflow", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var showHelp bool
	flags.BoolVar(&showHelp, "help", false, "display help and exit")
	flags.BoolVar(&showHelp, "h", false, "display help and exit")
	showVersion := flags.Bool("version", false, "display version and exit")
	flags.Usage = func() {
		fmt.Fprintln(stdout, "Usage: dfirflow [options]")
		fmt.Fprintln(stdout, "Options:")
		fmt.Fprintln(stdout, "  -h, --help       display help and exit")
		fmt.Fprintln(stdout, "      --version    display version and exit")
	}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if showHelp {
		flags.Usage()
		return nil
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *showVersion {
		_, err := fmt.Fprintf(stdout, "DFIRFlow %s\n", version)
		return err
	}

	flags.Usage()
	return nil
}
