package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
)

// onceString is a flag value that rejects empty values and repetition.
// A non-empty initial value acts as the default and may be overridden once.
type onceString struct {
	value string
	set   bool
}

func (o *onceString) String() string { return o.value }

func (o *onceString) Set(v string) error {
	if o.set {
		return errors.New("specified more than once")
	}
	if v == "" {
		return errors.New("must not be empty")
	}
	o.value, o.set = v, true
	return nil
}

// parseInterspersed parses fs options placed before or after positional
// arguments; everything after "--" is positional.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positionals, nil
		}
		// flag consumes the "--" terminator itself; detect it to stop parsing.
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			return append(positionals, rest...), nil
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
}

// parseList splits a comma-separated option value, rejecting empty,
// duplicate and unknown items.
func parseList(name, v string, allowed []string) ([]string, error) {
	items := strings.Split(v, ",")
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		switch {
		case item == "":
			return nil, &usageError{msg: fmt.Sprintf("invalid --%s %q: empty value", name, v)}
		case seen[item]:
			return nil, &usageError{msg: fmt.Sprintf("invalid --%s %q: duplicate value %q", name, v, item)}
		case !contains(allowed, item):
			return nil, &usageError{msg: fmt.Sprintf("invalid --%s %q: accepted values are %s", name, v, strings.Join(allowed, ", "))}
		}
		seen[item] = true
	}
	return items, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
