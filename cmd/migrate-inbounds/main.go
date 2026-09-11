package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/clayicarus/proxy-gateway/internal/config"
)

func main() {
	flags := flag.NewFlagSet("migrate-inbounds", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	input := flags.String("input", "", "path to the legacy YAML config")
	output := flags.String("output", "", "path for the new YAML config (must not exist)")
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 0 || *input == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: migrate-inbounds --input legacy-gateway.yaml --output gateway-new.yaml")
		os.Exit(2)
	}
	diagnostics, err := config.MigrateLegacyInboundsFile(*input, *output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migration failed: %v\n", err)
		os.Exit(1)
	}
	for _, diagnostic := range diagnostics {
		fmt.Fprintf(os.Stderr, "warning: %s\n", diagnostic)
	}
	fmt.Fprintf(os.Stdout, "migrated config written to %s\n", *output)
}
