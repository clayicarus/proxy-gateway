package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/clayicarus/proxy-gateway/internal/config"
)

func main() {
	flags := flag.NewFlagSet("validate-inbounds", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	input := flags.String("input", "", "path to a YAML config using the new inbounds schema")
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if flags.NArg() != 0 || *input == "" {
		fmt.Fprintln(os.Stderr, "usage: validate-inbounds --input gateway-new.yaml")
		os.Exit(2)
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "validation failed: unable to read input: %v\n", err)
		os.Exit(1)
	}
	if _, err := config.ParseInboundConfig(data); err != nil {
		fmt.Fprintf(os.Stderr, "validation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "inbound config is valid")
}
