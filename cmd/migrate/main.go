// Command migrate imports legacy YAML management data into the Gateway SQLite
// store. It intentionally has no runtime listener or Gateway lifecycle.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/clayicarus/proxy-gateway/internal/migration"
	"go.uber.org/zap"
)

func main() {
	flags := flag.NewFlagSet("migrate", flag.ExitOnError)
	configPath := flags.String("c", "configs/gateway.yaml", "path to legacy config file")
	replaceUsers := flags.Bool("replace-users", false, "replace managed users and routes while retaining nodes and traffic")
	_ = flags.Parse(os.Args[1:])

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	users, nodes, err := migration.RunLegacy(*configPath, *replaceUsers, logger)
	if err != nil {
		logger.Error("legacy migration failed", zap.Error(err))
		os.Exit(1)
	}
	if *replaceUsers {
		logger.Info("legacy users replaced; restart Gateway to apply them", zap.Int("users", users))
		return
	}
	logger.Info("legacy YAML migration completed", zap.Int("users", users), zap.Int("nodes", nodes))
}
