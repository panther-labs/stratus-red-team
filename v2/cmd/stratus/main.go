package main

import (
	"log"
	"os"

	_ "github.com/datadog/stratus-red-team/v2/internal/attacktechniques"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "stratus",
}

// Flag to customize the User-Agent prefix and resource prefixes
var customPrefix string

func init() {
	setupLogging()

	// Setup the custom prefix flag
	setupPrefixFlag(rootCmd)

	listCmd := buildListCmd()
	showCmd := buildShowCmd()
	warmupCmd := buildWarmupCmd()
	detonateCmd := buildDetonateCmd()
	revertCmd := buildRevertCmd()
	statusCmd := buildStatusCmd()
	cleanupCmd := buildCleanupCmd()
	versionCmd := buildVersionCmd()

	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(warmupCmd)
	rootCmd.AddCommand(detonateCmd)
	rootCmd.AddCommand(revertCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(cleanupCmd)
	rootCmd.AddCommand(versionCmd)
}

func setupLogging() {
	log.SetOutput(os.Stdout)
}

func main() {
	rootCmd.Execute()
}
