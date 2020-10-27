package cmd

import (
	"fmt"
	"os"

	"github.com/gofoji/foji/cfg"
	"github.com/spf13/cobra"
)

var (
	cfgFile         string
	verbose         bool
	trace           bool
	quiet           bool
	overwrite       bool
	includeDefaults bool
	stdout          bool
	simulate        bool
	dir             string
)

var rootCmd = &cobra.Command{
	Use:   "foji",
	Short: "Fōji Generator for Postgres, SQL, and OpenAPI (Swagger)",
	Long: `Fōji reads the metadata from your database, static sql files, OpenApi V3 and generates code using templates.  The output templates are easily customized to your needs.  
https://github.com/gofoji/foji
Version: ` + cfg.Version(),
}

func Execute() {
	registerFlags()
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(copyTemplatesCmd)
	rootCmd.AddCommand(copyTemplateCmd)
	rootCmd.AddCommand(dumpConfigCmd)
	rootCmd.AddCommand(weldCmd)
	rootCmd.AddCommand(listCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func registerFlags() {

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "foji.yaml", "config file (default is foji.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "include verbose logging")
	rootCmd.PersistentFlags().BoolVarP(&trace, "trace", "t", false, "include trace logging")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "mutes all logging (overrides verbose)")

	initCmd.PersistentFlags().BoolVarP(&overwrite, "overwrite", "y", false, "force overwrite an existing output file")

	dumpConfigCmd.PersistentFlags().BoolVarP(&includeDefaults, "includeDefaults", "d", false, "Include evaluated Fōji defaults in the dump")
	dumpConfigCmd.PersistentFlags().BoolVarP(&stdout, "stdout", "o", false, "write to stdout")

	copyTemplateCmd.PersistentFlags().BoolVarP(&stdout, "stdout", "o", false, "write to stdout")
	copyTemplateCmd.PersistentFlags().BoolVarP(&overwrite, "overwrite", "y", false, "force overwrite an existing output file")
	copyTemplateCmd.PersistentFlags().StringVarP(&dir, "dir", "d", "foji", "output directory")

	copyTemplatesCmd.PersistentFlags().StringVarP(&dir, "dir", "d", "foji", "output directory")
	copyTemplatesCmd.PersistentFlags().BoolVarP(&overwrite, "overwrite", "y", false, "force overwrite an existing output file")

	weldCmd.PersistentFlags().BoolVarP(&simulate, "simulate", "s", false, "simulates the processing, only displays files that would be generated")
}
