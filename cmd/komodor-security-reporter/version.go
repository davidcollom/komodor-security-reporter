package main

import (
	"fmt"

	appversion "github.com/davidcollom/komodor-security-reporter/internal/version"
	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the application version",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(
				cmd.OutOrStdout(),
				"version=%s commit=%s date=%s\n",
				appversion.Version,
				appversion.Commit,
				appversion.Date,
			)

			return err
		},
	}
}
