package main

import (
	"bytes"
	goflag "flag"
	"fmt"
	"k8s.io/klog"
	"os"

	"github.com/alcideio/rbac-tool/cmd"
	"github.com/spf13/cobra"
)

func RbacGenCmd() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "rbac-tool",
		Short: "rbac-tool",
		Long:  `rbac-tool`,
	}

	var genBashCompletionCmd = &cobra.Command{
		Use:   "bash-completion",
		Short: "Generate bash completion. source < (advisor bash-completion)",
		Long:  "Generate bash completion. source < (advisor bash-completion)",
		Run: func(cmd *cobra.Command, args []string) {
			out := new(bytes.Buffer)
			_ = rootCmd.GenBashCompletion(out)
			println(out.String())
		},
	}

	cmds := []*cobra.Command{
		cmd.NewCommandVersion(),
		genBashCompletionCmd,
		cmd.NewCommandGenerateClusterRole(),
		cmd.NewCommandVisualize(),
		cmd.NewCommandLookup(),
		cmd.NewCommandPolicyRules(),
	}

	flags := rootCmd.PersistentFlags()

	klog.InitFlags(nil)
	flags.AddGoFlagSet(goflag.CommandLine)

	// Hide all klog flags except for -v
	goflag.CommandLine.VisitAll(func(f *goflag.Flag) {
		if f.Name != "v" {
			flags.Lookup(f.Name).Hidden = true
		}
	})

	rootCmd.AddCommand(cmds...)

	return rootCmd
}

func main() {
	rootCmd := RbacGenCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
