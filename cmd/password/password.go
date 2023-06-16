package password

import (
	"github.com/spf13/cobra"
	"github.com/vhqtvn/vhmaskd/cmd"
	"github.com/vhqtvn/vhmaskd/lib/auth"
	"github.com/vhqtvn/vhmaskd/lib/vhmaskd"
)

var (
	ArgPassword string
)

var CmdPassword = &cobra.Command{
	Use:   "password",
	Short: "Use password authentication",
	Long:  `Use password authentication`,
	Args:  cobra.ExactArgs(0),
	Run: func(c *cobra.Command, args []string) {
		if (len(ArgPassword) < 8) || (len(ArgPassword) > 64) {
			panic("Invalid password length")
		}
		service := vhmaskd.NewVHMaskdService(
			cmd.ArgPort,
			cmd.ArgMaskedPort,
			auth.NewPasswordAuth(ArgPassword),
		)

		if err := service.Run(); err != nil {
			panic(err)
		}
	},
}

func init() {
	CmdPassword.Flags().StringVarP(&ArgPassword, "password", "", "", "password")
	CmdPassword.MarkFlagRequired("password")
	cmd.RootCmd.AddCommand(CmdPassword)
}
