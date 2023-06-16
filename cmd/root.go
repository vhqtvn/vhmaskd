package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

var (
	ArgPort       int
	ArgMaskedPort int
	ArgDaemon     bool
)

func validatePort(port int) (int, error) {
	if port < 0 || port > 65535 {
		return 0, errors.New("invalid port")
	} else {
		return port, nil
	}
}

var RootCmd = &cobra.Command{
	Use:   "vhmaskd",
	Short: "VHMaskd",
	Long:  `VHMaskd`,
	Args:  cobra.ExactArgs(1),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// parse args[0] is port
		var err error
		if _, err = validatePort(ArgMaskedPort); err != nil {
			panic(err)
		}
		if ArgPort != 0 {
			if _, err = validatePort(ArgPort); err != nil {
				panic(err)
			}
		}
	},
}

func Execute() error {
	return RootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().BoolVarP(&ArgDaemon, "daemon", "d", false, "run as daemon")
	RootCmd.PersistentFlags().IntVarP(&ArgPort, "port", "p", 0, "port to listen on (0 for random)")
	RootCmd.PersistentFlags().IntVarP(&ArgMaskedPort, "mask", "m", 22, "port to mask")
}

func initConfig() {
}
