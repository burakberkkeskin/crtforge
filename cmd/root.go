/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"crtforge/cmd/services"
	_ "embed"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var caName string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "crtforge",
	Short: "Be a local cert authority",
	Long: `With crtforge, you can create root, intermediate and application ca.
For example:
./crtforge crtforgeapp crtforge.com app.crtforge.com api.crtforge.com 
`,
	Args: cobra.MinimumNArgs(2),
	Run:  rootRun,
}

func rootRun(cmd *cobra.Command, args []string) {
	appName := args[0]
	appDomains := args[1:]

	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		log.Fatal("home directory couldn't find", err)
	}
	configDirectory := homeDirectory + "/.config/crtforge"
	createConfigDir(configDirectory)
	defaultCADir := services.CreateCaDir(configDirectory, caName)

	defaultCARootCACrt, defaultCARootCACnf, defaultCARootCAkey := services.CreateRootCa(defaultCADir)
	_ = defaultCARootCAkey

	defaultCAIntermediateCACrt, defaultCAIntermediateCACnf, defaultCAIntermediateCAkey := services.CreateIntermediateCa(defaultCADir, defaultCARootCACnf)

	services.CreateAppCrt(defaultCADir, defaultCAIntermediateCACnf, defaultCAIntermediateCACrt, defaultCAIntermediateCAkey, defaultCARootCACrt, appName, appDomains[0], appDomains)
}

func createConfigDir(configDir string) {
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		err := os.MkdirAll(configDir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.Flags().StringVar(&caName, "rootCa", "default", "Set CA Name")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
