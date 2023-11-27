/*
Copyright © 2023 NAME HERE crtforge@burakberk.dev
*/
package cmd

import (
	"crtforge/cmd/services"
	_ "embed"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

// Cli flags
var caName string
var outputDir string
var intermediateCaName string
var trustRootCrt bool
var pfx bool

var version = "v1.0.0"
var commitId = "abcd"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "crtforge webapp app.example.com",
	Short:   "Be a local cert authority",
	Long:    `With crtforge, you can create root, intermediate and application ca.`,
	Version: version + " " + commitId,
	PreRun:  toggleDebug,
	Run:     rootRun,
}

func rootRun(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		log.Error("No argument provided.")
		log.Fatal("Please run crtforge --help for example usage.")
	}

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

	if trustRootCrt {
		services.TrustCrt(defaultCARootCACrt)
	}

	intermediateCA := services.CreateIntermediateCa(services.CreateIntermediateCAOptions{
		ConfigDirectory:    defaultCADir,
		IntermediateCAName: intermediateCaName,
		RootCACnf:          defaultCARootCACnf,
	})

	// If output directory is not provided, use the default ca directory
	if outputDir == "" {
		outputDir = defaultCADir
	}
	services.CreateAppCrt(services.CreateAppCrtOptions{
		OutputDir:         outputDir,
		IntermediateCACnf: intermediateCA.IntermediateCACnf,
		IntermediateCACrt: intermediateCA.IntermediateCACrt,
		IntermediateCAKey: intermediateCA.IntermediateCAKey,
		RootCACrt:         defaultCARootCACrt,
		AppName:           appName,
		CommonName:        appDomains[0],
		AltNames:          appDomains,
		P12:               pfx,
	})
}

func createConfigDir(configDir string) {
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		log.Info("Creating config dir: ", configDir)
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

	// Version Flag
	rootCmd.Flags().BoolP("version", "v", false, "Print version information.")

	// Select if you want to trust to the root ca
	rootCmd.Flags().BoolVarP(&trustRootCrt, "trust", "t", false, "Trust the root ca crt.")

	// Select if you want to enable debug mode logging
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "verbose logging")

	// Select custom root ca
	rootCmd.Flags().StringVarP(&caName, "root-ca", "r", "default", "Set CA Name.")

	// Select if you want pfx file
	rootCmd.Flags().BoolVarP(&pfx, "pfx", "p", false, "Create pfx file.")

	// Select custom intermediate ca
	rootCmd.Flags().StringVarP(&intermediateCaName, "intermediate-ca", "i", "intermediateCA", "Set Intermediate CA Name.")

	// Select output directory for the
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Set output directory for the certs.")

	// Example usages:
	rootCmd.Example = `Generate a cert under the default root and the default intermediate ca: 
./crtforge crtforgeapp crtforge.com app.crtforge.com api.crtforge.com [flags]

Generate a cert under a root ca named medical and a intermediate ca named frontend:
./crtforge crtforgeapp -r medical -i frontend crtforge.com app.crtforge.com api.crtforge.com [flags]`
}
