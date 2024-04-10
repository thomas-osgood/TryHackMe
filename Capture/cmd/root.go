/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "bruter",
	Short: "command-line tool to brute-force a simple login form.",
	Long: `this tool allows for the username enumeration and password brute-forcing
of a simple http login form.`,
	// Run: func(cmd *cobra.Command, args []string) {
	// },
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
	rootCmd.PersistentFlags().StringP("route", "r", "login", "login page route")
	rootCmd.PersistentFlags().StringP("target", "t", "127.0.0.1", "ip address of target")
	rootCmd.PersistentFlags().BoolP("secure", "s", false, "indicate use of HTTPS")
}
