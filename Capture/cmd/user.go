/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bruter/structs/enumerator"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

// userCmd represents the user command
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "enumerate usernames",
	Long:  `this option attempts to enumerate usernames given a wordlist`,
	Run: func(cmd *cobra.Command, args []string) {
		var eobj *enumerator.Enumerator
		var err error
		var firstuser bool
		var likelies []string
		var route string
		var scheme string
		var secure bool
		var target string
		var wordlist string

		wordlist, err = cmd.Flags().GetString("wordlist")
		if err != nil {
			log.Panicf("error parsing args: %s\n", err.Error())
		}

		target, err = cmd.Flags().GetString("target")
		if err != nil {
			log.Panicf("error parsing args: %s\n", err.Error())
		}

		route, err = cmd.Flags().GetString("route")
		if err != nil {
			log.Panicf("error parsing args: %s\n", err.Error())
		}

		secure, err = cmd.Flags().GetBool("secure")
		if err != nil {
			log.Panicf("error parsing args: %s\n", err.Error())
		}

		firstuser, err = cmd.Flags().GetBool("first-user")
		if err != nil {
			log.Panicf("error parsing args: %s\n", err.Error())
		}

		if secure {
			scheme = "https"
		} else {
			scheme = "http"
		}

		fmt.Printf("Wordlist: %s\n", wordlist)
		fmt.Printf("Target: %s\n", target)
		fmt.Printf("Route: %s\n", route)
		fmt.Printf("Scheme: %s\n", scheme)
		fmt.Printf("\n")

		eobj, err = enumerator.NewEnumerator(
			enumerator.WithRoute(route),
			enumerator.WithTargetIP(target),
			enumerator.WithWordlist(wordlist),
			enumerator.WithScheme(scheme),
			enumerator.FindOne(firstuser),
		)
		if err != nil {
			log.Panicf("error initializing enumerator: %s\n", err.Error())
		}

		likelies, err = eobj.Enumerate()
		if err != nil {
			log.Panicf("%s\n", err.Error())
		}

		if len(likelies) < 1 {
			log.Panicf("no users found\n")
		}
	},
}

func init() {
	rootCmd.AddCommand(userCmd)
	userCmd.Flags().StringP("wordlist", "w", "usernames.txt", "wordlist containing possible usernames")
	userCmd.Flags().Bool("first-user", false, "stop enumerating users after finding one username")
}
